import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from peat import config, consts, utils
from peat.api import pillage_api
from peat.api.pillage_api import (
    UnlockSecrets,
    check_file_conditions,
    copy_file,
    is_bitlocker,
    is_image_attached_windows,
    is_valid_file,
    mount_image_windows,
    pillage,
    read_volume_header,
    search,
    search_volumes_windows,
    validate_image_mounting_windows,
)

PILLAGE_CONFIG = {
    "auto_copy": True,
    "recursive": True,
    "default": {"locations": [], "filenames": [], "extensions": []},
    "brands": {
        "SEL": {"locations": [], "filenames": ["set_all.txt"], "extensions": ["rdb"]},
    },
}


@pytest.fixture
def pillage_config(monkeypatch):
    monkeypatch.setattr(config, "PILLAGE", PILLAGE_CONFIG)


def _make_source(source: Path) -> None:
    (source / "Projects" / "relay1").mkdir(parents=True)
    (source / "Projects" / "relay1" / "SET_ALL.TXT").write_text("relay1", encoding="utf-8")
    (source / "Projects" / "relay2.rdb").write_text("relay2", encoding="utf-8")
    (source / "Projects" / "notes.txt").write_text("not a project file", encoding="utf-8")
    # Excluded system directories are skipped, case-insensitively, at the root
    (source / "WINDOWS" / "System32").mkdir(parents=True)
    (source / "WINDOWS" / "System32" / "excluded.rdb").write_text("x", encoding="utf-8")
    (source / "$Recycle.Bin").mkdir()
    (source / "$Recycle.Bin" / "deleted.rdb").write_text("x", encoding="utf-8")
    # Excluded names deeper in the tree aren't skipped
    (source / "Projects" / "Windows").mkdir()
    (source / "Projects" / "Windows" / "nested.rdb").write_text("nested", encoding="utf-8")


def test_pillage_bad_args():
    assert pillage("") is False


def test_search():
    assert search(Path("NONEXISTENT"), None) is False


def test_search_files(tmp_path, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_source(source)

    assert search(source, results, exclude_system_dirs=True) is True
    found = sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())
    assert found == ["SEL/SET_ALL.TXT", "SEL/nested.rdb", "SEL/relay2.rdb"]


def test_search_not_mount_point(tmp_path, pillage_config):  # noqa: ARG001
    # System directories are only skipped by default in the root of a drive or mount
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_source(source)

    assert search(source, results) is True
    found = sorted(p.name for p in results.rglob("*") if p.is_file())
    assert found == ["SET_ALL.TXT", "deleted.rdb", "excluded.rdb", "nested.rdb", "relay2.rdb"]


def test_search_junctions(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    results = tmp_path / "results"
    _make_source(source)
    junction = str(source / "Projects" / "relay1")
    real_lstat = os.lstat

    # Only defined on Windows
    monkeypatch.setattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003, raising=False)

    class _Stat:
        st_reparse_tag = stat.IO_REPARSE_TAG_MOUNT_POINT

    monkeypatch.setattr(consts, "WINDOWS", True)
    monkeypatch.setattr(os, "lstat", lambda p: _Stat() if str(p) == junction else real_lstat(p))

    assert search(source, results) is True
    assert not (results / "SEL" / "SET_ALL.TXT").exists()
    assert (results / "SEL" / "relay2.rdb").is_file()


def test_search_unreadable_root(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    def _scandir(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(os, "scandir", _scandir)
    assert search(tmp_path, tmp_path / "results") is False


def test_search_not_recursive(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PILLAGE", {**PILLAGE_CONFIG, "recursive": False})
    (tmp_path / "top.rdb").write_text("top", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "sub.rdb").write_text("sub", encoding="utf-8")
    results = tmp_path / "results"

    assert search(tmp_path, results) is True
    assert [p.name for p in results.rglob("*.rdb")] == ["top.rdb"]


def test_search_duplicate_names(tmp_path, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    for name in ["a", "b"]:
        (source / name).mkdir(parents=True)
        (source / name / "set_all.txt").write_text(name, encoding="utf-8")
    results = tmp_path / "results"

    assert search(source, results) is True
    assert sorted(p.name for p in (results / "SEL").iterdir()) == ["set_all.txt", "set_all.txt.1"]


def test_pillage_directory(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    source = tmp_path / "source"
    _make_source(source)
    monkeypatch.chdir(tmp_path)

    assert pillage(str(source)) is True
    assert (tmp_path / "pillage_results" / "SEL" / "relay2.rdb").is_file()


def test_copy_file_error(tmp_path):
    # Failing to copy one file (e.g. it's locked on Windows) shouldn't stop pillage
    copy_file(tmp_path / "nonexistent.rdb", tmp_path / "results" / "nonexistent.rdb")
    assert not (tmp_path / "results" / "nonexistent.rdb").exists()


def test_is_valid_file(tmp_path):
    assert is_valid_file(tmp_path) == (False, "")


def test_check_file_conditions(tmp_path):
    assert check_file_conditions(tmp_path, {}) == (False, "")
    assert check_file_conditions(Path("SET_ALL.txt"), {"filenames": ["set_all.TXT"]}) == (
        True,
        "FILENAME",
    )
    assert check_file_conditions(Path("relay.RDB"), {"extensions": ["rdb"]}) == (
        True,
        "EXTENSION",
    )


@pytest.mark.parametrize(
    ("image", "superuser", "tools", "expected"),
    [
        ("disk.vhdx", True, ["powershell"], True),
        ("disk.VHD", True, ["powershell"], True),
        ("disk.iso", False, ["powershell"], True),
        ("disk.vhdx", False, ["powershell"], False),
        ("disk.vhdx", True, [], False),
        ("disk.img", True, ["powershell"], False),
        ("disk.vmdk", True, ["powershell", "qemu-img"], True),
    ],
)
def test_validate_image_mounting_windows(monkeypatch, image, superuser, tools, expected):
    monkeypatch.setattr(shutil, "which", lambda cmd: cmd if cmd in tools else None)
    monkeypatch.setattr(utils, "are_we_superuser", lambda: superuser)
    assert validate_image_mounting_windows(Path(image)) is expected


def _fake_powershell(
    monkeypatch,
    mount: tuple[int, str] = (0, json.dumps({"volumes": []})),
    attached: str = "False",
    calls: list | None = None,
    unlock_passwords: tuple[str, ...] = (),
    bitlocker_available: str = "True",
):
    """
    Fake the PowerShell scripts: (returncode, stdout) for mount, the attached state,
    if BitLocker is available, and the secrets that unlock BitLocker volumes.
    """

    def _run(script, image=None, env_vars=None):
        if calls is not None:
            calls.append((script, image, env_vars or {}))
        if script == pillage_api._PS_MOUNT_SCRIPT:
            returncode, stdout = mount
        elif script == pillage_api._PS_ATTACHED_SCRIPT:
            returncode, stdout = 0, attached
        elif script == pillage_api._PS_BITLOCKER_AVAILABLE_SCRIPT:
            returncode, stdout = 0, bitlocker_available
        elif script == pillage_api._PS_UNLOCK_SCRIPT:
            ok = env_vars["PEAT_PILLAGE_SECRET"] in unlock_passwords
            returncode, stdout = (0, "NTFS") if ok else (1, "")
        else:
            returncode, stdout = 0, ""
        return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="error")

    monkeypatch.setattr(pillage_api, "_run_powershell", _run)


def _scripts(calls: list) -> list[str]:
    names = {
        pillage_api._PS_ATTACHED_SCRIPT: "attached",
        pillage_api._PS_MOUNT_SCRIPT: "mount",
        pillage_api._PS_UNMOUNT_SCRIPT: "unmount",
        pillage_api._PS_BITLOCKER_AVAILABLE_SCRIPT: "available",
        pillage_api._PS_UNLOCK_SCRIPT: "unlock",
        pillage_api._PS_LOCK_SCRIPT: "lock",
    }
    return [names[c[0]] for c in calls]


def test_mount_image_windows(monkeypatch):
    vol = {"drive_letter": "E", "path": "", "filesystem": "NTFS", "label": "DATA"}
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": [vol]})))
    assert mount_image_windows(Path("disk.vhdx")) == [vol]

    # Single volume serialized as an object instead of a list, and no volumes
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": vol})))
    assert mount_image_windows(Path("disk.vhdx")) == [vol]
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": None})))
    assert mount_image_windows(Path("disk.vhdx")) == []

    # Output printed before the JSON is ignored
    _fake_powershell(monkeypatch, (0, "warning\n" + json.dumps({"volumes": [vol]})))
    assert mount_image_windows(Path("disk.vhdx")) == [vol]

    _fake_powershell(monkeypatch, (1, ""))
    assert mount_image_windows(Path("disk.vhdx")) is None
    _fake_powershell(monkeypatch, (0, "not json"))
    assert mount_image_windows(Path("disk.vhdx")) is None


def test_is_image_attached_windows(monkeypatch):
    _fake_powershell(monkeypatch, attached="True")
    assert is_image_attached_windows(Path("disk.vhdx")) is True
    _fake_powershell(monkeypatch, attached="False")
    assert is_image_attached_windows(Path("disk.vhdx")) is False
    _fake_powershell(monkeypatch, attached="")
    assert is_image_attached_windows(Path("disk.vhdx")) is None


def test_run_powershell_env(monkeypatch):
    calls = []

    def _run(args, **kwargs):
        calls.append(kwargs["env"])
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _run)
    monkeypatch.setenv("PSModulePath", "C:\\Program Files\\PowerShell\\7\\Modules")
    pillage_api._run_powershell("", Path("disk.vhdx"), {"PEAT_PILLAGE_SECRET": "pw"})
    pillage_api._run_powershell("")

    # Inherited from PowerShell 7
    assert not [k for k in calls[0] if k.lower() == "psmodulepath"]
    assert calls[0]["PEAT_PILLAGE_IMAGE"] == "disk.vhdx"
    assert calls[0]["PEAT_PILLAGE_SECRET"] == "pw"
    assert "PEAT_PILLAGE_IMAGE" not in calls[1]


def test_run_powershell_timeout(monkeypatch):
    def _timeout(*args, **kwargs):  # noqa: ARG001
        raise subprocess.TimeoutExpired("powershell", 1)

    monkeypatch.setattr(subprocess, "run", _timeout)
    assert pillage_api._run_powershell("", Path("disk.vhdx")).returncode == 1


def test_search_volumes_windows(tmp_path, pillage_config):  # noqa: ARG001
    source = tmp_path / "volume"
    _make_source(source)
    results = tmp_path / "results"
    volumes = [
        {"drive_letter": "", "path": "", "filesystem": "Unknown", "label": "ext4"},
        {"drive_letter": "", "path": str(source), "filesystem": "NTFS", "label": "DATA"},
    ]

    assert search_volumes_windows(volumes, results) is True
    assert (results / "SEL" / "relay2.rdb").is_file()
    assert search_volumes_windows(volumes[:1], results) is False
    assert search_volumes_windows([], results) is False


def _setup_image_windows(tmp_path, monkeypatch, name: str = "disk.vhdx") -> tuple[Path, str]:
    volume = tmp_path / "volume"
    _make_source(volume)
    image = tmp_path / name
    image.write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(consts, "WINDOWS", True)
    monkeypatch.setattr(pillage_api, "validate_image_mounting_windows", lambda _: True)

    vol = {"drive_letter": "", "path": str(volume), "filesystem": "NTFS", "label": ""}
    return image, json.dumps({"volumes": [vol]})


BITLOCKER_HEADER = b"\xeb\x58\x90-FVE-FS-" + bytes(501)


def test_is_bitlocker():
    assert is_bitlocker(BITLOCKER_HEADER) is True
    assert is_bitlocker(b"\xeb\x52\x90NTFS    " + bytes(501)) is False
    assert is_bitlocker(b"") is False


def test_read_volume_header(tmp_path):
    volume = tmp_path / "volume"
    volume.write_bytes(BITLOCKER_HEADER + bytes(8192))
    assert read_volume_header(str(volume)) == BITLOCKER_HEADER + bytes(4096 - 512)
    assert read_volume_header(str(tmp_path / "nonexistent")) == b""


def test_search_volumes_windows_bitlocker(tmp_path, monkeypatch, caplog):
    headers = {"\\\\?\\Volume{locked}": BITLOCKER_HEADER}
    monkeypatch.setattr(pillage_api, "read_volume_header", lambda p: headers.get(p, b""))
    volumes = [
        {
            "drive_letter": "E",
            "path": "\\\\?\\Volume{locked}\\",
            "filesystem": "Unknown",
            "label": "",
        },
        {
            "drive_letter": "",
            "path": "\\\\?\\Volume{ext4}\\",
            "filesystem": "Unknown",
            "label": "",
        },
    ]

    assert search_volumes_windows(volumes, tmp_path / "results") is False
    assert caplog.text.count("encrypted with BitLocker and locked") == 1
    assert "filesystem isn't readable by Windows" in caplog.text

    # Lock status from Get-BitLockerVolume
    caplog.clear()
    volumes[1]["bitlocker"] = "Locked"
    assert search_volumes_windows(volumes[1:], tmp_path / "results") is False
    assert "encrypted with BitLocker" in caplog.text


@pytest.mark.parametrize("already_attached", [False, True])
def test_pillage_image_windows(tmp_path, monkeypatch, pillage_config, already_attached):  # noqa: ARG001
    image, out = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, (0, out), str(already_attached), calls)

    assert pillage(str(image)) is True
    results = tmp_path / "pillage_results" / "SEL"
    assert (results / "SET_ALL.TXT").is_file()
    assert not (results / "excluded.rdb").exists()  # System directories are skipped

    if already_attached:
        assert _scripts(calls) == ["attached", "mount"]  # Left attached
    else:
        assert _scripts(calls) == ["attached", "mount", "unmount"]
    assert all(c[1] == image for c in calls)
    assert all(not c[2] for c in calls)  # No secrets


@pytest.mark.usefixtures("pillage_config")
@pytest.mark.parametrize("already_attached", [False, True])
def test_pillage_image_windows_mount_fails(tmp_path, monkeypatch, already_attached):
    # Mounting can fail after the image was attached, so it's always unmounted,
    # unless it was attached before pillage started
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, (1, ""), str(already_attached), calls)

    assert pillage(str(image)) is False
    if already_attached:
        assert _scripts(calls) == ["attached", "mount"]
    else:
        assert _scripts(calls) == ["attached", "mount", "unmount"]


def test_pillage_image_windows_interrupted(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, calls=calls)

    def _interrupt(*args):  # noqa: ARG001
        raise KeyboardInterrupt

    monkeypatch.setattr(pillage_api, "mount_image_windows", _interrupt)
    with pytest.raises(KeyboardInterrupt):
        pillage(str(image))
    assert _scripts(calls) == ["attached", "unmount"]


def test_pillage_image_windows_not_an_image(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    calls = []
    _fake_powershell(monkeypatch, attached="", calls=calls)

    assert pillage(str(image)) is False
    assert _scripts(calls) == ["attached"]  # Nothing to unmount


def test_pillage_image_windows_converts(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    image, out = _setup_image_windows(tmp_path, monkeypatch, "disk.img")

    def _qemu_img(args):
        assert args[:4] == ["qemu-img", "convert", "-O", "vhdx"]
        Path(args[-1]).write_bytes(b"")
        return 0

    monkeypatch.setattr(subprocess, "call", _qemu_img)
    calls = []
    _fake_powershell(monkeypatch, (0, out), calls=calls)

    assert pillage(str(image)) is True
    converted = calls[0][1]
    assert converted.name == "disk.vhdx"
    assert converted.parent.parent == tmp_path
    assert converted.parent.name.startswith("pillage_temp_")
    assert not list(tmp_path.glob("pillage_temp*"))  # Cleaned up


def test_pillage_image_windows_convert_interrupted(tmp_path, monkeypatch, pillage_config):  # noqa: ARG001
    image, _ = _setup_image_windows(tmp_path, monkeypatch, "disk.img")

    def _qemu_img(args):
        Path(args[-1]).write_bytes(b"partial")
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "call", _qemu_img)
    calls = []
    _fake_powershell(monkeypatch, calls=calls)

    with pytest.raises(KeyboardInterrupt):
        pillage(str(image))
    assert not calls  # Nothing was mounted
    assert not list(tmp_path.glob("pillage_temp*"))  # Cleaned up


def _diskpart(script: str, tmp_path: Path) -> None:
    script_path = tmp_path / "diskpart.txt"
    script_path.write_text(textwrap.dedent(script), encoding="utf-8")
    proc = subprocess.run(
        ["diskpart", "/s", str(script_path)],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.slow
@pytest.mark.skipif(not consts.WINDOWS, reason="Windows-only")
def test_pillage_vhdx_windows(tmp_path, monkeypatch, caplog, pillage_config):  # noqa: ARG001
    """Create a real VHDX image with diskpart, then pillage it."""
    if not utils.are_we_superuser():
        pytest.skip("Mounting VHDX images requires Administrator")

    image = tmp_path / "pillage_test.vhdx"
    mount_dir = tmp_path / "mnt"
    mount_dir.mkdir()

    _diskpart(
        f"""
        create vdisk file="{image}" maximum=64 type=expandable
        select vdisk file="{image}"
        attach vdisk
        create partition primary
        format fs=ntfs quick label=PEATTEST
        assign mount="{mount_dir}"
        """,
        tmp_path,
    )
    try:
        _make_source(mount_dir)
    finally:
        _diskpart(
            f"""
            select vdisk file="{image}"
            detach vdisk
            """,
            tmp_path,
        )

    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)

    caplog.set_level("DEBUG")
    assert pillage(str(image)) is True, caplog.text
    results = work_dir / "pillage_results"
    found = sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())
    assert found == ["SEL/SET_ALL.TXT", "SEL/nested.rdb", "SEL/relay2.rdb"]
    assert (results / "SEL" / "relay2.rdb").read_text(encoding="utf-8") == "relay2"

    # The image is unmounted when pillage finishes
    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-DiskImage -ImagePath '{image}').Attached",
        ],
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    assert proc.stdout.strip() == "False"


# -- Encrypted volumes: secrets --

RECOVERY_PASSWORD = "123456-234567-345678-456789-567890-678901-789012-890123"
LUKS_HEADER = b"LUKS\xba\xbe\x00\x02" + bytes(4088)
LVM_HEADER = bytes(512) + b"LABELONE" + bytes(16) + b"LVM2 001" + bytes(3552)


@pytest.mark.parametrize(
    ("secret", "expected"),
    [
        (RECOVERY_PASSWORD, True),
        (f"  {RECOVERY_PASSWORD}\t", True),
        (RECOVERY_PASSWORD.replace("-", ""), False),
        (RECOVERY_PASSWORD[:-1], False),
        (RECOVERY_PASSWORD + "-123456", False),
        ("correct horse battery staple", False),
        ("", False),
    ],
)
def test_is_recovery_password(secret, expected):
    assert pillage_api.is_recovery_password(secret) is expected


def test_unlock_secrets_load(tmp_path):
    password_file = tmp_path / "passwords.txt"
    # Byte order mark, Windows line endings, empty lines, and spaces in passwords
    password_file.write_bytes(
        "\ufeffpass one\r\n\r\n\n  spaced  \r\n".encode() + RECOVERY_PASSWORD.encode()
    )
    secrets = UnlockSecrets(password_file)

    assert secrets.load() is True
    assert list(secrets.candidates("vol")) == ["pass one", "  spaced  ", RECOVERY_PASSWORD]

    # Secrets that worked are tried first next time
    secrets.remember(RECOVERY_PASSWORD)
    secrets.remember("prompted")
    assert list(secrets.candidates("vol")) == [
        "prompted",
        "pass one",
        "  spaced  ",
        RECOVERY_PASSWORD,
    ]


def test_unlock_secrets_load_errors(tmp_path):
    assert UnlockSecrets().load() is True
    assert UnlockSecrets(tmp_path / "nonexistent.txt").load() is False
    (tmp_path / "empty.txt").write_text("\n\r\n", encoding="utf-8")
    assert UnlockSecrets(tmp_path / "empty.txt").load() is False


def test_unlock_secrets_prompt(monkeypatch):
    prompts = []
    answers = iter(["first", "second", "third", "fourth"])

    def _getpass(prompt):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr(pillage_api.getpass, "getpass", _getpass)
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: True))

    # Prompts up to 3 times
    assert list(UnlockSecrets().candidates("'E:' (BitLocker)")) == ["first", "second", "third"]
    assert len(prompts) == 3
    assert "'E:' (BitLocker)" in prompts[0]

    # An empty answer, or EOF, skips the volume
    answers = iter(["", "never"])
    assert list(UnlockSecrets().candidates("vol")) == []

    def _eof(prompt):  # noqa: ARG001
        raise EOFError

    monkeypatch.setattr(pillage_api.getpass, "getpass", _eof)
    assert list(UnlockSecrets().candidates("vol")) == []


def test_unlock_secrets_no_prompt(tmp_path, monkeypatch):
    def _getpass(prompt):
        raise AssertionError(f"Unexpected prompt: {prompt}")

    monkeypatch.setattr(pillage_api.getpass, "getpass", _getpass)

    # Not a terminal
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: False))
    assert list(UnlockSecrets().candidates("vol")) == []

    # A password file was given, so there's no prompt even in a terminal
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: True))
    (tmp_path / "pw.txt").write_text("from file\n", encoding="utf-8")
    secrets = UnlockSecrets(tmp_path / "pw.txt")
    assert secrets.load() is True
    assert list(secrets.candidates("vol")) == ["from file"]


def test_unlock_secrets_can_prompt(monkeypatch):
    monkeypatch.setattr(pillage_api.sys, "stdin", None)
    assert UnlockSecrets.can_prompt() is False


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_bad_password_file(tmp_path, monkeypatch):
    image = tmp_path / "disk.img"
    image.write_bytes(b"")
    monkeypatch.chdir(tmp_path)

    def _fail(*args):  # noqa: ARG001
        raise AssertionError("Image shouldn't be mounted")

    monkeypatch.setattr(pillage_api, "pillage_image_windows", _fail)
    monkeypatch.setattr(pillage_api, "pillage_image_linux", _fail)
    assert pillage(str(image), password_file=tmp_path / "nonexistent.txt") is False


# -- Encrypted volumes: Windows --


def _locked_volume_windows(monkeypatch, tmp_path, drive_letter: str = "") -> dict:
    """A locked BitLocker volume, at the volume from _setup_image_windows once unlocked."""
    volume = tmp_path / "volume"
    monkeypatch.setattr(
        pillage_api,
        "read_volume_header",
        lambda p: BITLOCKER_HEADER if p == str(volume) else b"",
    )
    return {
        "drive_letter": drive_letter,
        "path": str(volume),
        "filesystem": "Unknown",
        "label": "SECRET",
    }


def _password_file(tmp_path: Path, *secrets: str) -> Path:
    path = tmp_path / "passwords.txt"
    path.write_text("\n".join(secrets) + "\n", encoding="utf-8")
    return path


@pytest.mark.usefixtures("pillage_config")
@pytest.mark.parametrize(
    ("secret", "secret_type"), [("hunter22", "password"), (RECOVERY_PASSWORD, "recovery")]
)
@pytest.mark.parametrize("already_attached", [False, True])
def test_pillage_image_windows_bitlocker(
    tmp_path, monkeypatch, caplog, secret, secret_type, already_attached
):
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    vol = _locked_volume_windows(monkeypatch, tmp_path, drive_letter="E")
    calls = []
    _fake_powershell(
        monkeypatch,
        (0, json.dumps({"volumes": [vol]})),
        str(already_attached),
        calls,
        unlock_passwords=(secret,),
    )
    searched = []
    monkeypatch.setattr(
        pillage_api, "search", lambda path, *_, **__: searched.append(path) or True
    )
    password_file = _password_file(tmp_path, "wrong password", secret)

    caplog.set_level("DEBUG")
    assert pillage(str(image), password_file=password_file) is True
    assert searched == ["E:\\"]

    expected = ["attached", "mount", "available", "unlock", "unlock"]
    if already_attached:
        assert _scripts(calls) == [*expected, "lock"]  # PEAT locks it again
        assert calls[-1][2] == {"PEAT_PILLAGE_VOLUME": "E:"}
    else:
        assert _scripts(calls) == [*expected, "unmount"]  # Unmounting locks it

    unlock_env = calls[4][2]
    assert unlock_env["PEAT_PILLAGE_VOLUME"] == "E:"
    assert unlock_env["PEAT_PILLAGE_VOLUME_PATH"] == vol["path"]
    assert unlock_env["PEAT_PILLAGE_SECRET"] == secret
    assert unlock_env["PEAT_PILLAGE_SECRET_TYPE"] == secret_type
    assert calls[3][2]["PEAT_PILLAGE_SECRET_TYPE"] == "password"  # "wrong password"
    assert secret not in caplog.text
    assert "wrong password" not in caplog.text


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_windows_bitlocker_wrong_password(tmp_path, monkeypatch, caplog):
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    vol = _locked_volume_windows(monkeypatch, tmp_path)
    calls = []
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": [vol]})), calls=calls)

    assert pillage(str(image), password_file=_password_file(tmp_path, "a", "b")) is False
    assert _scripts(calls) == ["attached", "mount", "available", "unlock", "unlock", "unmount"]
    # Volumes without a drive letter are unlocked using their volume GUID path
    assert calls[3][2]["PEAT_PILLAGE_VOLUME"] == vol["path"]
    assert "none of the 2 passwords tried unlocked it" in caplog.text
    assert "encrypted with BitLocker and locked" in caplog.text


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_windows_bitlocker_unavailable(tmp_path, monkeypatch, caplog):
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    vol = _locked_volume_windows(monkeypatch, tmp_path)
    calls = []
    _fake_powershell(
        monkeypatch,
        (0, json.dumps({"volumes": [vol]})),
        calls=calls,
        bitlocker_available="False",
    )

    assert pillage(str(image), password_file=_password_file(tmp_path, "pw")) is False
    assert _scripts(calls) == ["attached", "mount", "available", "unmount"]
    assert "BitLocker PowerShell module (Unlock-BitLocker) isn't available" in caplog.text


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_windows_bitlocker_no_password(tmp_path, monkeypatch, caplog):
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    vol = _locked_volume_windows(monkeypatch, tmp_path)
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: False))
    calls = []
    _fake_powershell(monkeypatch, (0, json.dumps({"volumes": [vol]})), calls=calls)

    assert pillage(str(image)) is False
    assert _scripts(calls) == ["attached", "mount", "available", "unmount"]
    assert "--password-file" in caplog.text


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_windows_bitlocker_prompt(tmp_path, monkeypatch):
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    vol = _locked_volume_windows(monkeypatch, tmp_path)
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: True))
    answers = iter(["typo", "typed"])
    monkeypatch.setattr(pillage_api.getpass, "getpass", lambda _: next(answers))
    calls = []
    _fake_powershell(
        monkeypatch,
        (0, json.dumps({"volumes": [vol]})),
        calls=calls,
        unlock_passwords=("typed",),
    )

    assert pillage(str(image)) is True
    assert (tmp_path / "pillage_results" / "SEL" / "relay2.rdb").is_file()
    assert [c[2]["PEAT_PILLAGE_SECRET"] for c in calls if c[2].get("PEAT_PILLAGE_SECRET")] == [
        "typo",
        "typed",
    ]


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_windows_bitlocker_search_fails(tmp_path, monkeypatch):
    # Volumes on images that were already attached are locked again, even if searching fails
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    vol = _locked_volume_windows(monkeypatch, tmp_path)
    calls = []
    _fake_powershell(
        monkeypatch,
        (0, json.dumps({"volumes": [vol]})),
        "True",
        calls,
        unlock_passwords=("pw",),
    )

    def _interrupt(*args):  # noqa: ARG001
        raise KeyboardInterrupt

    monkeypatch.setattr(pillage_api, "search_volumes_windows", _interrupt)
    assert pillage(str(image), password_file=_password_file(tmp_path, "pw")) is False
    assert _scripts(calls) == ["attached", "mount", "available", "unlock", "lock"]


def test_unlock_bitlocker_windows_output(monkeypatch):
    def _run(script, image=None, env_vars=None):  # noqa: ARG001
        return subprocess.CompletedProcess([], 0, stdout="WARNING: something\nNTFS\n", stderr="")

    monkeypatch.setattr(pillage_api, "_run_powershell", _run)
    assert pillage_api.unlock_bitlocker_windows("E:", "\\\\?\\Volume{x}\\", "pw") == "NTFS"


def test_lock_bitlocker_windows_fails(monkeypatch, caplog):
    def _run(script, image=None, env_vars=None):  # noqa: ARG001
        return subprocess.CompletedProcess([], 1, stdout="", stderr="busy")

    monkeypatch.setattr(pillage_api, "_run_powershell", _run)
    assert pillage_api.lock_bitlocker_windows("E:") is False
    assert "Lock-BitLocker -MountPoint" in caplog.text


# -- Encrypted volumes and partitions: Linux --


def test_is_luks_and_lvm():
    assert pillage_api.is_luks(LUKS_HEADER) is True
    assert pillage_api.is_luks(BITLOCKER_HEADER) is False
    assert pillage_api.is_luks(b"") is False
    assert pillage_api.is_lvm(LVM_HEADER) is True
    assert pillage_api.is_lvm(LVM_HEADER[512:]) is True  # Label in the first sector
    assert pillage_api.is_lvm(LUKS_HEADER) is False
    assert pillage_api.is_lvm(b"") is False


def test_list_partitions_linux(tmp_path):
    for name in ["nbd1p10", "nbd1p2", "nbd1p1", "nbd1pX"]:
        (tmp_path / "nbd1" / name).mkdir(parents=True)
    assert pillage_api.list_partitions_linux("/dev/nbd1", tmp_path) == [
        "/dev/nbd1p1",
        "/dev/nbd1p2",
        "/dev/nbd1p10",
    ]

    # No partition table, e.g. a filesystem directly on the disk
    (tmp_path / "nbd2").mkdir()
    assert pillage_api.list_partitions_linux("/dev/nbd2", tmp_path) == ["/dev/nbd2"]


def test_run_command(tmp_path):
    proc = pillage_api._run_command(
        [sys.executable, "-c", "import sys; print(sys.stdin.read()[::-1])"],
        input_data=b"terces",
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "secret"

    proc = pillage_api._run_command([str(tmp_path / "nonexistent")])
    assert proc.returncode == 1
    assert proc.stderr


def _cmd(args: list[str]) -> str:
    """The command and its first argument, with paths replaced by '/'."""
    return " ".join("/" if a.startswith("/") or os.path.isabs(a) else a for a in args[:2])


class FakeLinux:
    """
    Fake the commands used to mount images on Linux.

    ``partitions`` maps each partition device to its header. Encrypted partitions
    are unlocked by ``password``, and their header once unlocked is in ``unlocked``.
    Devices in ``unmountable`` fail to mount, devices in ``interrupt`` raise
    KeyboardInterrupt when mounted, and the rest are filled with project files.
    Commands in ``fail`` (see :func:`_cmd`) fail with that return code.
    """

    def __init__(self, monkeypatch, tmp_path, partitions, **kwargs):
        self.partitions: dict[str, bytes] = partitions
        self.password: str = kwargs.get("password", "")
        self.unlocked: dict[str, bytes] = kwargs.get("unlocked", {})
        self.unmountable: set[str] = set(kwargs.get("unmountable", []))
        self.interrupt: set[str] = set(kwargs.get("interrupt", []))
        self.host_vgs: str = kwargs.get("host_vgs", "")
        self.fail: dict[str, int] = kwargs.get("fail", {})
        self.tools: set[str] = set(kwargs.get("tools", ["cryptsetup", "lvm", "qemu-nbd"]))
        self.calls: list[tuple[list[str], bytes]] = []
        self.mapped: dict[str, str] = {}  # /dev/mapper device: partition
        self.removed_modules: list[str] = []
        self.rmmod_failures: int = kwargs.get("rmmod_failures", 0)

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(consts, "WINDOWS", False)
        monkeypatch.setattr(pillage_api, "validate_image_mounting", lambda: True)
        monkeypatch.setattr(pillage_api, "list_loaded_modules", list)
        monkeypatch.setattr(pillage_api, "kmodpy", self, raising=False)
        monkeypatch.setattr(pillage_api, "_run_command", self.run)
        monkeypatch.setattr(pillage_api, "read_volume_header", self.header)
        monkeypatch.setattr(pillage_api, "list_partitions_linux", lambda _: list(partitions))
        monkeypatch.setattr(pillage_api.time, "sleep", lambda _: None)
        monkeypatch.setattr(shutil, "which", lambda cmd: cmd if cmd in self.tools else None)

    # kmodpy.Kmod()
    def Kmod(self):
        return self

    def modprobe(self, name):
        assert name == "nbd"

    def rmmod(self, name):
        if self.rmmod_failures:
            self.rmmod_failures -= 1
            raise RuntimeError("Module nbd is in use")
        self.removed_modules.append(name)

    def header(self, device: str) -> bytes:
        if device in self.mapped:
            return self.unlocked.get(self.mapped[device], b"")
        return self.partitions.get(device, b"")

    def run(self, args: list[str], input_data: bytes = b"", timeout: float = 0):  # noqa: ARG002
        self.calls.append((args, input_data))
        returncode, stdout = self.fail.get(_cmd(args), 0), ""

        if args[:2] == ["cryptsetup", "open"]:
            if input_data.decode() != self.password:
                returncode = 2
            else:
                self.mapped[f"/dev/mapper/{args[-1]}"] = args[-2]
        elif args[0] == "mount":
            if args[3] in self.interrupt:
                raise KeyboardInterrupt
            if args[3] in self.unmountable:
                returncode = 32
            else:
                _make_source(Path(args[4]))
        elif args[0] == "umount" and not returncode:
            for child in Path(args[1]).iterdir():
                shutil.rmtree(child)
        elif args[:2] == ["lvm", "pvs"]:
            stdout = "  vg-data  UUID-1\n"
        elif args[:2] == ["lvm", "vgs"]:
            stdout = self.host_vgs
        elif args[:2] == ["lvm", "lvs"]:
            stdout = "  root\n  swap-1\n"

        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr="error")

    def commands(self) -> list[str]:
        return [_cmd(args) for args, _ in self.calls]


def _mapper(device: str) -> str:
    return f"peat_pillage_{os.getpid()}_{Path(device).name}"


def _disk_image(tmp_path: Path, name: str = "disk.img") -> Path:
    image = tmp_path / name
    image.write_bytes(b"")
    return image


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_partitions(tmp_path, monkeypatch, caplog):
    # A common Ubuntu image: EFI and boot partitions, then LUKS with LVM in it
    fake = FakeLinux(
        monkeypatch,
        tmp_path,
        {"/dev/nbd1p1": b"", "/dev/nbd1p2": b"", "/dev/nbd1p3": LUKS_HEADER},
        password="hunter22",
        unlocked={"/dev/nbd1p3": LVM_HEADER},
        unmountable=["/dev/mapper/vg--data-swap--1"],
    )
    image = _disk_image(tmp_path, "ubuntu.qcow2")
    password_file = _password_file(tmp_path, "wrong", "hunter22")

    caplog.set_level("DEBUG")
    assert pillage(str(image), password_file=password_file) is True

    mapper = _mapper("/dev/nbd1p3")
    assert fake.commands() == [
        "qemu-nbd -r",
        "mount -o",  # nbd1p1
        "mount -o",  # nbd1p2
        "cryptsetup open",  # wrong password
        "cryptsetup open",
        "lvm pvs",
        "lvm vgs",
        "lvm vgchange",
        "lvm lvs",
        "mount -o",  # root LV
        "mount -o",  # swap LV, fails
        "umount /",
        "umount /",
        "umount /",
        "lvm vgchange",
        "cryptsetup close",
        "qemu-nbd -d",
    ]
    assert fake.removed_modules == ["nbd"]  # PEAT loaded it, so it removes it

    # Unlocked read-only, with the key passed on stdin
    open_args, key = fake.calls[4]
    assert open_args == [
        "cryptsetup",
        "open",
        "--type",
        "luks",
        "--readonly",
        "--key-file",
        "-",
        "/dev/nbd1p3",
        mapper,
    ]
    assert key == b"hunter22"
    assert all("hunter22" not in " ".join(args) for args, _ in fake.calls)
    assert "hunter22" not in caplog.text

    # LVM is limited to the unlocked device, and activated read-only
    vgchange = fake.calls[7][0]
    assert vgchange[-1] == "vg-data"
    assert f"a|^/dev/mapper/{mapper}$|" in vgchange[3]
    assert 'read_only_volume_list = [ "vg-data" ]' in vgchange[3]
    assert fake.calls[14][0][-3:] == ["--activate", "n", "vg-data"]
    assert fake.calls[15][0] == ["cryptsetup", "close", mapper]

    # Each volume is mounted read-only in its own directory
    mounts = [args for args, _ in fake.calls if args[0] == "mount"]
    assert all(args[1:3] == ["-o", "ro"] for args in mounts)
    assert [args[3] for args in mounts] == [
        "/dev/nbd1p1",
        "/dev/nbd1p2",
        "/dev/mapper/vg--data-root",
        "/dev/mapper/vg--data-swap--1",
    ]
    assert [Path(args[4]).name for args in mounts] == [
        "nbd1p1",
        "nbd1p2",
        "nbd1p3_root",
        "nbd1p3_swap-1",
    ]
    assert Path(mounts[0][4]).parent.name.startswith("pillage_temp_")

    results = tmp_path / "pillage_results" / "SEL"
    assert sorted(p.name for p in results.iterdir()) == [
        "SET_ALL.TXT",
        "SET_ALL.TXT.1",
        "SET_ALL.TXT.2",
        "nested.rdb",
        "nested.rdb.1",
        "nested.rdb.2",
        "relay2.rdb",
        "relay2.rdb.1",
        "relay2.rdb.2",
    ]
    assert "Skipping volume '/dev/mapper/vg--data-swap--1'" in caplog.text
    assert not list(tmp_path.glob("pillage_temp*"))  # Cleaned up


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_no_partition_table(tmp_path, monkeypatch):
    fake = FakeLinux(monkeypatch, tmp_path, {"/dev/nbd1": b""})

    assert pillage(str(_disk_image(tmp_path))) is True
    assert [args[3] for args, _ in fake.calls if args[0] == "mount"] == ["/dev/nbd1"]


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_bitlocker(tmp_path, monkeypatch):
    fake = FakeLinux(
        monkeypatch,
        tmp_path,
        {"/dev/nbd1p1": BITLOCKER_HEADER},
        password=RECOVERY_PASSWORD,
    )
    # Whitespace around recovery passwords is ignored
    password_file = _password_file(tmp_path, f" {RECOVERY_PASSWORD} ")

    assert pillage(str(_disk_image(tmp_path, "windows.vhdx")), password_file=password_file)
    open_args, key = fake.calls[1]
    assert open_args[:4] == ["cryptsetup", "open", "--type", "bitlk"]
    assert "--readonly" in open_args
    assert key == RECOVERY_PASSWORD.encode()
    assert fake.calls[2][0][3] == f"/dev/mapper/{_mapper('/dev/nbd1p1')}"


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_no_cryptsetup(tmp_path, monkeypatch, caplog):
    # Encrypted partitions that can't be unlocked are skipped, the rest are searched
    fake = FakeLinux(
        monkeypatch,
        tmp_path,
        {"/dev/nbd1p1": b"", "/dev/nbd1p2": BITLOCKER_HEADER, "/dev/nbd1p3": LUKS_HEADER},
        tools=["qemu-nbd", "lvm"],
    )

    assert pillage(str(_disk_image(tmp_path)), password_file=_password_file(tmp_path, "pw"))
    assert fake.commands() == ["qemu-nbd -r", "mount -o", "umount /", "qemu-nbd -d"]
    assert caplog.text.count("requires 'cryptsetup'") == 2


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_wrong_password(tmp_path, monkeypatch, caplog):
    fake = FakeLinux(monkeypatch, tmp_path, {"/dev/nbd1p1": LUKS_HEADER}, password="right")
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: False))
    image = _disk_image(tmp_path)

    assert pillage(str(image)) is False
    assert "--password-file" in caplog.text
    assert fake.commands() == ["qemu-nbd -r", "qemu-nbd -d"]

    fake.calls.clear()
    assert pillage(str(image), password_file=_password_file(tmp_path, "wrong")) is False
    assert "none of the 1 passwords tried unlocked it" in caplog.text
    assert fake.commands() == ["qemu-nbd -r", "cryptsetup open", "qemu-nbd -d"]
    assert not list(tmp_path.glob("pillage_temp*"))


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_lvm(tmp_path, monkeypatch, caplog):
    # Unencrypted LVM, and an LVM volume group with the same name as one on the host
    fake = FakeLinux(monkeypatch, tmp_path, {"/dev/nbd1p1": b"", "/dev/nbd1p2": LVM_HEADER})

    assert pillage(str(_disk_image(tmp_path))) is True
    vgchange = next(args for args, _ in fake.calls if args[:2] == ["lvm", "vgchange"])
    assert "a|^/dev/nbd1p2$|" in vgchange[3]

    # The image's volume group, if the host activated it, and the host's own
    fake.host_vgs = "  vg-data  UUID-1\n  vg-data  UUID-2\n"
    fake.calls.clear()
    assert pillage(str(_disk_image(tmp_path))) is True
    assert "volume group with the same name is already on this system" in caplog.text
    assert "lvm vgchange" not in fake.commands()

    # LVM isn't installed
    fake.tools.remove("lvm")
    fake.calls.clear()
    assert pillage(str(_disk_image(tmp_path))) is True
    assert "install the 'lvm2' package" in caplog.text
    assert fake.commands() == ["qemu-nbd -r", "mount -o", "umount /", "qemu-nbd -d"]


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_attach_fails(tmp_path, monkeypatch):
    fake = FakeLinux(monkeypatch, tmp_path, {}, fail={"qemu-nbd -r": 1})

    assert pillage(str(_disk_image(tmp_path))) is False
    assert fake.commands() == ["qemu-nbd -r"]  # Nothing to disconnect
    assert fake.removed_modules == ["nbd"]
    assert not list(tmp_path.glob("pillage_temp*"))


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_nbd_already_loaded(tmp_path, monkeypatch):
    fake = FakeLinux(monkeypatch, tmp_path, {"/dev/nbd1p1": b""})
    monkeypatch.setattr(pillage_api, "list_loaded_modules", lambda: ["nbd"])

    assert pillage(str(_disk_image(tmp_path))) is True
    assert fake.removed_modules == []  # Left loaded, since PEAT didn't load it


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_remembers_password(tmp_path, monkeypatch):
    # The password that unlocked one partition is tried first on the others
    fake = FakeLinux(
        monkeypatch,
        tmp_path,
        {"/dev/nbd1p1": LUKS_HEADER, "/dev/nbd1p2": LUKS_HEADER},
        password="pw",
    )
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: True))
    prompts = []
    monkeypatch.setattr(pillage_api.getpass, "getpass", lambda p: prompts.append(p) or "pw")

    assert pillage(str(_disk_image(tmp_path))) is True
    assert len(prompts) == 1
    assert fake.commands().count("cryptsetup open") == 2
    assert fake.commands()[-3:] == ["cryptsetup close", "cryptsetup close", "qemu-nbd -d"]


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_interrupted(tmp_path, monkeypatch):
    # Everything is cleaned up on Ctrl-C, e.g. at a password prompt or while mounting
    fake = FakeLinux(
        monkeypatch,
        tmp_path,
        {"/dev/nbd1p1": LUKS_HEADER, "/dev/nbd1p2": LUKS_HEADER},
        password="pw",
        interrupt=[f"/dev/mapper/{_mapper('/dev/nbd1p2')}"],
    )
    image = _disk_image(tmp_path)
    monkeypatch.setattr(UnlockSecrets, "can_prompt", staticmethod(lambda: True))

    def _interrupt(prompt):  # noqa: ARG001
        raise KeyboardInterrupt

    monkeypatch.setattr(pillage_api.getpass, "getpass", _interrupt)
    with pytest.raises(KeyboardInterrupt):
        pillage(str(image))
    assert fake.commands() == ["qemu-nbd -r", "qemu-nbd -d"]
    assert fake.removed_modules == ["nbd"]

    fake.calls.clear()
    with pytest.raises(KeyboardInterrupt):
        pillage(str(image), password_file=_password_file(tmp_path, "pw"))
    assert fake.commands() == [
        "qemu-nbd -r",
        "cryptsetup open",
        "mount -o",
        "cryptsetup open",
        "mount -o",  # Interrupted
        "umount /",
        "cryptsetup close",
        "cryptsetup close",
        "qemu-nbd -d",
    ]
    assert not list(tmp_path.glob("pillage_temp*"))


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_linux_cleanup_fails(tmp_path, monkeypatch, caplog):
    fake = FakeLinux(monkeypatch, tmp_path, {"/dev/nbd1p1": b""}, fail={"umount /": 32})

    assert pillage(str(_disk_image(tmp_path))) is True
    assert fake.commands() == ["qemu-nbd -r", "mount -o", "umount /", "qemu-nbd -d"]
    assert "Failed to clean up after pillaging the image" in caplog.text
    # Not deleted, since the image may still be mounted in it
    assert len(list(tmp_path.glob("pillage_temp_*"))) == 1


# -- Real encrypted disk images --

REAL_TEST_PASSWORD = "PEAT test p4ssword!"


def _powershell(script: str, **env: str) -> str:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        env={k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"} | env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


def _bitlocker_available_windows() -> bool:
    proc = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[bool](Get-Command Enable-BitLocker -ErrorAction SilentlyContinue) -and "
            "[bool](Get-Service BDESVC -ErrorAction SilentlyContinue)",
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return proc.stdout.strip() == "True"


# Encrypts a volume with a password protector, waits for encryption to finish,
# then adds a recovery password protector and prints the recovery password.
_PS_ENABLE_BITLOCKER_TEST = r"""
$ErrorActionPreference = 'Stop'
$password = ConvertTo-SecureString -String $env:PEAT_TEST_PASSWORD -AsPlainText -Force
Enable-BitLocker -MountPoint $env:PEAT_TEST_VOLUME -PasswordProtector -Password $password `
    -UsedSpaceOnly | Out-Null
$deadline = (Get-Date).AddMinutes(5)
while ((Get-BitLockerVolume -MountPoint $env:PEAT_TEST_VOLUME).VolumeStatus -ne 'FullyEncrypted') {
    if ((Get-Date) -gt $deadline) { throw 'Timed out waiting for BitLocker to encrypt the volume' }
    Start-Sleep -Seconds 1
}
Add-BitLockerKeyProtector -MountPoint $env:PEAT_TEST_VOLUME -RecoveryPasswordProtector `
    -WarningAction SilentlyContinue | Out-Null
(Get-BitLockerVolume -MountPoint $env:PEAT_TEST_VOLUME).KeyProtector |
    Where-Object KeyProtectorType -eq 'RecoveryPassword' |
    Select-Object -First 1 -ExpandProperty RecoveryPassword
"""


def _pillage_in(
    work_dir: Path, monkeypatch, caplog, image: Path, password_file: Path
) -> list[str]:
    """Pillage an image in a new working directory, and return the files found."""
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    assert pillage(str(image), password_file=password_file) is True, caplog.text
    results = work_dir / "pillage_results"
    return sorted(p.relative_to(results).as_posix() for p in results.rglob("*") if p.is_file())


@pytest.mark.slow
@pytest.mark.skipif(not consts.WINDOWS, reason="Windows-only")
def test_pillage_bitlocker_vhdx_windows(tmp_path, monkeypatch, caplog, pillage_config):  # noqa: ARG001
    """
    Create a real VHDX image with a BitLocker encrypted volume, then pillage it,
    unlocking it with a password, and with a recovery password.
    """
    if not utils.are_we_superuser():
        pytest.skip("Mounting VHDX images and BitLocker require Administrator")
    if not _bitlocker_available_windows():
        pytest.skip("BitLocker isn't available (e.g. Windows Server without the feature)")

    image = tmp_path / "pillage_bitlocker.vhdx"
    _diskpart(
        f"""
        create vdisk file="{image}" maximum=256 type=expandable
        select vdisk file="{image}"
        attach vdisk
        create partition primary
        format fs=ntfs quick label=PEATBL
        assign
        """,
        tmp_path,
    )
    try:
        letter = _powershell(
            "(Get-DiskImage -ImagePath $env:PEAT_TEST_IMAGE | Get-Disk | Get-Partition | "
            "Where-Object DriveLetter | Select-Object -First 1).DriveLetter",
            PEAT_TEST_IMAGE=str(image),
        )
        assert len(letter) == 1, letter
        _make_source(Path(f"{letter}:\\"))
        recovery_password = _powershell(
            _PS_ENABLE_BITLOCKER_TEST,
            PEAT_TEST_VOLUME=f"{letter}:",
            PEAT_TEST_PASSWORD=REAL_TEST_PASSWORD,
        ).splitlines()[-1]
        assert pillage_api.is_recovery_password(recovery_password), recovery_password
    finally:
        _diskpart(
            f"""
            select vdisk file="{image}"
            detach vdisk
            """,
            tmp_path,
        )

    expected = ["SEL/SET_ALL.TXT", "SEL/nested.rdb", "SEL/relay2.rdb"]
    caplog.set_level("DEBUG")

    # Password, after a wrong one
    password_file = _password_file(tmp_path, "wrong password", REAL_TEST_PASSWORD)
    assert (
        _pillage_in(tmp_path / "password", monkeypatch, caplog, image, password_file) == expected
    ), caplog.text
    # Unlocked even though the image is attached read-only
    assert "Unlocked BitLocker volume" in caplog.text

    # Recovery password
    password_file = _password_file(tmp_path, recovery_password)
    assert (
        _pillage_in(tmp_path / "recovery", monkeypatch, caplog, image, password_file) == expected
    ), caplog.text
    assert REAL_TEST_PASSWORD not in caplog.text
    assert recovery_password not in caplog.text

    # The image is unmounted when pillage finishes
    attached = _powershell(
        "(Get-DiskImage -ImagePath $env:PEAT_TEST_IMAGE).Attached", PEAT_TEST_IMAGE=str(image)
    )
    assert attached == "False"


def _sh(*args: str, input_data: bytes = b"") -> str:
    proc = subprocess.run(list(args), input=input_data, capture_output=True, check=False)
    assert proc.returncode == 0, f"{args}: {proc.stdout!r} {proc.stderr!r}"
    return proc.stdout.decode().strip()


@pytest.mark.slow
@pytest.mark.skipif(not consts.LINUX or consts.WSL, reason="Linux-only")
def test_pillage_image_linux_real(tmp_path, monkeypatch, caplog, pillage_config):  # noqa: ARG001
    """
    Create a real raw disk image with an ext4 partition, a swap partition, and a
    LUKS encrypted partition with LVM in it (like a default encrypted Ubuntu
    install), then pillage it. Requires root, and the nbd kernel module.
    """
    if os.geteuid() != 0:
        pytest.skip("Mounting disk images requires root")
    tools = ["qemu-nbd", "cryptsetup", "lvm", "sfdisk", "losetup", "mkfs.ext4", "mkswap"]
    missing = [tool for tool in tools if not shutil.which(tool)]
    if missing:
        pytest.skip(f"Missing tools: {missing}")
    if subprocess.run(["modinfo", "nbd"], capture_output=True, check=False).returncode != 0:
        pytest.skip("The nbd kernel module isn't available")

    image = tmp_path / "disk.img"
    with image.open("wb") as fp:
        fp.truncate(128 * 1024 * 1024)
    _sh(
        "sfdisk",
        "--quiet",
        str(image),
        input_data=b"label: gpt\nsize=16MiB, type=linux\nsize=8MiB, type=swap\ntype=linux\n",
    )

    password = REAL_TEST_PASSWORD.encode()
    vg = f"peat_test_{os.getpid()}"
    luks = f"peat_test_luks_{os.getpid()}"
    mnt = tmp_path / "mnt"
    mnt.mkdir()

    loop = _sh("losetup", "--find", "--show", "--partscan", str(image))
    try:
        if shutil.which("udevadm"):
            _sh("udevadm", "settle")
        _sh("mkfs.ext4", "-q", f"{loop}p1")
        _sh("mount", f"{loop}p1", str(mnt))
        try:
            (mnt / "efi").mkdir()
            (mnt / "efi" / "boot.rdb").write_text("boot", encoding="utf-8")
        finally:
            _sh("umount", str(mnt))
        _sh("mkswap", f"{loop}p2")

        _sh(
            "cryptsetup",
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--key-file",
            "-",
            f"{loop}p3",
            input_data=password,
        )
        _sh("cryptsetup", "open", "--key-file", "-", f"{loop}p3", luks, input_data=password)
        try:
            _sh("lvm", "pvcreate", "-q", f"/dev/mapper/{luks}")
            _sh("lvm", "vgcreate", "-q", vg, f"/dev/mapper/{luks}")
            _sh("lvm", "lvcreate", "-q", "-y", "-n", "root", "-l", "100%FREE", vg)
            _sh("mkfs.ext4", "-q", f"/dev/mapper/{vg}-root")
            _sh("mount", f"/dev/mapper/{vg}-root", str(mnt))
            try:
                _make_source(mnt)
            finally:
                _sh("umount", str(mnt))
        finally:
            _sh("lvm", "vgchange", "-q", "--activate", "n", vg)
            _sh("cryptsetup", "close", luks)
    finally:
        _sh("losetup", "--detach", loop)

    caplog.set_level("DEBUG")
    password_file = _password_file(tmp_path, "wrong password", REAL_TEST_PASSWORD)
    work_dir = tmp_path / "work"
    assert _pillage_in(work_dir, monkeypatch, caplog, image, password_file) == [
        "SEL/SET_ALL.TXT",
        "SEL/boot.rdb",
        "SEL/nested.rdb",
        "SEL/relay2.rdb",
    ], caplog.text
    assert "Skipping volume '/dev/nbd1p2', it couldn't be mounted" in caplog.text  # swap
    assert f"Activated LVM volume group '{vg}' (read-only)" in caplog.text
    assert REAL_TEST_PASSWORD not in caplog.text

    # Everything is cleaned up
    assert not list(work_dir.glob("pillage_temp*"))
    assert not list(Path("/dev/mapper").glob("peat_pillage_*"))
    assert not Path(f"/dev/mapper/{vg}-root").exists()
    assert not Path("/sys/block/nbd1/pid").exists()  # Disconnected


@pytest.mark.usefixtures("pillage_config")
@pytest.mark.parametrize(("failures", "removed"), [(3, True), (10, False)])
def test_pillage_image_linux_rmmod_busy(tmp_path, monkeypatch, caplog, failures, removed):
    # The nbd module is busy for a moment after the device is disconnected
    fake = FakeLinux(monkeypatch, tmp_path, {"/dev/nbd1p1": b""}, rmmod_failures=failures)

    assert pillage(str(_disk_image(tmp_path))) is True
    assert fake.removed_modules == (["nbd"] if removed else [])
    assert ("Failed to remove 'nbd' module" in caplog.text) is not removed
    # Deleted even if nbd couldn't be removed, since nothing is mounted in it
    assert not list(tmp_path.glob("pillage_temp*"))


@pytest.mark.usefixtures("pillage_config")
def test_pillage_image_windows_bitlocker_lock_status(tmp_path, monkeypatch):
    # Volumes that the BitLocker module says are locked are unlocked, even if their
    # header can't be read (reading volumes directly can fail on Windows)
    image, _ = _setup_image_windows(tmp_path, monkeypatch)
    monkeypatch.setattr(pillage_api, "read_volume_header", lambda _: b"")
    vol = {
        "drive_letter": "",
        "path": str(tmp_path / "volume"),
        "filesystem": "Unknown",
        "label": "",
        "bitlocker": "Locked",
    }
    ext4 = {**vol, "path": "\\\\?\\Volume{ext4}\\", "bitlocker": "Unlocked"}
    calls = []
    _fake_powershell(
        monkeypatch,
        (0, json.dumps({"volumes": [ext4, vol]})),
        calls=calls,
        unlock_passwords=("pw",),
    )

    assert pillage(str(image), password_file=_password_file(tmp_path, "pw")) is True
    assert _scripts(calls) == ["attached", "mount", "available", "unlock", "unmount"]
    assert calls[3][2]["PEAT_PILLAGE_VOLUME"] == vol["path"]
