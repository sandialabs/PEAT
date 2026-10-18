import json
import os
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

from peat import config, consts, utils
from peat.api import pillage_api
from peat.api.pillage_api import (
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
):
    """Fake the PowerShell scripts: (returncode, stdout) for mount, and the attached state."""

    def _run(script, image):
        if calls is not None:
            calls.append((script, image))
        if script == pillage_api._PS_MOUNT_SCRIPT:
            returncode, stdout = mount
        elif script == pillage_api._PS_ATTACHED_SCRIPT:
            returncode, stdout = 0, attached
        else:
            returncode, stdout = 0, ""
        return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="error")

    monkeypatch.setattr(pillage_api, "_run_powershell", _run)


def _scripts(calls: list) -> list[str]:
    names = {
        pillage_api._PS_ATTACHED_SCRIPT: "attached",
        pillage_api._PS_MOUNT_SCRIPT: "mount",
        pillage_api._PS_UNMOUNT_SCRIPT: "unmount",
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
    assert "encrypted with BitLocker" in caplog.text
    assert caplog.text.count("encrypted with BitLocker") == 1
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
