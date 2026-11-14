import os
import re
import shlex
import socket
import sys
import threading
from base64 import b64decode, b64encode
from time import monotonic, sleep
from unittest.mock import Mock

import pytest

from peat import SCEPTRE, DeviceData
from peat.modules.sandia import sceptre_fcd, sceptre_shell
from peat.modules.sandia.sceptre_fcd import FIRMWARE_PREFIX, FIRMWARE_UPLOAD_NAME
from peat.protocols import SSH, Telnet

FIRMWARE = os.urandom(1024 * 1024)
HOME = "/home/sceptre"
ARG = r"'[^']*'|\S+"  # A shell-quoted path


class FakeSFTP:
    def __init__(self, files: dict[str, bytes], behavior: dict) -> None:
        self.files = files
        self.behavior = behavior

    def listdir(self, path):
        return [p.rsplit("/", 1)[1] for p in self.files if p.startswith(path + "/")]

    def getfo(self, path, buf):
        buf.write(self.files[path])

    def putfo(self, buf, path):
        data = buf.read()
        if self.behavior["put_fails"]:
            self.files[path] = data[:10]  # Truncated transfer
            raise OSError("put failed")
        self.files[path] = data
        self.behavior["ops"].append(f"write {path}")

    def posix_rename(self, old, new):
        self.behavior["ops"].append(f"rename {old} {new}")
        self.files[new] = self.files.pop(old)

    def remove(self, path):
        del self.files[path]


class FakeSSHClient:
    def __init__(self, files, behavior):
        self.sftp = FakeSFTP(files, behavior)
        self.behavior = behavior

    def open_sftp(self):
        if self.behavior["sftp_fails"]:
            raise OSError("no sftp subsystem")
        return self.sftp

    def close(self):
        pass


class FakeTelnetComm:
    """A tiny shell: ls, wc, base64 <f>, base64 -d > <f> <<'EOF', mv, stty [-]echo."""

    def __init__(self, files: dict[str, bytes], behavior: dict) -> None:
        self.files = files
        self.behavior = behavior
        self.commands: list[str] = []
        self.out = b"login: "
        self.state = "user"
        self.heredoc: tuple[str, list[str], str] | None = None
        self.buf = ""
        self.echo = True

    def write(self, data: bytes) -> None:
        self.buf += data.decode()
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self._line(line.rstrip("\r"))

    def _line(self, line: str) -> None:
        if self.state == "user":
            self.state = "pass"
            self.out += b"Password: "
        elif self.state == "pass":
            if self.behavior["bad_login"]:
                self.out += b"\r\nLogin incorrect\r\n"
            else:
                self.state = "shell"
                self.out += b"\r\n$ "
        elif self.heredoc:
            name, lines, tail = self.heredoc
            if line == "EOF":
                self.heredoc = None
                if self.behavior["stall"]:
                    return  # The shell never comes back
                if self.behavior["decode_fails"]:
                    self.files[name] = b"trunc"  # base64 died half way
                    if m := re.search(rf"rm -f ({ARG}); echo (\w+)", tail):
                        del self.files[shlex.split(m[1])[0]]
                        self.out += m[2].encode() + b"\r\n"
                else:
                    self.files[name] = b64decode("".join(lines))
                    self.behavior["ops"].append(f"write {name}")
                    m = re.search(rf"&& mv ({ARG}) ({ARG}) && echo (\w+)", tail)
                    self.files[shlex.split(m[2])[0]] = self.files.pop(shlex.split(m[1])[0])
                    self.behavior["ops"].append(
                        f"rename {shlex.split(m[1])[0]} {shlex.split(m[2])[0]}"
                    )
                    self.out += m[3].encode() + b"\r\n"
                self.out += b"$ "
            else:
                lines.append(line)
                self.out += b"> "
        else:
            self._cmd(line)

    def _cmd(self, line: str) -> None:
        self.commands.append(line)
        out = line + "\r\n" if self.echo else ""
        if line in ("stty -echo", "stty echo"):
            self.echo = line == "stty echo"
        if m := re.fullmatch(r"ls -1 (.+) \| cat", line):
            home = shlex.split(m[1])[0]
            out += "".join(
                p.rsplit("/", 1)[1] + "\r\n" for p in self.files if p.startswith(home + "/")
            )
        elif m := re.fullmatch(r"wc -c < (.+)", line):
            out += f"{len(self.files[shlex.split(m[1])[0]])}\r\n"
        elif m := re.fullmatch(r"base64 (?!-d)(.+)", line):
            enc = b64encode(self.files[shlex.split(m[1])[0]]).decode()
            out += "".join(enc[i : i + 76] + "\r\n" for i in range(0, len(enc), 76))
        elif m := re.match(rf"base64 -d > ({ARG}) <<'EOF'(.*)", line):
            self.heredoc = (shlex.split(m[1])[0], [], m[2])
            self.out += out.encode()
            return
        self.out += (out + "$ ").encode()

    def read_very_eager(self) -> bytes:
        return b""

    def read_eager(self) -> bytes:
        data, self.out = self.out, b""
        return data

    def expect(self, patterns, _timeout=None):
        for i, pat in enumerate(patterns):
            if m := pat.search(self.out):
                data, self.out = self.out[: m.end()], self.out[m.end() :]
                return i, m, data
        raise EOFError("no match")

    def read_until(self, match, _timeout=None):
        i = self.out.index(match) + len(match)
        data, self.out = self.out[:i], self.out[i:]
        return data

    def close(self):
        pass


@pytest.fixture
def config(examples_path):
    return examples_path("devices/sceptre/bp/dnp3-client.xml").read_bytes()


@pytest.fixture
def files(config):
    return {f"{HOME}/config.xml": config, f"{HOME}/ferrofire.firmware": FIRMWARE}


@pytest.fixture
def behavior():
    return {
        "bad_login": False,
        "sftp_fails": False,
        "put_fails": False,
        "decode_fails": False,
        "stall": False,
        "ops": [],
    }


@pytest.fixture
def conns():
    """Every connection the code under test opened (disconnect is a Mock)."""
    return []


@pytest.fixture
def fake(monkeypatch, files, behavior, conns):
    """Patch the SSH and Telnet classes used by SceptreShell to use in-memory fakes."""
    monkeypatch.setattr(Telnet, "PRE_WRITE_SLEEP", 0)
    monkeypatch.setattr(Telnet, "POST_WRITE_SLEEP", 0)
    monkeypatch.setattr(Telnet, "READ_DELAY", 0)

    def make_ssh(ip, port, timeout, username=None, password=None):
        conn = SSH(ip, port, timeout, username=username, password=password)
        conn.comm = FakeSSHClient(files, behavior)
        conn.connected = True
        conn.disconnect = Mock()
        conns.append(conn)
        return conn

    def make_telnet(ip, port, timeout):
        conn = Telnet(ip, port, timeout)
        conn.comm = FakeTelnetComm(files, behavior)
        conn.connected = True
        conn.disconnect = Mock()
        conns.append(conn)
        return conn

    monkeypatch.setattr(sceptre_shell, "SSH", make_ssh)
    monkeypatch.setattr(sceptre_shell, "Telnet", make_telnet)
    # No real FTP server: unverified pulls try FTP first
    monkeypatch.setattr(SCEPTRE, "_download_ftp", classmethod(lambda *_a, **_k: (None, None, "")))
    return files


@pytest.fixture
def dev():
    d = DeviceData(ip="192.0.2.10")
    d._module = SCEPTRE
    return d


@pytest.mark.usefixtures("fake")
@pytest.mark.parametrize("protocol", ["ssh", "telnet"])
def test_ssh_identify_finds_firmware(dev, protocol):
    assert SCEPTRE._verify_shell(dev, protocol) is True
    assert dev.options["sceptre"]["firmware_filename"] == "ferrofire.firmware"


@pytest.mark.parametrize("protocol", ["ssh", "telnet"])
def test_identify_prefers_configured_firmware(fake, dev, config, protocol):
    fake.clear()  # The other firmware is listed first
    fake[f"{HOME}/ferrofire-mod.firmware"] = b"mod"
    fake[f"{HOME}/config.xml"] = config
    fake[f"{HOME}/ferrofire.firmware"] = FIRMWARE
    assert SCEPTRE._verify_shell(dev, protocol) is True
    assert dev.options["sceptre"]["firmware_filename"] == "ferrofire.firmware"
    assert SCEPTRE._push(dev, b"new", "firmware") is True
    assert fake[f"{HOME}/ferrofire.firmware"] == b"new"
    assert fake[f"{HOME}/ferrofire-mod.firmware"] == b"mod"


@pytest.mark.parametrize("protocol", ["ssh", "telnet"])
def test_identify_falls_back_to_listed_firmware(fake, dev, protocol):
    fake[f"{HOME}/other.firmware"] = fake.pop(f"{HOME}/ferrofire.firmware")
    assert SCEPTRE._verify_shell(dev, protocol) is True
    assert dev.options["sceptre"]["firmware_filename"] == "other.firmware"


@pytest.mark.parametrize("protocol", ["ssh", "telnet"])
def test_identify_rejects_without_files(fake, dev, protocol):
    fake.clear()
    assert SCEPTRE._verify_shell(dev, protocol) is False


@pytest.mark.usefixtures("fake")
def test_ssh_pull_round_trips(dev, config):
    assert SCEPTRE._pull(dev) is True
    assert dev._cache["sceptre_protocol"] == "ssh"
    assert dev.firmware.original == FIRMWARE
    assert dev.name == "fep-1"  # Config was parsed
    shell = dev._cache["sceptre_ssh_shell"]
    assert shell.read_file("config.xml") == config
    assert shell.read_file("ferrofire.firmware") == FIRMWARE


@pytest.mark.usefixtures("fake")
def test_telnet_pull_round_trips_binary(dev, behavior):
    behavior["sftp_fails"] = True  # ssh doesn't work, so telnet is used
    assert SCEPTRE._pull(dev) is True
    assert dev._cache["sceptre_protocol"] == "telnet"
    assert dev.firmware.original == FIRMWARE


@pytest.mark.usefixtures("fake")
def test_pull_annotates_ferrofire(dev):
    assert SCEPTRE._pull(dev) is True
    assert dev.os.name == "Buildroot"
    assert dev.os.vendor.name == "Buildroot"
    assert dev.os.vendor.id == "Buildroot"
    assert dev.description.model == "ferrofire"


@pytest.mark.parametrize("protocol", ["ssh", "telnet"])
def test_write_file_uses_tmp_then_rename(fake, dev, protocol):
    shell = sceptre_shell.SceptreShell.open(dev, protocol)
    data = os.urandom(5000)
    shell.write_file("config.xml", data)
    assert fake[f"{HOME}/config.xml"] == data
    assert not any(p.endswith(".tmp") for p in fake)


@pytest.mark.usefixtures("fake")
def test_telnet_write_turns_echo_off_then_on(dev):
    shell = sceptre_shell.SceptreShell.open(dev, "telnet")
    shell.write_file("config.xml", b"new")
    sent = shell.conn.comm.commands
    assert sent[0] == "stty -echo"
    assert sent[1].startswith("base64 -d > ")
    assert sent[-1] == "stty echo"
    assert shell.conn.comm.echo


@pytest.mark.parametrize("protocol", ["ssh", "telnet"])
def test_failed_write_leaves_target_unchanged(fake, dev, behavior, config, protocol):
    shell = sceptre_shell.SceptreShell.open(dev, protocol)
    behavior["put_fails" if protocol == "ssh" else "decode_fails"] = True
    with pytest.raises(OSError):
        shell.write_file("config.xml", os.urandom(5000))
    assert fake[f"{HOME}/config.xml"] == config
    assert not any(p.endswith(".tmp") for p in fake)


@pytest.mark.usefixtures("fake")
@pytest.mark.parametrize(("protocol", "flag"), [("ssh", "sftp_fails"), ("telnet", "bad_login")])
def test_open_failure_disconnects(dev, behavior, conns, protocol, flag):
    behavior[flag] = True
    with pytest.raises((OSError, PermissionError, ConnectionError)):
        sceptre_shell.SceptreShell.open(dev, protocol)
    assert len(conns) == 1
    conns[0].disconnect.assert_called_once()


@pytest.mark.parametrize("protocol", ["ssh", "telnet"])
def test_identify_rejects_unsafe_firmware_name(fake, dev, protocol):
    del fake[f"{HOME}/ferrofire.firmware"]
    fake[f"{HOME}/a;touch_x.firmware"] = b"x"
    assert SCEPTRE._verify_shell(dev, protocol) is False


def test_telnet_quotes_paths(fake, dev):
    fake[f"{HOME}/a b;c"] = b"data"
    shell = sceptre_shell.SceptreShell.open(dev, "telnet")
    assert shell.read_file("a b;c") == b"data"
    shell.write_file("x y", b"data")
    sent = shell.conn.comm.commands
    assert f"base64 '{HOME}/a b;c'" in sent
    assert any(f"'{HOME}/x y.tmp'" in c and f"'{HOME}/x y'" in c for c in sent)


@pytest.mark.usefixtures("fake")
def test_second_verified_shell_is_dropped(dev, conns, monkeypatch):
    register = Mock()
    monkeypatch.setattr(sceptre_fcd.exit_handler, "register", register)
    assert SCEPTRE._verify_shell(dev, "ssh") is True
    assert SCEPTRE._verify_shell(dev, "telnet") is True
    assert register.call_count == 1
    ssh_conn, telnet_conn = conns
    ssh_conn.disconnect.assert_not_called()
    telnet_conn.disconnect.assert_called_once()
    # Pulling over telnet-only needs a reopen and drops the ssh session
    dev._cache["sceptre_ssh_verified"] = False
    assert SCEPTRE._use_shell(dev, "telnet") is True
    ssh_conn.disconnect.assert_called_once()
    assert not dev._cache.get("sceptre_ssh_shell")


def test_ftp_pull_still_first(dev, monkeypatch, config):
    """No verified service: FTP is tried first and ssh/telnet are never touched."""

    def download(_cls, _dev, candidates, *_args, **_kwargs):
        if "config.xml" in candidates:
            return config, None, "config.xml"
        if candidates == [FIRMWARE_PREFIX]:
            return FIRMWARE, None, FIRMWARE_PREFIX
        return None, None, ""

    monkeypatch.setattr(SCEPTRE, "_download_ftp", classmethod(download))
    monkeypatch.setattr(
        SCEPTRE, "_verify_shell", Mock(side_effect=AssertionError("shell touched"))
    )
    assert SCEPTRE._pull(dev) is True
    assert dev._cache["sceptre_protocol"] == "ftp"
    assert dev.firmware.original == FIRMWARE
    assert dev.os.name != "Buildroot"


@pytest.fixture(params=["ssh", "telnet"])
def protocol(request, behavior):
    if request.param == "telnet":
        behavior["sftp_fails"] = True  # ssh doesn't work, so telnet is used
    return request.param


@pytest.fixture
def verified(dev, protocol):
    """What a scan leaves behind: the device was verified over ``protocol``."""
    dev._cache[f"sceptre_{protocol}_verified"] = True
    return protocol


@pytest.mark.usefixtures("fake", "verified")
def test_push_writes_temp_then_renames(dev, behavior):
    assert SCEPTRE._push(dev, b"new", "config") is True
    tmp, target = f"{HOME}/config.xml.tmp", f"{HOME}/config.xml"
    assert behavior["ops"] == [f"write {tmp}", f"rename {tmp} {target}"]


@pytest.mark.usefixtures("fake", "verified")
def test_push_firmware_round_trips(dev, protocol):
    data = os.urandom(1024 * 1024)
    assert SCEPTRE._push(dev, data, "firmware") is True
    assert dev._cache[f"sceptre_{protocol}_shell"].read_file("ferrofire.firmware") == data


@pytest.mark.usefixtures("fake", "verified")
def test_push_config(dev, files, protocol):
    new = b"<config/>"
    assert SCEPTRE._push(dev, new, "config") is True
    assert files[f"{HOME}/config.xml"] == new
    assert dev._cache.get(f"sceptre_{protocol}_shell")
    assert files[f"{HOME}/ferrofire.firmware"] == FIRMWARE


def test_push_without_shell_service_fails(fake, dev):
    fake.clear()  # Neither ssh nor telnet identify the device
    assert SCEPTRE._push(dev, b"new", "config") is False


@pytest.mark.usefixtures("fake")
def test_push_ftp_verified_uses_ftp(dev, files, monkeypatch):
    """A device verified over FTP (bennu) keeps the FTP push, even if ssh also works."""
    dev._cache["sceptre_ftp_verified"] = True
    dev._cache["sceptre_ssh_verified"] = True
    shell_push = Mock(side_effect=AssertionError("shell push used"))
    monkeypatch.setattr(SCEPTRE, "_push_shell", shell_push)
    upload = Mock(return_value=True)
    monkeypatch.setattr(SCEPTRE, "_upload_ftp", classmethod(lambda _c, *a: upload(*a)))
    before = dict(files)
    assert SCEPTRE._push(dev, b"firmware", "firmware") is True
    assert upload.call_args.args[1:] == (FIRMWARE_UPLOAD_NAME, b"firmware")
    assert SCEPTRE._push(dev, b"<config/>", "config") is False  # unsupported over FTP
    assert files == before


@pytest.mark.usefixtures("fake", "verified")
@pytest.mark.parametrize(
    ("push_type", "name"), [("config", "config.xml"), ("firmware", "ferrofire.firmware")]
)
def test_push_file_via_module_push(dev, files, protocol, push_type, name, tmp_path):
    f = tmp_path / "upload.bin"
    f.write_bytes(data := os.urandom(3000))
    assert SCEPTRE.push(dev, f, push_type) is True
    assert files[f"{HOME}/{name}"] == data
    assert dev._cache.get(f"sceptre_{protocol}_shell")


@pytest.mark.usefixtures("fake")
def test_push_falls_back_to_other_verified_protocol(dev, behavior, files):
    assert SCEPTRE._verify_shell(dev, "ssh")
    assert SCEPTRE._verify_shell(dev, "telnet")
    dev._cache.pop("sceptre_ssh_shell").close()
    behavior["sftp_fails"] = True  # Reopening ssh now fails
    assert SCEPTRE._push(dev, b"new", "config") is True
    assert files[f"{HOME}/config.xml"] == b"new"
    assert dev._cache.get("sceptre_telnet_shell")


@pytest.mark.usefixtures("fake")
@pytest.mark.parametrize("push_type", ["config", "firmware"])
@pytest.mark.parametrize("empty", [b"", "", "empty_file", "-"])
def test_push_refuses_empty_payload(
    dev, files, behavior, conns, push_type, empty, tmp_path, monkeypatch
):
    if empty == "empty_file":
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
    elif empty == "-":  # empty stdin: the incident path
        monkeypatch.setattr(sys, "stdin", Mock(buffer=Mock(read=Mock(return_value=b""))))
    dev._cache["sceptre_ssh_verified"] = True
    before = dict(files)
    assert SCEPTRE._push(dev, empty, push_type) is False
    assert files == before
    assert behavior["ops"] == []
    assert conns == []  # no session was opened


@pytest.mark.usefixtures("fake")
@pytest.mark.parametrize("missing", [False, True])
def test_push_directory_path_fails(dev, files, behavior, conns, tmp_path, caplog, missing):
    target = tmp_path / "nope" if missing else tmp_path
    dev._cache["sceptre_ssh_verified"] = True
    before = dict(files)
    with caplog.at_level("ERROR"):
        assert SCEPTRE._push(dev, target, "config") is False
    assert "can't read" in caplog.text
    assert files == before
    assert behavior["ops"] == []
    assert conns == []


def test_clean_drops_prompt():
    out = b"ls -1 /home/sceptre\r\nconfig.xml\r\nferrofire.firmware\r\n$ "
    assert sceptre_shell.SceptreShell._clean(out) == ["config.xml", "ferrofire.firmware"]


def test_telnet_write_raises_without_prompt(fake, dev, behavior, config):
    dev._runtime_options.setdefault("telnet", {})["timeout"] = 0.2
    shell = sceptre_shell.SceptreShell.open(dev, "telnet")
    behavior["stall"] = True
    with pytest.raises(TimeoutError):
        shell.write_file("config.xml", b"new")
    assert fake[f"{HOME}/config.xml"] == config


def telnet_device(monkeypatch, data, chunk, delay=0.0, cut=None, size=None, timeout=0.5):
    """
    SceptreShell over PEAT's real telnetlib, on a socketpair to a thread that
    answers ``wc -c`` and ``base64`` for ``data``: ``chunk`` bytes per send,
    ``delay`` between sends, output cut after ``cut`` bytes (socket left open),
    ``size`` reported by wc.
    """
    monkeypatch.setattr(Telnet, "PRE_WRITE_SLEEP", 0)
    monkeypatch.setattr(Telnet, "POST_WRITE_SLEEP", 0)
    ours, theirs = socket.socketpair()

    def serve():
        with theirs, theirs.makefile("rb") as commands:
            for line in commands:
                cmd = line.decode().strip()
                if cmd.startswith("wc "):
                    body = f"{len(data) if size is None else size}\r\n".encode()
                else:
                    enc = b64encode(data)
                    body = b"".join(enc[i : i + 76] + b"\r\n" for i in range(0, len(enc), 76))
                out = (cmd.encode() + b"\r\n" + body + b"$ ")[:cut]
                for i in range(0, len(out), chunk):
                    theirs.sendall(out[i : i + chunk])
                    sleep(delay)

    threading.Thread(target=serve, daemon=True).start()
    conn = Telnet("192.0.2.10", 23, timeout)
    conn.connected = True
    conn.comm.sock = ours
    return sceptre_shell.SceptreShell(conn, "telnet", HOME)


def test_telnet_read_survives_slow_tiny_chunks(monkeypatch):
    """The timeout counts from the last output, not from the start of the transfer."""
    data = os.urandom(3000)
    shell = telnet_device(monkeypatch, data, chunk=7, delay=0.002, timeout=0.5)
    start = monotonic()
    assert shell.read_file("fw") == data
    assert monotonic() - start > 0.5
    shell.close()


def test_telnet_read_raises_when_stream_stalls(monkeypatch):
    data = os.urandom(30000)
    shell = telnet_device(monkeypatch, data, chunk=512, cut=20000, timeout=0.3)
    with pytest.raises(TimeoutError):
        shell.read_file("fw")
    shell.close()


def test_telnet_read_checks_length(monkeypatch):
    data = os.urandom(3000)
    shell = telnet_device(monkeypatch, data, chunk=4096, size=len(data) + 1)
    with pytest.raises(OSError, match="got 3000 of 3001 bytes"):
        shell.read_file("fw")
    shell.close()
