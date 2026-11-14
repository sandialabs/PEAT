"""
Shell access (SSH with SFTP, or telnet) to SCEPTRE devices that don't run FTP,
such as the Buildroot-based ferrofire RTU image.

Authors

- Ryan Adams
"""

import re
import shlex
from base64 import b64decode, b64encode
from io import BytesIO
from posixpath import join as pjoin
from time import monotonic, sleep
from typing import Literal

from peat import DeviceData
from peat.protocols import SSH, Telnet

PROMPT = re.compile(rb"\$ $")
PROMPT_END = b"\n$ "  # The prompt ending a command's output
LOGIN_FAILED = re.compile(rb"incorrect|denied|failed", re.IGNORECASE)
B64_LINE_LEN = 76
OK = "SCEPTRE_WRITE_OK"
FAIL = "SCEPTRE_WRITE_FAIL"
HEREDOC_CHUNK = 4096
# ponytail: assumed device decode rate for the silent wait after a push;
# raise it if pushes to slow devices time out
DECODE_BYTES_PER_SEC = 1_000_000


class SceptreShell:
    """
    Minimal file access to the SCEPTRE user's home directory over SSH or telnet.

    Paths are relative to ``dev.options["sceptre"]["home"]``.
    """

    def __init__(self, conn: SSH | Telnet, protocol: str, home: str) -> None:
        self.conn = conn
        self.protocol = protocol
        self.home = home

    @classmethod
    def open(cls, dev: DeviceData, protocol: Literal["ssh", "telnet"]) -> "SceptreShell":
        """
        Connect and log in. Raises an exception on failure.
        """
        opts = dev.options[protocol]
        home = dev.options["sceptre"]["home"]
        user = opts.get("user") or "sceptre"
        passwd = opts.get("pass") or "sceptre"

        if protocol == "ssh":
            conn = SSH(dev.ip, opts["port"], opts["timeout"], username=user, password=passwd)
        elif protocol == "telnet":
            conn = Telnet(dev.ip, opts["port"], opts["timeout"])
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

        try:
            if protocol == "ssh":
                _ = conn.comm  # Connects, raises on auth failure
                conn.open_sftp()
                if conn.sftp_conn is None:
                    raise ConnectionError("Failed to open SFTP session")
            else:
                conn.read_until("login: ")
                conn.write(user)
                conn.read_until("Password: ")
                conn.write(passwd)
                idx, _match, _data = conn.comm.expect([PROMPT, LOGIN_FAILED], conn.timeout)
                if idx != 0:
                    raise PermissionError(f"Telnet login failed for user '{user}'")
        except BaseException:
            conn.disconnect()
            raise

        dev.related.user.add(user)
        return cls(conn, protocol, home)

    @staticmethod
    def _clean(data: bytes) -> list[str]:
        """
        Output lines without the echoed command, PS2 lines and the trailing
        prompt (the first two contain spaces; the output we care about doesn't).
        """
        text = data.decode("utf-8", errors="replace").replace("\r", "").removesuffix("$ ")
        lines = [ln.strip() for ln in text.split("\n")]
        return [ln for ln in lines if ln and " " not in ln]

    def _read_prompt(self, timeout: float) -> bytes:
        """
        Read telnet output up to the shell prompt that ends it, in time linear
        in its size: telnetlib's expect() rescans its whole buffer, and
        read_until() recopies it, on every 50-byte recv. ``timeout`` counts
        from the last output, so large transfers finish; a stalled one raises
        ``TimeoutError`` rather than returning truncated output.
        """
        comm = self.conn.comm
        out = bytearray()
        deadline = monotonic() + timeout
        # With echo off, a command without output returns just the prompt
        while not (b"\n" + out[-3:]).endswith(PROMPT_END):
            data = comm.read_eager()  # Small reads keep telnetlib's own buffer small
            if data:
                out += data
                deadline = monotonic() + timeout
            elif monotonic() > deadline:
                raise TimeoutError(
                    f"No shell prompt from {self.conn.ip} within {timeout:g}s of its last output"
                )
            else:
                sleep(0.005)
        return bytes(out)

    def _run(self, command: str) -> list[str]:
        """
        Run a command in the telnet shell, return output lines without the echo.
        """
        self.conn.write(command)
        return self._clean(self._read_prompt(self.conn.timeout))

    def list_home(self) -> list[str]:
        if self.protocol == "ssh":
            return self.conn.sftp_conn.listdir(self.home)
        # A pipe, not the tty: BusyBox ls colors names on a tty
        return self._run(f"ls -1 {shlex.quote(self.home)} | cat")

    def read_file(self, name: str) -> bytes:
        path = pjoin(self.home, name)
        if self.protocol == "ssh":
            buf = BytesIO()
            self.conn.sftp_conn.getfo(path, buf)
            return buf.getvalue()
        q_path = shlex.quote(path)
        size = self._run(f"wc -c < {q_path}")
        if len(size) != 1 or not size[0].isdigit():
            raise OSError(f"Failed to read {path}: no size from wc ({size})")
        data = b64decode("".join(self._run(f"base64 {q_path}")))
        if len(data) != int(size[0]):
            raise OSError(f"Failed to read {path}: got {len(data)} of {size[0]} bytes")
        return data

    def write_file(self, name: str, data: bytes) -> None:
        """
        Write to ``<name>.tmp`` then rename over ``<name>``, so a failed
        transfer never leaves a truncated file in place. Raises ``OSError``
        on failure, leaving ``<name>`` unchanged.
        """
        path = pjoin(self.home, name)
        tmp = f"{path}.tmp"
        if self.protocol == "ssh":
            sftp = self.conn.sftp_conn
            try:
                sftp.putfo(BytesIO(data), tmp)
                sftp.posix_rename(tmp, path)
            except Exception as ex:
                try:
                    sftp.remove(tmp)
                except Exception:
                    pass
                raise OSError(f"Failed to write {path}: {ex}") from ex
            return

        q_path, q_tmp = shlex.quote(path), shlex.quote(tmp)
        encoded = b64encode(data).decode()
        lines = [encoded[i : i + B64_LINE_LEN] for i in range(0, len(encoded), B64_LINE_LEN)]
        # Echo off: the heredoc echo comes back as fast as it's sent, and the
        # device stops reading (sendall times out) when it isn't drained in time
        self._run("stty -echo")
        # The shell runs the whole chain once the heredoc is terminated
        self.conn.comm.write(
            f"base64 -d > {q_tmp} <<'EOF' && mv {q_tmp} {q_path} && echo {OK}"
            f" || {{ rm -f {q_tmp}; echo {FAIL}; }}\n".encode()
        )
        for i in range(0, len(lines), HEREDOC_CHUNK // B64_LINE_LEN):
            chunk = lines[i : i + HEREDOC_CHUNK // B64_LINE_LEN]
            self.conn.comm.write(("\n".join(chunk) + "\n").encode())
            self.conn.comm.read_very_eager()  # Drain PS2 prompts so buffers don't fill
        self.conn.comm.write(b"EOF\n")
        # PS2 prompts for the line backlog keep arriving, then the device decodes in silence
        out = self._read_prompt(self.conn.timeout + len(data) / DECODE_BYTES_PER_SEC)
        self._run("stty echo")
        # PS2 "> " prompts can precede the marker on its line; the echoed command
        # line contains the marker but doesn't end with it.
        lines = out.decode("utf-8", errors="replace").replace("\r", "").split("\n")
        if not any(ln.strip().split(" ")[-1] == OK for ln in lines):
            raise OSError(f"Failed to write {path}")

    def close(self) -> None:
        self.conn.disconnect()
