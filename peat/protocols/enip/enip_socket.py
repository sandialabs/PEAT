from __future__ import annotations

import io
import socket
import struct
from pathlib import Path

from peat import config, exit_handler, log, state, utils

from .enip_const import HEADER_SIZE, EnipCommError


class EnipSocket:
    """
    Ethernet/IP (ENIP) socket.

    Authors

    - Christopher Goes
    """

    def __init__(self, ip: str, port: int, timeout: float = 5.0) -> None:
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )

        self.is_connected: bool = False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        self.fmt_log_fp: io.FileIO | None = None
        self.raw_log_fp: io.FileIO | None = None

        self.fmt_log_path: Path | None = None
        self.raw_log_path: Path | None = None

        self.log_to_file: bool = False

        if config.DEBUG >= 2 and config.LOG_DIR:
            self.log_to_file = True
            d_ip = self.ip.replace(".", "-")
            self.fmt_log_path = config.LOG_DIR / "enip" / f"{d_ip}_enip-data-formatted.log"
            self.raw_log_path = config.LOG_DIR / "enip" / f"{d_ip}_enip-data-raw.csv"

        self.log.trace(f"Initialized {repr(self)}")

    def __enter__(self) -> EnipSocket:
        if not self.connect():
            raise EnipCommError(f"failed to connect to {str(self)}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
        if exc_type:
            self.log.debug(f"{exc_type.__name__}: {exc_val}")

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    def connect(self) -> bool:
        """
        Connect to ENIP socket.

        Returns:
            If connection was successful

        Raises:
            EnipCommError: if the socket timed out during connection
        """
        try:
            self.sock.connect((self.ip, self.port))
        except TimeoutError:
            self.log.debug(f"Socket timed out during connect (timeout: {self.timeout} seconds)")
            raise EnipCommError(f"socket timeout during connection to {str(self)}") from None

        self.is_connected = True
        return self.is_connected

    def close(self) -> None:
        """
        Close the Python socket and log files (if debugging).
        """
        if self.is_connected:
            self.is_connected = False
            try:
                self.sock.close()
            except Exception:
                pass

        self._close_log_files()

    def send(self, message: bytes) -> int:
        """
        Send a ENIP message.

        Returns:
            Number of bytes sent

        Raises:
            EnipCommError: Exception occured while sending the message
        """
        if self.log_to_file:
            self._log_protocol_msg(message, "SEND")

        total_sent = 0

        while total_sent < len(message):
            try:
                sent = self.sock.send(message[total_sent:])
                if not sent:
                    raise EnipCommError(f"socket connection broken during send to {str(self)}")
                total_sent += sent
            except TimeoutError:
                self.log.warning(f"Socket timed out during send (timeout: {self.timeout} seconds)")
                raise EnipCommError(f"socket timeout during send to {str(self)}") from None
            except OSError:
                raise EnipCommError(
                    f"socket connection broken during send to {str(self)}"
                ) from None

        return total_sent

    def receive(self) -> bytes:
        """
        Receive and unpack an ENIP response.

        Returns:
            The ENIP response as bytes

        Raises:
            EnipCommError: Exception occured while recieving the response
        """
        msg_len = 28
        chunks = []
        bytes_received = 0
        one_shot = True

        while bytes_received < msg_len:
            try:
                chunk = self.sock.recv(min(msg_len - bytes_received, 2048))
                if not chunk:
                    raise EnipCommError(
                        f"socket connection broken during receive from {str(self)}"
                    )
                if one_shot:
                    data_size = int(struct.unpack("<H", chunk[2:4])[0])
                    msg_len = HEADER_SIZE + data_size
                    one_shot = False
                chunks.append(chunk)
                bytes_received += len(chunk)
            except TimeoutError:
                self.log.warning(
                    f"Socket timed out during receive (timeout: {self.timeout} seconds)"
                )
                raise EnipCommError(f"socket timeout during receive from {str(self)}") from None
            except OSError:
                raise EnipCommError(
                    f"socket connection broken during receive from {str(self)}"
                ) from None

        message = b"".join(chunks)
        if self.log_to_file:
            self._log_protocol_msg(message, "RECEIVE")

        return message

    def _close_log_files(self) -> None:
        if self.fmt_log_fp:
            self.fmt_log_fp.close()
            self.fmt_log_fp = None
        if self.raw_log_fp:
            self.raw_log_fp.close()
            self.raw_log_fp = None

    def _log_protocol_msg(self, msg: bytes, direction: str) -> None:
        """
        Logs protocol messages to two files: formatted bytes and raw bytes.
        """
        if not self.log_to_file:  # Skip if file output is disabled
            return

        if not self.fmt_log_fp:
            # Create directory and open files on first write
            # We don't do this in __init__ in case no sends/receives occur
            if not self.fmt_log_path.parent.exists():
                self.fmt_log_path.parent.mkdir(parents=True, exist_ok=True)

            state.written_files.add(self.fmt_log_path.as_posix())
            state.written_files.add(self.raw_log_path.as_posix())

            add_csv_header = False
            if not self.raw_log_path.exists():
                add_csv_header = True

            self.fmt_log_fp = self.fmt_log_path.open("w")
            self.raw_log_fp = self.raw_log_path.open("w")

            # Close files when peat exits
            exit_handler.register(self._close_log_files, "FILE")

            if add_csv_header:
                self.raw_log_fp.write("TIMESTAMP,IP,PORT,DIRECTION,BYTES\n")

        ts = utils.utc_now()
        # write raw bytes in a comma-separated format to a single line
        raw = f"{ts.isoformat()},{self.ip},{self.port},{direction},{msg.hex()}\n"
        self.raw_log_fp.write(raw)

        # format bytes in a hexdump format
        header = f"        {'-' * 16} {ts.strftime('%H:%M:%S.%f')} {'-' * 15}\n"
        if direction == "SEND":
            header += "        --------------------- SEND ---------------------"
        else:
            header += "        -------------------- RECEIVE -------------------"

        fmt = f"{self._format_bytes_msg(msg, header)}\n\n\n"
        self.fmt_log_fp.write(fmt)

    @staticmethod
    def _format_bytes_msg(message: bytes, info: str = "") -> str:
        out = info
        line = 0

        for idx, ch in enumerate(message):
            if idx % 8 == 0:
                out += " "
            if idx % 16 == 0:
                out += f"\n0x{line * 0x10:0>4x}  "
                line += 1
            out += f"{ch:0>2x} "

        return out


__all__ = ["EnipSocket"]
