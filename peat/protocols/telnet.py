import traceback
from time import sleep
from typing import Any

import peat
from peat import CommError, log

from . import forked_telnetlib as telnetlib


class Telnet:
    """
    Telnet functionality for interacting with devices.

    Added features:

    - Improved error handling
    - Improved cleanup of connections on exit, even if exceptions happen
    - Logging messages
    - Records all commands and responses and saves to a file
    - Simpler function calls
    """

    # These will vary by device and should be overridden as needed
    ENCODING: str = "utf-8"
    PRE_WRITE_SLEEP: float = 0.15
    POST_WRITE_SLEEP: float = 0.1
    READ_DELAY: float = 0.15
    LINE_TERMINATOR: str = "\r\n"

    def __init__(self, ip: str, port: int = 23, timeout: float = 5.0) -> None:
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout

        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )

        self.connected: bool = False

        self.all_output: list[str] = []
        self.raw_output: list[bytes] = []
        self.info: dict[str, Any] = {}

        self.successful_creds: tuple[str, str] | None = None
        self._comm: telnetlib.Telnet = telnetlib.Telnet()

        self.log.trace2(f"Initialized {repr(self)}")

    def __enter__(self) -> "Telnet":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(f"Unhandled exception while exiting - {exc_type.__name__}: {exc_val}")
            self.log.trace(
                f"Exception traceback\n"
                f"{''.join(traceback.format_tb(exc_tb))}"
                f"{exc_type.__name__}: {exc_val}"
            )

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    @property
    def comm(self) -> telnetlib.Telnet:
        """
        Python Telnet instance used for interacting with the device.
        """
        if not self.connected:
            try:
                self._comm.open(self.ip, self.port, self.timeout)
                self.connected = True
                self.log.info(f"Connected to {self.ip}:{self.port}")
            except Exception as ex:
                raise CommError(f"Failed to connect to {self.ip}:{self.port}: {ex}") from ex

        return self._comm

    @comm.setter
    def comm(self, obj: telnetlib.Telnet) -> None:
        self._comm = obj

    def test_connection(self) -> bool:
        """
        Test connection to the device.
        """
        try:
            if self.comm:
                return True
            return False
        except CommError:
            return False

    def disconnect(self) -> None:
        """
        Cleanly disconnect from the device.
        """
        if self.connected and self._comm:
            self._comm.close()
            self.connected = False
            self.log.debug(f"Disconnected from {self.ip}")

            if self.all_output:
                # Save the raw output to disk as an artifact
                try:
                    dev = peat.data.datastore.get(self.ip)
                    dev.write_file(self.all_output, "raw-telnet-output.json", merge_existing=True)
                except Exception as ex:
                    self.log.warning(f"Failed to write raw output to file: {ex}")

    def write(self, command: bytes | str | int, flush: bool = False) -> None:
        """
        Send a Telnet command to the device.

        Args:
            command: Command to send (this will be automatically encoded)
            flush: If the responses to the command should be dropped
        """
        self.log.debug(f"Writing command: {command}")

        # If it's an int, first convert to a string, which will then be encoded
        if isinstance(command, int):
            command = str(command)

        # If it's a string, encode to bytes with the device's encoding
        if isinstance(command, str):
            command = command.encode(self.ENCODING)

        # Append the line terminator (encode here to ensure proper encoding)
        command += self.LINE_TERMINATOR.encode(self.ENCODING)

        # NOTE(cegoes): If we don't sleep, things get REALLY wonky.
        # Wasted an hour figuring out why the exact same telnet commands
        # worked in the REPL, but not the script...well, it was the pauses
        # between sending and reading commands. JustTelnetThings.
        sleep(self.PRE_WRITE_SLEEP)
        self.comm.write(command)
        sleep(self.POST_WRITE_SLEEP)

        if flush:
            self.comm.read_very_eager()

    def login(self, user: str, passwd: str) -> dict | None:
        """
        Login to the telnet device.
        """
        pass

    def read(self, delay: float | None = None, strip_whitespace: bool = True) -> str:
        """
        Read all data currently in the telnet response buffer.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        ``all_output`` class attribute for future access.

        Args:
            delay: Seconds to sleep before querying for data
            strip_whitespace: If ``str.strip()`` should be called on the results

        Returns:
            Decoded data read from the Telnet receive stream
        """
        if delay is None:
            delay = self.READ_DELAY

        sleep(delay)

        return self._add_data(self.comm.read_very_eager(), strip_whitespace)

    def read_until(
        self,
        until: bytes | str,
        delay: float = 0.15,
        timeout: float | None = None,
        strip_whitespace: bool = True,
    ) -> str:
        """
        Read the telnet response buffer until the specified string is reached.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        all_output class attribute for future access.

        Args:
            until: String to read all data up to
            delay: Seconds to sleep before querying for data
            timeout: Seconds to wait for the string before timing out
            (if None, this defaults to the Telnet class's timeout configuration)
            strip_whitespace: If ``strip()`` should be called on the results

        Returns:
            Decoded data read from the telnet receive stream
        """
        if isinstance(until, str):
            until = until.encode(self.ENCODING)

        if timeout is None:
            timeout = self.timeout

        sleep(delay)

        return self._add_data(self.comm.read_until(until, timeout), strip_whitespace)

    def _add_data(self, raw_data: bytes, strip_whitespace: bool = True) -> str:
        """
        Decodes and saves responses from device.
        """
        self.raw_output.append(raw_data)

        data = raw_data.decode(self.ENCODING)
        self.all_output.append(data)

        if "Goodbye" in data:
            self.log.debug("Device said goodbye")
            self.disconnect()

        if strip_whitespace:
            data = data.strip()

        return data


__all__ = ["Telnet"]
