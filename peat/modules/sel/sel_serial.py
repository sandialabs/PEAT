import shutil
import subprocess
import tempfile
from functools import cached_property
from pathlib import Path
from time import sleep

import serial  # PySerial

from peat import CommError, config, exit_handler
from peat.protocols.serial import pretty_hex_bytes

from .sel_ascii import SELAscii


class SELSerial(SELAscii):
    """
    Serial functionality for SEL relays over a RS-232 serial link.

    This is a transport implementation of :class:`~peat.modules.sel.sel_ascii.SELAscii`.
    Refer to :class:`~peat.modules.sel.sel_ascii.SELAscii` for functions/commands to run.

    The class can be used either for one-off pulls or establishing a
    longer-lived connection for continual polling/monitoring.

    YMODEM is required for relays that don't have the "file show" command.
    PySerial doesn't support YMODEM, and the Python ``modem`` package hasn't been
    updated in over 11 years, so we're forced to subprocess and call the rz/sz
    commands from the ``lrzsz`` project. This is not available on Windows, but
    is available on Linux (``sudo apt install lrzsz``) and
    MacOS (``sudo brew install lrzsz``).

    - ``show`` supported: 700G, 351S, 351
    - ``read``: 451, 2032 (Requires Ymodem to transfer the file)
    """

    PRE_WRITE_SLEEP = 1.0
    # minor hack to cache results of the "file show" check between instances
    _SUPPORTS_SHOW_CACHE = {}  # type: dict[str, bool]

    def __init__(
        self,
        serial_port: str,
        baudrate: int = 9600,
        timeout: float | int = 5.0,
        force_ymodem: bool = False,
    ):
        super().__init__(address=serial_port, timeout=timeout)

        self.baud = baudrate  # type: int
        self._comm = None  # type: Optional[serial.Serial]

        # use ymodem for file transfers
        self.force_ymodem = force_ymodem  # type: bool
        self._supports_show = None  # type: Optional[bool]

        if self.force_ymodem:
            self._supports_show = False
        elif SELSerial._SUPPORTS_SHOW_CACHE.get(self.address) is not None:
            self._supports_show = SELSerial._SUPPORTS_SHOW_CACHE[self.address]

        # Ensure serial connection is properly cleaned up and not left
        # in a weird state when PEAT terminates, even if the user kills
        # it using CTRL+C.
        exit_handler.register(self.disconnect, "CONNECTION")

        self.log.trace(f"Initialized {repr(self)}")

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.address}, "
            f"{self.baud}, {self.timeout}, {self.force_ymodem})"
        )

    @property
    def comm(self) -> serial.Serial:
        if not self._comm:
            try:
                relay = serial.Serial(
                    port=self.address,
                    baudrate=self.baud,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    bytesize=serial.EIGHTBITS,
                    timeout=self.timeout,
                    write_timeout=self.timeout,
                )
                relay.isOpen()
                self._comm = relay
            except serial.SerialException as ex:
                raise ex
            except Exception as ex:
                raise CommError(
                    f"Error connecting to SEL relay serial "
                    f"port {self.address}: {ex}"
                ) from ex

        return self._comm

    @comm.setter
    def comm(self, obj: serial.Serial):
        self._comm = obj

    @property
    def supports_show(self) -> bool:
        """
        If the device supports the ``file show`` command. This allows transfer
        of files without requiring the use of YMODEM.
        """
        if self._supports_show is None:
            self.write("file show")
            response = self.read().lower()

            if "invalid parameter" in response:
                self.log.warning(
                    "Device doesn't support 'file show' command, falling back "
                    "to using 'file read' and YMODEM for file transfers"
                )
                self._supports_show = False
            else:
                self.log.debug("Device supports 'file show' command")
                self._supports_show = True

            SELSerial._SUPPORTS_SHOW_CACHE[self.address] = self._supports_show

        return self._supports_show

    @cached_property
    def sz_path(self) -> str:
        """
        Absolute file path to the ``sz`` executable.

        References

        - https://manpages.debian.org/testing/lrzsz/sz.1.en.html
        - https://www.ohse.de/uwe/software/lrzsz.html
        """
        sz_path = shutil.which("sz")
        if sz_path is None:
            raise CommError(
                "Could not find path to 'sz' command, which is required "
                "for YMODEM serial file uploads to SEL devices. Have "
                "you apt-installed 'lrzsz'?"
            )
        return sz_path

    @cached_property
    def rz_path(self) -> str:
        """
        Absolute file path to the ``rz`` executable.

        References

        - https://manpages.debian.org/testing/lrzsz/rz.1.en.html
        - https://www.ohse.de/uwe/software/lrzsz.html
        """
        rz_path = shutil.which("rz")
        if rz_path is None:
            raise CommError(
                "Could not find path to 'rz' command, which is required "
                "for YMODEM serial file downloads from SEL devices. Have "
                "you apt-installed 'lrzsz'?"
            )
        return rz_path

    def test_connection(self) -> bool:
        try:
            return self.comm.isOpen()
        except CommError as ex:
            self.log.warning(f"Serial connection failed: {ex}")
            return False

    def disconnect(self) -> None:
        if self._comm:
            # If running with elevated privs, then de-escalate them before exiting
            if self.priv_level > 0:
                self.write("quit")
                self.read()
            self._comm.close()
            self._comm = None
            self.log.info("Disconnected")

    def _process_read(self, raw: bytes, strip_whitespace: bool = True) -> str:
        self.raw_output.append(raw)

        if config.DEBUG:
            log_msg = f"Read {len(raw)} bytes"
            if config.DEBUG >= 2:
                log_msg += f"\n-- ASCII --\n{raw.decode('ascii')}"
            if config.DEBUG >= 3:
                log_msg += f"\n-- Hex bytes --\n{pretty_hex_bytes(raw)}"
            self.log.debug(log_msg)

        try:
            decoded = raw.decode(self.ENCODING)
        except UnicodeDecodeError as ex:
            self.log.warning(
                f"Bad data (failed decode using '{self.ENCODING}' encoding): {raw}"
            )
            raise ex

        self.all_output.append(decoded)

        if strip_whitespace:
            decoded = decoded.strip()

        # See docstring in _set_level_from_prompt() below
        if self.priv_level == 0:
            self._set_level_from_prompt(decoded)

        return decoded

    def read(
        self,
        delay: float | None = None,
        strip_whitespace: bool = True,
    ) -> str:
        if delay is None:
            delay = self.READ_DELAY
        sleep(delay)

        raw = self.comm.read_all()

        if raw is None:
            raise CommError("None-type returned from pyserial read_all()")

        return self._process_read(raw, strip_whitespace)

    def read_until(
        self,
        until: bytes | str,
        strip_whitespace: bool = True,
    ) -> str:
        if isinstance(until, str):
            until = until.encode(self.ENCODING)

        raw = self.comm.read_until(terminator=until)

        # clear lingering output in the buffer, since we already have it
        self.comm.reset_input_buffer()

        return self._process_read(raw, strip_whitespace)

    def _set_level_from_prompt(self, raw_line: str) -> bool:
        """
        Set privilege level from the current prompt.

        If you disconnect from a serial connection without running ``quit``,
        the privilege level is preserved when you reconnect! This means if PEAT
        exits uncleanly, then reconnects later, the access level may be weird.

        When connected via serial, the privilege levels are in the prompt.
        Therefore, we check the prompt and set the current access level based
        on the characters at the start of the prompt.

        '='    : level 0 (no priv, can do a few basic commands)
        '=>'   : level 1 (acc)
        '=>>'  : level 2 (2ac)
        '==>>' : level 3 (cal)

        Returns:
            True if the privilege level was set,
            False if it wasn't set.
        """
        stripped = raw_line.replace("\u0003", "")
        prompt_to_level = {
            "=>": 1,
            "=>>": 2,
            "==>>": 3,
        }

        for prompt, level in prompt_to_level.items():
            if stripped.endswith(prompt):
                self.priv_level = level
                return True

        return False

    def write(self, command: bytes | str | int) -> None:
        self.comm.reset_input_buffer()
        self.log.trace2(f"Writing: {command}")
        super().write(command)

    def ymodem_read_file(self, file_id: str) -> bytes | None:
        """
        Read a file from the relay over YMODEM.

        .. warning::
           Requires the ``rz`` command from the ``lrzsz`` library.

        Thus uses the ``file read <filename>`` command on the relay,
        and ``rz`` program from the ``lrzsz`` package on the client.

        Args:
            file_id: file to read. This can be a filename, e.g. "CFG.TXT",
                or a path to a file, e.g. "SETTINGS SET_A1.TXT"
                or "SETTINGS/SET_A1.TXT". Basically, anything that's
                accepted by the ``file read`` command on the relay.
        """
        if "/" in file_id:
            filename = file_id.rsplit("/", maxsplit=1)[-1]
        elif " " in file_id:
            filename = file_id.rsplit(" ", maxsplit=1)[-1]
        else:
            filename = file_id

        self.log.debug(f"Reading file {filename} via YMODEM")

        self._ensure_priv("ymodem_read_file", level=1)

        # rz must write files to a directory. However, all of the other
        # SEL functions work with data in memory. Therefore, we use a
        # temporary directory to store the file, read it's contents,
        # then delete the file and directory. If config.TEMP_DIR is set,
        # then use it. Otherwise, in cases where TEMP_DIR is not set
        # (e.g. if PEAT was not initialized), fallback to mkdtemp().
        remove_temp = False
        if config.OUT_DIR and config.TEMP_DIR:
            out_dir = config.TEMP_DIR
        else:
            out_dir = Path(tempfile.mkdtemp())
            remove_temp = True

        if not out_dir.exists():
            out_dir.mkdir(exist_ok=True, parents=True)

        self.comm.reset_output_buffer()
        self.comm.reset_input_buffer()

        self.write(f"fil read {file_id}")

        sleep(0.5)  # this is needed since sometimes it takes a bit to start

        # If response to command has error, then exit early, don't pull file
        # e.g. if file doesn't exist or command is malformed
        resp = self.read()
        if "ready to send" not in resp.lower():
            self.log.error(
                f"Failed to read '{file_id}' via YMODEM: bad response from "
                f"'file read' relay command: '{resp}'"
            )
            return None

        # shell out to rz command for YMODEM file retrieval
        cmd = f"{self.rz_path} --ymodem --quiet > {self.address} < {self.address}"
        self.log.debug(f"Starting 'rz' subprocess: {cmd}")
        proc = subprocess.run(
            cmd, shell=True, cwd=out_dir, stderr=subprocess.PIPE, check=False
        )
        self.log.debug("Finished executing 'rz'")

        # rz writes files lowercase
        lower_path = out_dir / filename.lower()
        data = b""
        file_pulled = False
        if lower_path.exists():
            self.log.debug(f"Reading data from {lower_path}")
            data = lower_path.read_bytes()  # read raw data from file
            lower_path.unlink()  # delete the file
            file_pulled = True

        if remove_temp:
            shutil.rmtree(out_dir, ignore_errors=True)

        self.comm.reset_output_buffer()
        self.comm.reset_input_buffer()

        if proc.returncode != 0:
            self.log.error(
                f"rz failed to transfer '{file_id}'\n**stderr**\n{proc.stderr}"
            )
            return None
        elif not file_pulled:
            self.log.error(
                f"No file transferred with rz, but process exited "
                f"successfully for '{file_id}'"
            )
            return None

        # Remove a stream of 1A bytes at end of file
        data = data.rstrip(b"\x1a")

        return data

    def ymodem_push_configs(self, config_files: list[str], configs_dir: Path) -> bool:
        """
        Upload (push) configuration files to the device over serial.

        .. warning::
           Requires the ``sz`` command from the ``lrzsz`` library.

        Args:
            config_files: Names of configuration files to upload
            configs_dir: Directory with configuration files to upload

        Returns:
            If the push was successful

        Raises:
            CommError: ``sz`` command not found
            CalledProcessError: ``sz`` command execution failed
        """
        # TODO: split into functions for uploading individual files

        if not configs_dir.is_dir():
            self.log.error(
                f"Configs directory doesn't exist for serial upload "
                f"(directory: {configs_dir})"
            )
            return False

        self._ensure_priv("ymodem_push_configs", level=2)
        sleep(0.2)

        self.comm.reset_input_buffer()
        sleep(0.2)

        for conf_file in config_files:
            self.comm.reset_input_buffer()
            sleep(1.5)

            self.comm.reset_output_buffer()
            sleep(1.5)

            self.log.debug(f"Transferring config {conf_file}")
            self.write(f"file write {conf_file}")
            sleep(1.5)

            proc = subprocess.run(
                f"{self.sz_path} --ymodem -vv -b {conf_file} > {self.address} < {self.address}",
                shell=True,
                cwd=configs_dir,
                check=True,
            )
            if proc.returncode != 0:
                self.log.error(f"sz failed to push config {conf_file}")
                return False

            # TODO: why do we call sz twice?
            subprocess.run(
                f"{self.sz_path} --ymodem -vv -b {conf_file} > {self.address} < {self.address}",
                shell=True,
                cwd=configs_dir,
                check=True,
            )
            sleep(2.5)

        if not self.restart_device():
            return False

        self.disconnect()

        self.log.info("Completed relay serial upload")

        return True

    # TODO: rename from "download_binary"
    def download_binary(
        self, filename: str, save_to_file: bool = True  # noqa: ARG002
    ) -> str | bytes | None:
        # TODO: change "filename" arg to "file_id", fix "SETTINGS SET_P1.TXT" being a thing here
        self.log.info(f"Reading file: {filename}")

        # Push buffer and cache current priv level
        self.write("")
        self.read()

        self._ensure_priv("download_binary", level=1)
        self.read()  # Flush any output from previous operations

        if self.force_ymodem or not self.supports_show:
            data = self.ymodem_read_file(filename)
            if data is None:
                return None
        else:
            # "show" supported: 700G, 351S, 351,
            # "read": 451, 2032 (Requires Ymodem to transfer the file?)
            self.write(f"fil show {filename}")

            # TODO: handle errors (ALSO DO THIS FOR TELNET)
            # - "303 Transfer Rejected - Cannot access file"

            sleep(self.READ_DELAY)  # Give tn time to load file

            raw_file = ""
            # ensure command and 0x02 character doesn't appear in chunk
            first_parts = self.read(strip_whitespace=False).splitlines()

            if not first_parts:
                self.log.error(f"No data for file {filename} from {self.address}")
                return None

            index = 0
            while "fil show" in first_parts[index] or (
                "=>" in first_parts[index] and index < len(first_parts)
            ):
                index += 1

            chunk = "\r\n".join(first_parts[index:])
            raw_file += chunk
            while chunk and "\x03" not in chunk:
                chunk = self.read(strip_whitespace=False)
                raw_file += chunk

            # 0x02: START OF TEXT
            # 0x03: END OF TEXT
            match = self.DATA_REGEX.search(raw_file)

            if not match:
                self.log.error(
                    f"Failed to match the data section read of file "
                    f"'{filename}' from {self.address} via Serial. It may"
                    f"be a text file or something we haven't seen yet. "
                    f"Returning the raw data."
                )
                return raw_file

            data = match.groups()[0]

            if data:
                data = data.replace("\x02", "").replace("\x03", "")

        self.log.info(f"Finished reading file '{filename}' from {self.address}")

        return data


__all__ = ["SELSerial"]
