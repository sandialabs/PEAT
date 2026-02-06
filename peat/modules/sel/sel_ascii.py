import json
import re
import traceback
from abc import ABC, abstractmethod
from datetime import datetime
from time import sleep

from dateutil.parser import parse as date_parse

from peat import DeviceError, config, consts, exit_handler, log, state, utils
from peat.protocols import Telnet
from peat.protocols.common import MAC_RE_DASH

from .relay_parse import parse_status_output


class SELAscii(ABC):
    """
    Commands and parsers for the SEL ASCII command interface.
    """

    DATA_REGEX = re.compile(r"\x02([^\x03]*)\x03", re.ASCII)
    ENCODING = "ascii"
    PRE_WRITE_SLEEP = 0.15
    POST_WRITE_SLEEP = 0.1
    READ_DELAY = 0.15
    LINE_TERMINATOR = "\r\n"
    DEFAULT_CREDS = {
        "acc": "OTTER",  # Access level 1
        "bac": "EDITH",  # Access level B
        "2ac": "TAIL",  # Access level 2
        "cal": "CLARKE",  # Access level C
    }

    def __init__(self, address: str, timeout: int | float = 5.0) -> None:
        self.address: str = address
        self.timeout: int | float = timeout

        self.log = log.bind(classname=self.__class__.__name__, target=self.address)

        self.all_writes: list[bytes] = []
        self.all_output: list[str] = []
        self.raw_output: list[bytes] = []
        self.successful_usernames: set[str] = set()
        self.priv_level: int = 0

        # A hint about what the model is. This is helpful
        # for devices where we're pretty confident in the
        # commands available.
        self.model: str = ""

        # friendly name of the communication method, either Telnet or Serial
        self.type = self.__class__.__name__.partition("SEL")[2].capitalize()

        if config.LOG_DIR and config.OUT_DIR:
            # Ensure data gets saved when PEAT exits if it doesn't exit with context
            exit_handler.register(self._save_state_to_file, "FILE")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if config.LOG_DIR and config.OUT_DIR:
            try:
                self._save_state_to_file()
            except Exception:
                self.log.exception("file save failed")
            exit_handler.unregister(self._save_state_to_file, "FILE")

        self.disconnect()
        exit_handler.unregister(self.disconnect, "CONNECTION")

        if exc_type:
            self.log.debug(f"Unhandled exception while exiting - {exc_type.__name__}: {exc_val}")
            self.log.trace(
                f"Exception traceback\n"
                f"{''.join(traceback.format_tb(exc_tb))}"
                f"{exc_type.__name__}: {exc_val}"
            )

    def __str__(self) -> str:
        return self.address

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(address={self.address}, timeout={self.timeout})"

    def _save_state_to_file(self) -> bool:
        """
        Save all data sent/received to a file in ``peat_results/<run-dir>/logs/``.
        """
        data = {
            "class": self.__class__.__name__,
            "address": self.address,
            "timeout": self.timeout,
            "successful_usernames": sorted(self.successful_usernames),
            "final_privilege_level": self.priv_level,
            "all_writes": self.all_writes,
            "all_output": self.all_output,
            "raw_output": self.raw_output,
        }

        if hasattr(self, "baud"):
            data["baudrate"] = getattr(self, "baud", 0)

        # "/dev/ttyUSB0" => "ttyUSB0"
        basename = f"selascii-protocol-data_{self.address.split('/')[-1]}"
        if data.get("baudrate") is not None:
            basename += f"_{data['baudrate']}"
        f_path = config.LOG_DIR / consts.sanitize_filename(f"{basename}.json")

        # If file already exists, read JSON, append current object as a dict
        # to the list of dicts in the file, then overwrite the file.
        #
        # This can happen if multiple SELASCII instances are created
        # and destroyed for the same port, e.g. during scanning.
        if f_path.exists():
            raw_file = f_path.read_text(encoding="utf-8")  # type: str
            file_data = json.loads(raw_file)  # type: list[dict]
            file_data.append(data)
            return utils.write_file(file_data, f_path, overwrite_existing=True)
        else:
            # Write a new file with a list with a single dict
            return utils.write_file([data], f_path)

    @property
    @abstractmethod
    def comm(self):
        """
        Underlying communication protocol class instance used for interacting
        with the device (e.g. :class:`~peat.protocols.telnet.Telnet`).
        """
        pass

    @comm.setter
    @abstractmethod
    def comm(self, obj):
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to the device.
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """
        Cleanly disconnect from the device.
        """
        pass

    @abstractmethod
    def read(self, delay: float | None = None, strip_whitespace: bool = True) -> str:
        pass

    def write(self, command: bytes | str | int) -> None:
        """
        Send a command to the device.

        Args:
            command: Command to send (this will be automatically encoded)
        """
        # If it's an int, first convert to a string, which will then be encoded
        if isinstance(command, int):
            command = str(command)

        # If it's a string, encode to bytes with the device's encoding
        if isinstance(command, str):
            command = command.encode(self.ENCODING)

        # Append the line terminator (encode here to ensure proper encoding)
        command += self.LINE_TERMINATOR.encode(self.ENCODING)
        self.all_writes.append(command)

        # If we don't sleep, errors can occur.
        if self.PRE_WRITE_SLEEP:
            sleep(self.PRE_WRITE_SLEEP)

        # NOTE: calling telnetlib object directly is a bit of a hack,
        #   the peat.protocols.Telnet wrapper mostly duplicates what we do.
        if isinstance(self.comm, Telnet):
            self.comm.comm.write(command)
        else:
            self.comm.write(command)

        if self.POST_WRITE_SLEEP:
            sleep(self.POST_WRITE_SLEEP)

    def read_lines(self, exclude_command: bool = True, read_until_str: bool = False) -> list[str]:
        """
        Read raw data and process it into a clean trimmed list.

        Args:
            exclude_command: Exclude the first item in the list,
                which is generally the command that was executed
            read_until_str: read until ASCII "0x0003" character
                is encountered, which according to SEL's documentation
                indicates the end of output from a command.
        """
        if read_until_str is True:
            raw_data = self.read_until("\u0003")
        else:
            raw_data = self.read()

        lines = [
            x.strip().replace("\x03\x02", "").replace("\x02", "").strip()
            for x in raw_data.split("\r\n")
            if x
        ]

        # Another filter for empty strings
        # Strings that contain "0x03" and not "0x0302" are
        # strings that contain the prompt, e.g. "=>\u0003".
        lines = [x for x in lines if x and not x.endswith("\x03")]

        if exclude_command:
            return lines[1:]
        else:
            return lines

    def exec_read(
        self,
        command: str,
        return_lines: bool = True,
        added_delay: float | None = None,
        read_until_prompt: bool = False,
    ) -> str | list[str]:
        """
        Execute a command and return the results.

        Args:
            command: The command to execute, e.g. "date" or "id"
            return_lines: If the return value should be a list of
                cleaned and trimmed strings. If False, then the raw
                output is returned unmodified.
            added_delay: Add a sleep between executing the command
                and reading the reply. Needed for commands that take
                a while to execute on the device.
            read_until_prompt: Dynamic way of waiting for large
                outputs or latency
        """
        self.read()  # Flush any output from previous operations
        self.write(command)

        if added_delay:
            # longer delays for commands with a lot of output
            sleep(added_delay)
        if return_lines:
            return self.read_lines(True, read_until_prompt)

        return self.read()

    def extract(self, raw_data: str) -> str:
        """
        Extract the actual data payload from raw command output.
        """
        match = self.DATA_REGEX.search(raw_data)

        if not match:
            self.log.error(
                f"Failed to find data in command output.\n** raw data **\n{repr(raw_data)}"
            )
            return ""

        return match.groups()[0].strip()

    def _ensure_priv(self, method_name: str, level: int = 1) -> None:
        """
        Ensure the current command terminal is at a certain privilege level.
        """
        if self.priv_level < level:
            self.log.info(
                f"Method {method_name}() requires privilege level {level}, "
                f"current level is {self.priv_level}. Attempting "
                f"to elevate automatically..."
            )

            if not self.elevate(level):
                raise DeviceError(f"failed to auto-elevate privilege level on {self.address}")

    def elevate(self, level: int, creds: dict | None = None) -> bool:
        """
        Elevates user privileges on the device.

        .. warning::
           This does not handle non-standard privilege levels, such as ``bac``,
           that are not the standard three levels for SEL (acc/1, 2ac/2, cal/3).

        Args:
            level: Privilege level to elevate to, as a :class:`int`. Available levels:

                - ``1`` : The ``acc`` level
                - ``2`` : The ``2ac`` level
                - ``3`` : The ``cal`` level (aka the ``calibration`` level)
            creds: Login credentials to use for each level, as a :class:`dict`.
                If not specified or :obj:`None`, SEL's default creds are used.
                Example: ``{"acc": "l1pass", "2ac": "l2pass", "cal": "calpass"}``

        Returns:
            If the privilege elevation was successful
        """
        self.log.debug(f"Elevating to privilege level {level} from {self.priv_level}")

        if level > 3 or level < 1:
            self.log.error(f"Invalid SEL privilege level: {level}")
            return False

        if level == self.priv_level:
            self.log.debug(f"Already at privilege level {level}, no elevation commands sent")
            return True

        if not creds:
            creds = self.DEFAULT_CREDS

        try:
            while self.priv_level < level:
                if self.priv_level == 0:
                    self.log.debug("Elevating to level 1 (acc)")
                    self.write("acc")
                    self.read()
                    self.write(creds["acc"])
                    if "invalid" in self.read().lower():
                        self.log.error("Invalid level 1 (acc) password")
                        return False
                    self.priv_level = 1
                    self.successful_usernames.add("acc")

                elif self.priv_level == 1:
                    self.log.debug("Elevating to level 2 (2ac)")
                    self.write("2ac")
                    self.read()
                    self.write(creds["2ac"])
                    if "invalid" in self.read().lower():
                        self.log.error("Invalid level 2 (2ac) password")
                        return False
                    self.priv_level = 2
                    self.successful_usernames.add("2ac")

                elif self.priv_level == 2:
                    self.log.debug("Elevating to level 3 (cal)")
                    self.write("cal")
                    self.write(creds["cal"])
                    if "invalid" in self.read().lower():
                        self.log.error("Invalid level 3 (cal) password")
                        return False
                    self.priv_level = 3
                    self.successful_usernames.add("cal")

                else:
                    self.log.critical(f"Unexpected elevation level: {level}")
                    state.error = True
                    return False
        except Exception as ex:
            self.log.debug(
                f"Failed elevation to privilege level {level} from {self.priv_level}: {ex}"
            )
            self.disconnect()
            return False

        self.log.info(f"Elevated to privilege level {level}")
        return True

    def get_active_group(self) -> str:
        """
        Determine the currently active settings group on a relay (``gro`` command)

        Returns:
            The active settings group
        """
        self.log.debug("Checking the active settings group")

        # "gro" command requires level 1 (show the active group)
        self._ensure_priv("get_active_group", level=1)

        raw_grp = self.exec_read("gro", False, self.POST_WRITE_SLEEP)
        active_res = re.search(
            r".*Active\s+Group\s+=\s+(\d+).*", raw_grp, re.ASCII | re.IGNORECASE
        )

        if not active_res:
            self.log.warning("Unable to determine active settings group")
            return ""

        active_group = str(active_res.groups()[0])

        self.log.debug(f"Active settings group: {active_group}")
        return active_group

    def change_active_group(self, new_group: str) -> None:
        """
        Change the active setting group via the ``gro`` command.

        .. note::
           If the currently active group matches the group to change to then
           the group change command will NOT be executed.

        .. warning::
           This method will NOT validate if the group number being changed
           to is valid for this particular relay!

        Args:
            new_group: Group to change to. Examples: ``"6"``, ``"1"``
        """
        # TODO: validate the group number is valid
        # TODO: error handling if the active group change failed
        current_group = self.get_active_group()

        if not current_group:
            self.log.warning("Unable to determine active settings group")
        elif current_group == new_group:
            self.log.info(f"Settings group '{new_group}' is already active, skipping change")
            return

        # Change active group requires level 2
        self._ensure_priv("change_active_group", level=2)

        self.log.info(f"Changing active group from '{current_group}' to '{new_group}'")

        self.write(f"gro {new_group}")
        sleep(self.POST_WRITE_SLEEP)
        self.write("y")  # answer yes to prompt

        self.log.info(f"Active group changed to '{new_group}'")

    def restart_device(self) -> bool:
        """
        Execute a system restart on the SEL relay (``STA C`` command)

        .. warning::
           This will clear all relay self-test warnings and failures

        Returns:
            If the restart initiation was successful
        """
        self.log.debug("Restarting relay...")

        self._ensure_priv("restart_device", level=2)

        try:
            self.write("sta c")
            sleep(self.POST_WRITE_SLEEP)
            self.write("y")
        except Exception as ex:
            self.log.error(f"Exception during restart: {ex}")
            return False

        self.log.info("Successfully initiated relay restart!")
        return True

    def get_sta(self) -> dict[str, datetime | str]:
        """
        ``sta`` command (basic device information and status).

        .. warning::
           This function currently does not work reliably on all devices

        Returns:
            Data extracted from the command output.
            Refer to :func:`~peat.modules.sel.relay_parse.parse_status_output`
            for details on the data extracted from the command.
        """
        self._ensure_priv("get_sta", level=1)

        output = self.exec_read("sta", read_until_prompt=True)

        return parse_status_output(output)

    def get_id(self) -> dict[str, str]:
        """
        ``id`` command.

        Typical information pulled by ``id``

        - FID
        - BFID
        - CID
        - Device name (``DEVID``)
        - Part number (``PARTNO``)
        - Serial number (``SERIALNO``)
        - Hardware configuration (?) (``CONFIG``)
        - ``Special``
        - IED Name (``iedName``)
        - Type
        - Configuration version (``configVersion``)
        """
        lines = self.exec_read("id", added_delay=5.0)

        self.log.trace2(f"** Unparsed 'id' command output **\n{lines}")
        if not lines:
            return {}

        # TODO: move parsing of output to an independent function
        # 351 has newline separating id and data, 451 doesn't
        info = {}
        for line in lines[:-2]:  # Exclude '=>>' and weird byte lines
            # Handle any weird input that could happen
            if "," not in line:
                self.log.trace2(f"No comma in line of id command output. Raw line: {line}")
                continue

            # Example line: "DEVID=STATION A","049C"
            # Remove the trailing hex and quotes, then split on '='
            key_val = line.rpartition(",")[0].replace('"', "").replace("\x02", "").split("=")
            self.log.trace2(f"get_id() => 'key_val': {key_val}")

            # Handle cases of no value for a key, e.g. "configVersion=","0609"
            if len(key_val) == 1:
                self.log.trace(f"No value for key '{key_val[0]}' in result of id command")
            else:
                info[key_val[0]] = key_val[1]  # info['DEVID'] = 'STATION A'

        self.log.trace2(f"** get_id() => 'info' **\n{info}")
        return info

    def parse_exit_info(self, raw: str) -> dict[str, datetime | str]:
        """
        Extract info returned when we disconnect cleanly (run ``exit``).

        Info keys

        - ``time_source`` (Optional)
        - ``RID``
        - ``device_time``
        - ``TID``

        Info includes the RID, TID, and current device time. It may also
        include the time source identifier.
        """
        # TODO: unit test
        # TODO: merge this parsing with relay_parse.parse_status_info()
        info = {}
        clean = raw.replace("\x02", "").replace("\x03", "").strip("=")
        if "Time Source" in clean:
            ts_match = re.search(r"Time Source: ([\w ]*)\s", clean)
            if ts_match:
                info["time_source"] = ts_match.groups()[0]
            clean = clean.split("Time Source")[0]

        # TODO: group 4 (TID) may not exist on some devices, like weird a SEL-311L
        regex = r"(?:quit|exit)\s*([\S ]*)\s*Date\: (\S*)\s*Time\: (\S*)\s*([\S ]*)\s"
        match = re.search(regex, clean, re.ASCII)
        if not match:
            self.log.warning("Failed to parse info returned on exit")
            return info

        data = match.groups()
        info["RID"] = data[0].strip()
        info["device_time"] = date_parse(f"{data[1]} {data[2]}")
        info["TID"] = data[3].strip()

        if info["TID"] == "#exit":
            info["TID"] = ""

        return info

    def list_files(self, directory: str | None = None) -> list[str]:
        """
        List files in a directory on the device.

        .. note::
           File listing requires level 1 (``acc``) permissions on all devices
           we've seen. The privilege level will be automatically escalated
           when this function is called, if needed.

        Args:
            directory: Case-insensitive name of directory to list the contents of.
                If :obj:`None` or empty string, the current directory is listed.

        Returns:
            List of names of files in the directory.

        Raises:
            DeviceError: Automatic privilege elevation failed
        """
        self._ensure_priv("list_files", level=1)

        if directory:
            dir_name = f"directory '{directory}'"
        else:
            dir_name = "the current directory"

        self.log.info(f"Reading file listing of {dir_name}")

        self.read()  # Flush any output from previous operations

        if directory:
            self.write(f"fil dir {directory}")
        else:
            self.write("fil dir")

        # ... takes ~5-15 seconds to get results ...
        sleep(10.0)  # Give telnet time to load file

        # parse the filenames into a list of strings
        parsed_file_list = []

        for line in self.read_lines():
            # If directory is empty or doesn't exist
            if "file specified does not exist" in line.lower():
                self.log.warning(f"{dir_name} is empty or doesn't exist")
                return []

            m = re.search(r"(?P<item>[\w.]+)\s+(?P<type>\w)", line, re.ASCII | re.IGNORECASE)

            if m:
                name = m.groups()[0]  # name, filetype ('R' or 'D')
                if name.lower() != "fil":
                    parsed_file_list.append(name)
            elif config.DEBUG >= 3:
                self.log.trace3(f"Failed to match line: {line}")

        self.log.trace(f"** File listing of {dir_name} **\n{parsed_file_list}")
        return parsed_file_list

    def show_bre(self) -> list[str]:
        """
        ``bre`` command. Provides the Breaker monitor report.
        """
        self._ensure_priv("show_bre", level=1)

        return self.exec_read("bre", added_delay=2.0)

    def show_mac(self) -> dict[str, str]:
        """
        ``mac`` command.
        """
        self._ensure_priv("show_mac", level=1)

        output = self.exec_read("mac", return_lines=False, read_until_prompt=True)
        data = self.extract(output)

        # TODO: SEL-451 and SEL-351 (and 351S and 700G??)

        # SEL-351S has this format
        regex = r".*\(IP\) MAC.*" + MAC_RE_DASH + r".*\(GOOSE\) MAC.*" + MAC_RE_DASH
        match = re.match(regex, data, re.ASCII | re.DOTALL)

        if not match:
            return {}

        return {
            "ip_mac": match.groups()[0].replace("-", ":").upper(),
            "goose_mac": match.groups()[1].replace("-", ":").upper(),
        }

    def show_eth(self) -> list[str]:
        """
        ``eth`` command.
        """
        return self.exec_read("eth", added_delay=2.0)

    def get_device_time(self) -> datetime | None:
        """
        Combines output of ``date`` and ``time`` commands.

        On the SEL-451 and some other models, the output may also contain timezone information.
        This information will be returned as part of the :class:`datetime.datetime` object.
        """
        self._ensure_priv("get_device_time", level=1)

        raw_date = self.exec_read("date")
        raw_time = self.exec_read("time")

        if not raw_date or not raw_time:
            return None

        raw_date = raw_date[0]
        raw_time = raw_time[0]

        # Attempt to infer the device's timezone from UTC offset in output of commands
        tz_offset = ""

        # SEL-451
        if "UTC " in raw_date:
            # date: "local: 02/09/2023     UTC: 02/09/2023     UTC Offset: -08.0 hrs"
            # time: "local: 14:35:20     UTC: 22:35:20     UTC Offset: -08.0 hrs"
            regex = re.compile(
                (
                    r"local\: (?P<local>[\d/:]+) \s+ UTC\: (?P<utc>[\d/:]+) "
                    r"\s+ UTC Offset\: (?P<offset>.+) hrs"
                ),
                re.ASCII | re.IGNORECASE,
            )
            d_match = regex.match(raw_date)
            t_match = regex.match(raw_time)

            if not d_match or not t_match:
                return None

            dates = d_match.groupdict()
            times = t_match.groupdict()

            raw_date = dates["local"]
            raw_time = times["local"]
            tz_offset = dates["offset"].replace(".", ":")

        # SEL-700G
        elif ":=" in raw_date:
            # date: "Date     := 02/09/2023"
            # time: "Time     := 15:51:00.265"
            raw_date = raw_date.partition(":=")[2].strip()
            raw_time = raw_time.partition(":=")[2].strip()

        # 2032, 351, 351S
        # "02/09/23"
        # "14:28:06"

        # "02/09/23 15:51:00.265"
        ts_string = f"{raw_date} {raw_time} {tz_offset}".strip()

        return utils.parse_date(ts_string)

    def show_his(self) -> list[str]:
        """
        ``his`` command.
        """
        return self.exec_read("his", added_delay=15.0, read_until_prompt=True)

    def show_status(self) -> list[str]:
        """
        ``sta s`` command.

        Known devices that DO NOT support this command:

        - SEL-2032
        - SEL-351
        - SEL-351S
        """
        return self.exec_read("sta s")

    def show_ser(self) -> list[str]:
        """
        ``ser`` command. Sequential Event Recorder (SER).

        NOTE: this can take a while if the SER has a lot of entries.
        """
        # On the SEL-2032, this requires an argument.
        # SEL-2032 RTU has per-port SER logs. Maybe we could
        # be smarter about this in the future, and issue multiple
        # queries for each port's log?
        if self.model == "2032":
            result = self.exec_read("ser GLOBAL 100", added_delay=5.0)
        else:
            # TODO: use the same buffering technique as for "fil dir"
            # TODO: handle large SER log (like on the 700G on the PEAT rack)
            result = self.exec_read("ser", read_until_prompt=True, added_delay=10.0)

        return result

    def show_sum(self) -> list[str]:
        """
        ``sum`` command.

        Potentially not present on:

        - SEL-2032
        - SEL-351
        """
        return self.exec_read("sum")

    def show_eve(self) -> list[str]:
        """
        ``eve`` command. Event reports.
        """
        return self.exec_read("eve", added_delay=2.0)


__all__ = ["SELAscii"]
