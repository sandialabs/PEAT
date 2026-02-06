from __future__ import annotations

import re
import socket
import time
from pathlib import Path

from peat import (
    IO,
    DeviceData,
    DeviceModule,
    Event,
    IPMethod,
    config,
    log,
    state,
    utils,
)


# TODO: record all data sent and received via telnet
# TODO: subclass peat.protocols.Telnet (need to make this work with telnetlib first)
#   (from notes): can't use telnetlib with the D25, it'll cause
#     device's telnet server to crash or become non-responsive
class D25Telnet:
    """
    Implementation of the command interface for the GE D25 RTU over Telnet.
    """

    def __init__(
        self,
        ip: str,
        port: int = 23,
        timeout: float = 5.0,
        menu_sleep_seconds: float = 5.0,
        raw_dir: Path | None = None,
    ):
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout
        self.menu_sleep_seconds: float = menu_sleep_seconds

        self.raw_dir: Path | None = raw_dir
        if self.raw_dir:
            self.raw_dir.mkdir(parents=True, exist_ok=True)

        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.is_connected: bool = False
        self.logged_in: bool = False

    def __enter__(self) -> D25Telnet:
        if not self.connect():
            raise Exception(f"failed to connect to {str(self)}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(f"{exc_type.__name__}: {exc_val}")

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.ip}, {self.port}, "
            f"{self.timeout}, {self.menu_sleep_seconds})"
        )

    def connect(self) -> bool:
        try:
            self.sock.connect((self.ip, self.port))
        except TimeoutError:
            self.log.debug(f"Socket timed out during connect (timeout: {self.timeout} seconds)")
            raise Exception(f"socket timeout during connection to {str(self)}") from None
        self.is_connected = True
        return self.is_connected

    def disconnect(self) -> None:
        self.is_connected = False
        self.logged_in = False
        self.sock.close()

    def login(self, username: str, password: str) -> bool:
        """
        Logs into D25 telnet with supplied username and password.
        """
        self.sock.send(b"\r\n")

        time.sleep(1)
        data = self.sock.recv(4096)
        if b"NAME:" in data:
            self.sock.send(f"{username}\r\n".encode())
        else:
            self.log.error(f"Failed login as '{username}': no 'NAME' in output")
            return False

        time.sleep(1)
        data = self.sock.recv(4096)
        if b"PASSWORD:" in data:
            self.sock.send(f"{password}\r\n".encode())
        else:
            self.log.error(f"Failed login as '{username}': no 'PASSWORD' in output")
            return False

        self.logged_in = True
        self.log.info(f"Logged in to {self.ip} as {username}")
        time.sleep(5)

        return True

    def is_desired_menu(self, menu: str) -> bool:
        """
        Checks to see if telnet session is at main menu.
        """
        data = self.sock.recv(8192)
        if menu.encode() in data:
            return True
        return False

    def select_menu_option(self, option: bytes | str | int) -> None:
        """
        Sends a number, letter, or command corresponding to a menu option.
        """
        if not isinstance(option, (bytes, str)):
            option = str(option)
        if isinstance(option, str):
            option = option.encode()

        self.log.info(f"Sending menu option: {option}".replace(" b'", " ").strip("'"))
        self.sock.send(option)

        self.log.debug(f"Sleeping for {self.menu_sleep_seconds} seconds")
        time.sleep(self.menu_sleep_seconds)

    def navigate_menus(self, menu_options: list[dict[str, list]]) -> bool:
        """
        Navigates to desired menu in telnet sessions.
        """
        # Go to top menu first. \x14 = Ctrl+T
        self.sock.recv(8192)  # skip garbage
        self.select_menu_option(b"\x14")

        for o in menu_options:
            for k in o:
                if self.is_desired_menu(k):
                    for c in o[k]:
                        self.select_menu_option(c)
                else:
                    self.log.warning(
                        f"Trouble navigating to desired menu (menu options: {menu_options})"
                    )
                    return False

        return True

    def get_data_digital_io(self, io: str) -> str:
        """
        Parse data of Digital Input Display submenu.
        """
        data = self.sock.recv(8192)
        data = clean_up_data(data)

        if io == "I":
            # Go to beginning and get next until end
            self.select_menu_option("b")
            self.sock.recv(8192)  # skip garbage
            chunk = ""
            while chunk != ",":
                self.select_menu_option("n")
                chunk = self.sock.recv(8192)
                chunk = clean_up_data(chunk)
                data += chunk
        elif io == "O":
            self.select_menu_option("n")
            data = self.sock.recv(8192)
            data = clean_up_data(data)

        if self.raw_dir:
            utils.write_file(data, self.raw_dir / f"digital_io_{io}.txt")

        return data

    def get_data_erroruser_logs(self, remove_time: bool) -> str:
        """
        Parse data function Error and User logs.
        Returns up to 20 latest log entries.
        """
        data = self.sock.recv(8192)
        if remove_time:
            data = clean_up_data(data)
        else:
            data = clean_up_data(data, rm_time=False)

        # Add marker to help parse later
        data += ",~%meep%~,"
        self.select_menu_option("n")

        chunk = self.sock.recv(8192)
        if remove_time:
            chunk = clean_up_data(chunk)
        else:
            chunk = clean_up_data(chunk, rm_time=False)
        data += chunk

        if self.raw_dir:
            utils.write_file(data, self.raw_dir / "erroruser_logs.txt")

        return data

    def get_internet_stats(self) -> str:
        """
        A parse data function for Internet stats.
        """
        data = self.sock.recv(8192)
        data = clean_up_data(data, rm_time=True)

        if self.raw_dir:
            utils.write_file(data, self.raw_dir / "internet_stats.txt")

        return data


class GERTU(DeviceModule):
    """
    PEAT module for the GE D25 RTU.

    Listening services

    - Telnet (TCP 23)

    Authors

    - Christopher Goes
    - Justin Cox, Idaho National Laboratory (INL)
    """

    device_type = "RTU"
    vendor_id = "GE"
    vendor_name = "General Electric"
    brand = "Multilin"
    model = "D25"
    supported_models = ["D25"]
    default_options = {
        "telnet": {
            "user": "User",
            "pass": "Password",
        },
        "ge": {
            "menu_sleep_seconds": 5.0,
        },
    }

    # TODO: move to D25Telnet
    menu_nav_digital_i = [{"Main Menu": [1]}, {"System Data Menu": [1]}]
    menu_nav_digital_o = [{"Main Menu": [1]}, {"System Data Menu": [2]}]
    menu_nav_analog_i = [{"Main Menu": [1]}, {"System Data Menu": [3]}]
    menu_nav_analog_o = [{"Main Menu": [1]}, {"System Data Menu": [4]}]
    menu_nav_errorlog = [{"Main Menu": [2]}, {"System Functions Menu": [4]}]
    menu_nav_userlog = [{"Main Menu": [2]}, {"System Functions Menu": [5]}]
    menu_nav_internet_ip = [
        {"Main Menu": [3]},
        {"Application Menu": [b"\x1b\x5b\x43", "\r\n"]},
        {"Internet Statistics Menu": [3]},
    ]
    menu_nav_internet_udp = [
        {"Main Menu": [3]},
        {"Application Menu": [b"\x1b\x5b\x43", "\r\n"]},
        {"Internet Statistics Menu": [4]},
    ]
    menu_nav_internet_tcp = [
        {"Main Menu": [3]},
        {"Application Menu": [b"\x1b\x5b\x43", "\r\n"]},
        {"Internet Statistics Menu": [5]},
    ]

    @classmethod
    def _setup_tn(cls, dev: DeviceData) -> D25Telnet | None:
        # TODO: register exit handler to properly disconnect
        # from telnet with peat.exit_handler.register().
        if not dev._cache.get("d25telnet_object"):
            raw_dir = None
            if config.DEVICE_DIR:
                raw_dir = dev.get_sub_dir("raw_telnet_data")

            dev._cache["d25telnet_object"] = D25Telnet(
                ip=dev.ip,
                port=dev.options["telnet"]["port"],
                timeout=dev.options["telnet"]["timeout"],
                menu_sleep_seconds=dev.options["ge"]["menu_sleep_seconds"],
                raw_dir=raw_dir,
            )

        tn: D25Telnet = dev._cache["d25telnet_object"]

        if not tn.is_connected and not tn.connect():
            cls.log.warning("Unable to connect")
            return None

        if not tn.logged_in and not tn.login(
            dev.options["telnet"]["user"], dev.options["telnet"]["pass"]
        ):
            cls.log.warning("Unable to login")
            return None

        dev.related.user.add(dev.options["telnet"]["user"])

        return tn

    @classmethod
    def _verify_telnet(cls, dev: DeviceData) -> bool:
        """
        Verify GE D25 RTU via Telnet by attempting to connect and
        login to the Telnet user interface.
        """
        if cls._setup_tn(dev):
            cls.log.info(f"Verified {dev.ip} via Telnet")
            return True

        cls.log.debug(f"Failed to verify {dev.ip} via Telnet")
        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        tn = cls._setup_tn(dev)  # setup telnet connection
        if not tn:
            return False

        rtu_data = {}

        # Get Digital Input Display
        tn.navigate_menus(cls.menu_nav_digital_i)
        data = tn.get_data_digital_io("I")
        rtu_data["digital_input"] = parse_digital_io_menu(data, "I")
        cls.process_io(dev, rtu_data["digital_input"], "digital", "input")

        # Get Digital Output Display
        tn.navigate_menus(cls.menu_nav_digital_o)
        data = tn.get_data_digital_io("O")
        rtu_data["digital_output"] = parse_digital_io_menu(data, "O")
        cls.process_io(dev, rtu_data["digital_output"], "digital", "output")

        # Get Analog Input Display
        tn.navigate_menus(cls.menu_nav_analog_i)
        data = tn.get_data_digital_io("I")
        rtu_data["analog_input"] = parse_analog_io_menu(data, "I")
        cls.process_io(dev, rtu_data["analog_input"], "analog", "input")

        # Get Analog Output Display
        tn.navigate_menus(cls.menu_nav_analog_o)
        data = tn.get_data_digital_io("O")
        rtu_data["analog_output"] = parse_analog_io_menu(data, "O")
        cls.process_io(dev, rtu_data["analog_output"], "analog", "output")

        # Get Internet Statistics
        # IP
        tn.navigate_menus(cls.menu_nav_internet_ip)
        data = tn.get_internet_stats()
        rtu_data["inet_ip"] = parse_internet_stats_menu(data)

        # UDP
        tn.navigate_menus(cls.menu_nav_internet_udp)
        data = tn.get_internet_stats()
        rtu_data["inet_udp"] = parse_internet_stats_menu(data)

        # TCP
        tn.navigate_menus(cls.menu_nav_internet_tcp)
        data = tn.get_internet_stats()
        rtu_data["inet_tcp"] = parse_internet_stats_menu(data)

        # Get Error Logs
        tn.navigate_menus(cls.menu_nav_errorlog)
        data = tn.get_data_erroruser_logs(True)
        rtu_data["error_log"] = parse_errorlog_menu(data)
        cls.process_error_log(dev, rtu_data["error_log"])

        # Get User Logs
        tn.navigate_menus(cls.menu_nav_userlog)
        data = tn.get_data_erroruser_logs(False)
        rtu_data["user_log"] = parse_userlog_menu(data)
        cls.process_user_log(dev, rtu_data["user_log"])

        dev.write_file(rtu_data, "raw-data.json")
        dev.extra.update(rtu_data)

        # Remove extraneous data that's been processed into the data model.
        # If the values are desired, look at the data in "*raw-data*.json".
        for extra_key in [
            "error_log",
            "user_log",
            "digital_input",
            "digital_output",
            "analog_input",
            "analog_output",
        ]:
            if extra_key in dev.extra:
                del dev.extra[extra_key]

        return True

    @classmethod
    def process_io(cls, dev: DeviceData, data: dict[str, str], typ: str, direction: str) -> None:
        for addr in data.keys():
            io = IO(
                address=addr,
                type=typ,
                direction=direction,
            )
            dev.store("io", io)

    @classmethod
    def process_error_log(cls, dev: DeviceData, data: dict[str, str]) -> None:
        for seq, log_text in data.items():
            event = Event(
                category={"host"},
                dataset="error_log",
                kind={"event"},
                module=cls.__name__ if not dev._module else dev._module.__name__,
                original=log_text,
                sequence=int(seq),
            )

            if "IP=" in log_text:
                event.category.add("network")
                event.type = {"info"}
                try:
                    ip = log_text.partition("IP=")[2].split(",")[0].strip()
                    dev.related.ip.add(ip)
                except Exception as ex:
                    cls.log.warning(f"Failed to parse event: {ex}")
                    event.kind.add("pipeline_error")
            else:
                event.type = {"error"}

            if "can't" in log_text.lower():
                event.outcome = "failure"

            dev.store("event", event)

    @classmethod
    def process_user_log(cls, dev: DeviceData, data: dict[str, dict[str, str]]) -> None:
        for seq, log_values in data.items():
            # Parse single event into two separate events for login and logout
            for log_type in ["Login", "Logout"]:
                # WARNING: some of these can be malformed by the device due
                # to the flakiness of the device's interface.
                # For example, the username might bleed into the "created" field
                # of a previous log entry.
                # TODO: get raw log entry before it's parsed, store in "original"
                try:
                    event = Event(
                        action=f"user-{log_type.lower()}",
                        category={"authentication", "network", "session", "host"},
                        dataset="user_log",
                        kind={"event"},
                        extra={},
                        module=(cls.__name__ if not dev._module else dev._module.__name__),
                        sequence=int(seq),
                        type={"access", "allowed", "user", "connection"},
                    )

                    if log_values.get(log_type):
                        # "25/09/09 00:00:00"
                        # year/month/day hour:minute:second
                        try:
                            event.created = utils.parse_date(
                                raw_time=log_values[log_type], year_first=True
                            )
                        except Exception as ex:
                            cls.log.warning(f"Failed to parse event timestamp for {dev.ip}: {ex}")
                            event.kind.add("pipeline_error")
                    else:
                        cls.log.warning(
                            f"Failed to get '{log_type}' for event "
                            f"from {dev.ip}\n** Raw data **\n{log_values}"
                        )
                        event.kind.add("pipeline_error")

                    if log_values.get("Channel"):
                        event.extra["channel"] = log_values["Channel"]

                    if log_values.get("UserId"):
                        event.extra["user_id"] = log_values["UserId"]
                        dev.related.user.add(log_values["UserId"])
                    elif log_values.get("User"):
                        event.extra["user_id"] = log_values["User"]
                        dev.related.user.add(log_values["User"])

                    dev.store("event", event)
                except Exception as ex:
                    cls.log.error(
                        f"Failed '{log_type}' event processing for "
                        f"{dev.ip}: {ex}\n** Raw data **\n{log_values}"
                    )
                    state.error = True


GERTU.ip_methods = [
    IPMethod(
        name="GE D25 RTU Telnet",
        description=str(GERTU._verify_telnet.__doc__).strip(),
        type="unicast_ip",
        identify_function=GERTU._verify_telnet,
        reliability=5,
        protocol="telnet",
        transport="tcp",
        default_port=23,
    ),
]


def clean_up_data(data: bytes, rm_time: bool = True) -> str:
    """
    Filters and removes garbage data from telnet session.
    """
    # Filter out ANSI characters
    data = re.sub(rb"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]", b"", data)
    data = re.sub(rb"\xff|\xf9|\x1b[0-9]", b"", data)

    # Remove clock/date
    if rm_time:
        data = re.sub(rb"[0-9][0-9]:[0-9][0-9]:[0-9][0-9]", b"", data)
    data = re.sub(rb"[0-9][0-9]-[0-9][0-9]-[0-9][0-9]", b"", data)

    # Remove telnet strings causing trouble
    data = re.sub(rb"N / A NODE:0 SYNC:NONE", b"", data)

    # Remove multiple spaces
    data = re.sub(rb" {2,}", b",", data)
    data = data.decode(errors="replace")

    return data


def parse_digital_io_menu(data: str, io: str) -> dict:
    """
    Parse Digital Input and Digital Output display menus.
    """
    parts = data.split(",")
    digital_io = {}
    prev = ""

    for w in parts:
        if w == "OFF":
            digital_io[prev] = "OFF"
        elif w == "ON":
            digital_io[prev] = "ON"
        elif "OFF" in w:
            if io == "I":
                w = w.split("OFF")[0]
                digital_io[w] = "OFF"
            elif io == "O":
                w = w.strip("*")
                w = w.replace("OFF", ",OFF")
                w = w.replace("ON", ",ON")
                w = w.split(",")
                for i, val in enumerate(w):
                    if i != 0:
                        digital_io[str(i)] = val
        elif "ON" in w:
            w = w.split("ON")[0]
            digital_io[w] = "ON"

        prev = w

    return digital_io


def parse_analog_io_menu(data: str, io: str) -> dict:
    """
    Parse Analog Input and Analog Output display menus.
    """
    parts = data.split(",")
    analog_io = {}
    prev = ""
    entry_count = 0

    for w in parts:
        if "********" in w:
            if re.search(r"\+[0-9]", w) or re.search(r"-[0-9]", w):
                val_stripped = w.strip("*")
                entry_count += 1
                analog_io[str(entry_count)] = val_stripped
            re_result = re.findall(r"\*\*\*\*\*\*\*\*", w)
            entry_count += len(re_result)
        elif re.search(r"\+[0-9]", w):
            if io == "I":
                analog_io[str(prev)] = w
            elif io == "O":
                entry_count += 1
                analog_io[str(entry_count)] = w
        elif re.search(r"-[0-9]", w):
            if io == "I":
                analog_io[str(prev)] = w
            elif io == "O":
                entry_count += 1
                analog_io[str(entry_count)] = w

        prev = w

    return analog_io


def parse_errorlog_menu(data: str) -> dict:
    """
    Parse Error Log Menu.
    """
    data_first_page = data.split(",~%meep%~,", maxsplit=1)[0]
    data_second_page = data.split(",~%meep%~,")[1]
    errorlog = {}

    # First Page
    positions = []
    iter_match = re.finditer(r"[a-zA-z0-9]{4}\sN0:", data_first_page)
    for match in iter_match:
        positions.append(match.start())
    for i, _ in enumerate(positions):
        if i < (len(positions) - 1):
            errorlog[i + 1] = data_first_page[positions[i] : positions[i + 1]]
        else:
            errorlog[i + 1] = data_first_page[positions[i] :]

    # Second Page
    positions = []
    iter_match = re.finditer(r"[a-zA-z0-9]{4}\sN0:", data_second_page)
    for match in iter_match:
        positions.append(match.start())
    for i, _ in enumerate(positions):
        # To avoid duplicates, we don't care about the first 13 (2-14) entries
        if i > 12:
            if i < (len(positions) - 1):
                errorlog[i + 2] = data_second_page[positions[i] : positions[i + 1]]
            else:
                errorlog[i + 2] = data_second_page[positions[i] :]

    return {str(i): v for i, v in errorlog.items()}


def parse_userlog_menu(data: str) -> dict:
    """
    Parse User Log Menu.
    """
    data_first_page = data.split(",~%meep%~,", maxsplit=1)[0]
    data_second_page = data.split(",~%meep%~,")[1]
    userlog = {}

    # First Page
    position = 0
    counter = 1
    data_first_page = data_first_page.split(",")
    login_val = None
    next_login_val = None
    logout_val = ""
    channel_val = ""

    for entry in data_first_page:
        if position == 0:
            if re.search(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry):
                raw_val = re.split(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry)[0]
                login_val = entry.replace(raw_val, "", 1)
        elif position == 1:
            logout_val = entry
        elif position == 2:
            channel_val = entry
        else:
            if re.search(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry):
                userid_val = re.split(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry)[0]
                if counter == 1:
                    userlog[counter] = {
                        "Login": login_val,
                        "Logout": logout_val,
                        "Channel": channel_val,
                        "UserId": userid_val,
                    }
                else:
                    userlog[counter] = {
                        "Login": next_login_val,
                        "Logout": logout_val,
                        "Channel": channel_val,
                        "UserId": userid_val,
                    }
                next_login_val = entry.replace(userid_val, "", 1)
                counter += 1
                position = 0
            # TODO: fix userid getting merged with channel with all logs newer than 14
            elif counter == 14:
                userid_val = entry
                userlog[counter] = {
                    "Login": next_login_val,
                    "Logout": logout_val,
                    "Channel": channel_val,
                    "UserId": userid_val,
                }
                counter += 1
                position = 0

        if login_val:
            position += 1

    # Second Page
    data_second_page = data_second_page.split(",")
    position = 0
    counter = 1
    login_val = None
    next_login_val = None
    logout_val = ""
    channel_val = ""

    for entry in data_second_page:
        if position == 0:
            if re.search(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry):
                raw_val = re.split(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry)[0]
                login_val = entry.replace(raw_val, "", 1)
        elif position == 1:
            logout_val = entry
        elif position == 2:
            channel_val = entry
        else:
            if re.search(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry):
                userid_val = re.split(r"[0-9]{2}/[0-9]{2}/[0-9]{2}", entry)[0]
                if counter > 14:
                    userlog[counter] = {
                        "Login": next_login_val,
                        "Logout": logout_val,
                        "Channel": channel_val,
                        "UserId": userid_val,
                    }
                next_login_val = entry.replace(userid_val, "", 1)
                counter += 1
                position = 0
            elif counter == 20:
                userid_val = entry
                userlog[counter] = {
                    "Login": next_login_val,
                    "Logout": logout_val,
                    "Channel": channel_val,
                    "UserId": userid_val,
                }
                counter += 1
                position = 0

        if login_val:
            position += 1

    return {str(i): v for i, v in userlog.items()}


def parse_internet_stats_menu(data: str) -> dict:
    """
    Get Internet Statistics by parsing internet stat sub-menus.
    """
    internet_stats = {}

    # Fix numbers not separated by commas
    re_result = re.finditer(r"\d+\s\d+", data)
    for r in re_result:
        data = data.replace(data[r.start() : r.end()], data[r.start() : r.end()].replace(" ", ","))
    parts = data.split(",")

    # Get Keys and Values
    start_now = False
    skip_one = False
    keys = []
    num_vals = 0

    for i_e, entry in enumerate(parts):
        if "Top_menu" in entry:
            start_now = True
            entry = entry.split("Top_menu Zero ")[1]
            matches = re.finditer(r"[a-z][A-Z](?!rder)", entry)
            previous = 0
            # Get keys
            for m in matches:
                m_pos = m.start()
                keys.append(entry[previous : m_pos + 1])
                previous = m_pos + 1

            # Get last key
            keys.append(entry[previous:])

            # Check to see if you are at numeric values yet
            # This must be done because sometimes keys get split into two entries in the array
            try:
                int(parts[i_e + 1])
                pass
            except ValueError:
                matches = re.finditer(r"[a-z][A-Z](?!rder)", parts[i_e + 1])
                previous = 0
                # Get keys
                for m in matches:
                    m_pos = m.start()
                    keys.append(parts[i_e + 1][previous : m_pos + 1])
                    previous = m_pos + 1
                # Get last key
                keys.append(parts[i_e + 1][previous:])
                skip_one = True

            # Fix/Split Outliers
            # num_to_skip is used to skip over added indices parsed prom T/O string
            num_to_skip = 0
            for i, key in enumerate(keys):
                if num_to_skip == 0:
                    if "Fragmented OK" in key:
                        match = re.finditer(r"KFrag", key)
                        for m in match:
                            m_pos = m.start()
                        keys[i] = key[: m_pos + 1]
                        keys.insert(i + 1, key[m_pos + 1 :])
                    if "T/O" in key:
                        match = re.finditer(r"T/O", key)
                        temp_keys = []
                        previous = 0
                        for m in match:
                            num_to_skip += 1
                            m_pos = m.start()
                            temp_keys.append(key[previous : m_pos + 3])
                            previous = m_pos + 3
                        # Get last key
                        temp_keys.append(key[previous:])
                        num_to_skip += 1

                        for j in range(len(temp_keys)):
                            if j == 0:
                                keys[i] = temp_keys[j]
                            else:
                                keys.insert(i + j, temp_keys[j])
                else:
                    num_to_skip -= 1
        elif start_now:
            if skip_one:
                skip_one = False
            elif num_vals < len(keys):
                internet_stats[keys[num_vals].replace(" ", "_").lower()] = entry
                num_vals += 1

    return internet_stats
