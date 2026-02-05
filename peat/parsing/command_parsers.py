"""
Parse and/or process the output of various Linux commands and files,
such as ``arp -a``, ``/proc/meminfo``, ``/var/log/messages``, etc.

References for /proc (aka, "procfs"):

- https://www.kernel.org/doc/html/latest/filesystems/proc.html
- https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html
- https://www.man7.org/linux/man-pages/man5/procfs.5.html
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/s1-proc-topfiles

"""

import datetime
import itertools
import json
import os.path
import re
from collections import defaultdict
from pathlib import PurePosixPath

import humanfriendly
from humanfriendly.text import split_paragraphs

from peat import DeviceData, Event, Interface, log, utils
from peat.data.models import File, Service, User


class NixParserBase:
    """
    Base class for nix file and command parsers (Linux, VxWorks, etc.).
    """

    # file paths/names for file parsers
    file: PurePosixPath | None = None
    paths: list[PurePosixPath] = []

    # list of commands with arguments
    command: str = ""
    commands: list[str] = []

    @classmethod
    def parse_and_process(cls, to_parse: str, dev: DeviceData) -> bool:
        """
        Parse the data, then process it into the device data model.
        """
        if not to_parse:
            log.warning(f"{cls.__name__}: no data to parse")
            return False

        # Save raw file or command output to file
        if cls.file:
            # PEAT's auto-serialization of JSON works against
            # us here, so manually load it then save.
            file_data = to_parse
            if cls.file.suffix == ".json":
                file_data = json.loads(file_data)

            dev.write_file(
                data=file_data,
                filename=cls.file.name,
                out_dir=dev.get_out_dir() / "raw_files",
            )
        elif cls.command:
            dev.write_file(
                data=to_parse,
                filename=convert_filename(cls.command) + ".txt",
                out_dir=dev.get_out_dir() / "raw_commands",
            )
        else:
            raise ValueError(f"'file' and 'command' unset for {cls.__name__}")

        try:
            parsed = cls.parse(to_parse)
        except Exception as ex:
            log.error(f"{cls.__name__}: Exception parsing {cls.type()} data: {ex}")
            return False

        if not parsed:
            log.warning(f"{cls.__name__}: no parsed data, parse probably failed")
            return False

        # Set file extension based on type of parsed data
        if isinstance(parsed, (dict, list)):
            file_ext = ".json"
        else:
            file_ext = ".txt"

        # Determine file basename
        if cls.file:
            dev.related.files.add(str(cls.file))
            f_base = cls.file.stem
        else:
            f_base = convert_filename(cls.command)

        # Save parsed format to file
        dev.write_file(
            data=parsed,
            filename=f_base + file_ext,
            out_dir=dev.get_out_dir() / "parsed",
        )

        # Save parsed format to extra
        if cls not in [
            VarLogMessagesParser,
            LsRecursiveParser,
        ]:
            if cls.file and str(cls.file) not in dev.extra:
                dev.extra[str(cls.file)] = parsed
            elif cls.command and cls.command not in dev.extra:
                dev.extra[cls.command] = parsed

        # Process the data
        try:
            cls.process(parsed, dev)
        except Exception as ex:
            log.error(f"{cls.__name__}: Exception processing {cls.type()} data: {ex}")
            return False

        return True

    @classmethod
    def type(cls) -> str:
        if cls.file:
            return "file"
        elif cls.command:
            return "command"
        else:
            raise ValueError(f"'file' and 'command' unset for {cls.__name__}")

    @classmethod
    def parse(cls, to_parse: str):
        """
        Parse raw data into a Python data structure,
        such as a dict or list.
        """
        ...

    @classmethod
    def process(cls, to_process, dev: DeviceData) -> None:
        """
        Process parsed data into the device data model.
        """
        ...


class VarLogMessagesParser(NixParserBase):
    """
    Parse messages from ``/var/log/messages``.
    """

    file = PurePosixPath("/var/log/messages")

    MESSAGE_REGEX = (
        r"(?P<timestamp>\w+[ \t]+\d+[ \t]+\d{2}:\d{2}:\d{2})[ \t]+"
        r"(?P<hostname>\S+)[ \t]+(?P<logger>\S+)\.(?P<level>\S+)[ \t]+"
        r"(?P<process>[^:]+): (?P<message>.*)"
    )  # type: str

    @classmethod
    def parse(cls, to_parse: str) -> list[dict[str, str]]:
        results = []

        for line in to_parse.strip().splitlines():
            match = re.match(cls.MESSAGE_REGEX, line.strip(), re.IGNORECASE)
            if match:
                msg = match.groupdict()
                msg["raw_line"] = line
                results.append(msg)
            else:
                log.warning(f"Failed to parse message line: {line}")

        return results

    @classmethod
    def process(cls, to_process, dev: DeviceData) -> None:
        for index, msg in enumerate(to_process):
            timestamp = utils.parse_date(msg["timestamp"])

            # !! NOTE: this relies on DateParser running prior this !!
            # make year for timestamps relative to the correct year
            if (
                dev.extra.get("current_time")
                and timestamp.year > dev.extra["current_time"].year
            ):
                timestamp = timestamp.replace(year=dev.extra["current_time"].year)

            msg_lower = msg["message"].lower()  # type: str
            event_category = {"host"}  # type: set[str]
            event_type = set()  # type: set[str]
            event_outcome = ""  # type: str

            # add to event.category
            if msg["logger"] == "auth":
                event_category.add("authentication")

            # event.type
            if msg["level"] in ["err", "error"] or "error:" in msg_lower:
                event_type.add("error")
            if "starting" in msg_lower:
                event_type.add("start")
            if "failed password" in msg_lower:
                event_category.add("authentication")
                event_type.add("denied")
                event_type.add("access")
                event_outcome = "failure"
            if "accepted password" in msg_lower:
                event_category.add("authentication")
                event_type.add("allowed")
                event_type.add("access")
                event_outcome = "success"

            # Create the Event object
            event = Event(
                category=event_category,
                created=timestamp,
                dataset="/var/log/messages",
                message=msg["message"],
                original=msg["raw_line"],
                outcome=event_outcome,
                sequence=index,
                type=event_type,
            )

            # TODO: log.* fields
            #   msg["logger"] => "syslog", "auth", "kernel"
            #   msg["level"] => "notice", "err", "info"

            # TODO: add file.* metadata, e.g. /var/log/messages

            # TODO: pull more information out of messages
            #   related.ip
            #   related.ports

            # TODO: extract PID, e.g. "sshd[7050]"

            # Add hostname to related.hosts
            dev.related.hosts.add(msg["hostname"])

            if " from " in msg["message"]:
                match = re.search(
                    r" from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ",
                    msg["message"],
                    re.IGNORECASE | re.ASCII,
                )

                if match:
                    for m in match.groups():
                        if utils.is_ip(m):
                            dev.related.ip.add(m)

            dev.store("event", event, append=True)


class ProcCmdlineParser(NixParserBase):
    """
    Parse output of ``/proc/cmdline`` (the kernel's startup command
    line arguments). Parses returns dict with the arguments as
    key-value pairs.
    """

    file = PurePosixPath("/proc/cmdline")

    @classmethod
    def parse(cls, to_parse: str) -> dict[str, bool | str]:
        results = {}

        for arg in to_parse.strip().split():
            key, _, value = arg.partition("=")
            # e.g. a single value like "rw" or "quiet"
            # would result in "rw": True
            if not value:
                results[key] = True
            else:
                results[key] = value

        return results

    @classmethod
    def process(cls, to_process: dict[str, bool | str], dev: DeviceData) -> None:
        # TODO: do more with this data?
        dev.extra[str(cls.file)] = to_process


class ProcCpuinfoParser(NixParserBase):
    """
    Parse output of ``/proc/cpuinfo`` and return
    dict with the formatted data.
    """

    file = PurePosixPath("/proc/cpuinfo")

    @classmethod
    def parse(cls, to_parse: str) -> dict[str, list | str]:
        results = {}

        proc_cpuinfo = to_parse.replace("\r\n", "\n")

        # split into by groups of lines
        for group in proc_cpuinfo.strip().split("\n\n"):
            group = group.strip()
            processor = {}

            for line in group.splitlines():
                key, _, value = line.partition(":")
                key = key.strip().replace(" ", "_").lower()
                value = value.strip()

                if group.startswith("processor"):
                    processor[key] = value
                else:
                    results[key] = value

            if processor:
                if "processors" not in results:
                    results["processors"] = []
                results["processors"].append(processor)

        return results

    @classmethod
    def process(cls, to_process: dict[str, list | str], dev: DeviceData) -> None:
        cpu_model = ""
        cpu_full = ""
        cpu_description = ""

        if to_process.get("platform"):
            cpu_full += to_process["platform"] + " "
            cpu_description += to_process["platform"] + " "
        elif to_process.get("model"):
            cpu_full += to_process["model"] + " "
            cpu_description += to_process["model"] + " "

        if to_process.get("processors"):
            proc = to_process["processors"][0]
            if proc.get("cpu"):
                cpu_model = proc["cpu"] + " "
                cpu_full += proc["cpu"] + " "
                cpu_description += proc["cpu"] + " "
            elif to_process.get("model"):
                cpu_model = to_process["model"] + " "

            if proc.get("clock"):
                cpu_description += proc["clock"] + " "

            if proc.get("revision"):
                cpu_description += f"revision {proc['revision']}"

        if cpu_model:
            dev.hardware.cpu.model = cpu_model.strip()
        if cpu_full:
            dev.hardware.cpu.full = cpu_full.strip()
        if cpu_description:
            dev.hardware.cpu.description = cpu_description.strip()


class ProcMeminfoParser(NixParserBase):
    """
    Parse output of ``/proc/meminfo`` and return
    dict with the formatted data, with integer
    values in bytes.
    """

    file = PurePosixPath("/proc/meminfo")

    @classmethod
    def parse(cls, to_parse: str) -> dict[str, int]:
        results = {}

        for line in to_parse.splitlines():
            key, _, value = line.partition(":")

            key = utils.convert_to_snake_case(key)
            key = utils.clean_replace(key, "_", "()")
            key = key.strip("_").replace("__", "_")

            # Convert size strings like "24M" or "42" into a raw integer
            # NOTE: while this says "kB", it's actually kibibytes
            # Therefore, we set binary=True for size parsing
            value = humanfriendly.parse_size(value, binary=True)

            results[key] = value

        return results

    @classmethod
    def process(cls, to_process: dict[str, int], dev: DeviceData) -> None:
        if "mem_total" in to_process:
            dev.hardware.memory_total = to_process["mem_total"]
        if "mem_free" in to_process:
            dev.hardware.memory_available = to_process["mem_free"]


class ProcModulesParser(NixParserBase):
    """
    Parse output of ``/proc/modules`` and return a list
    of the module names.
    """

    file = PurePosixPath("/proc/modules")

    @classmethod
    def parse(cls, to_parse: str) -> list[str]:
        return [line.split(" ")[0] for line in to_parse.splitlines()]

    @classmethod
    def process(cls, to_process: list[str], dev: DeviceData) -> None:
        # TODO: do more with /proc/modules data
        dev.extra[str(cls.file)] = to_process


class ProcUptimeParser(NixParserBase):
    """
    Parse ``/proc/uptime`` and return the timedelta for
    how long the system has been up for.

    Process sets ``dev.uptime``.
    """

    file = PurePosixPath("/proc/uptime")

    @classmethod
    def parse(cls, to_parse: str) -> datetime.timedelta:
        uptime = float(to_parse.strip().split(" ")[0])
        return datetime.timedelta(seconds=uptime)

    @classmethod
    def process(cls, to_process: datetime.timedelta, dev: DeviceData) -> None:
        dev.uptime = to_process


class ProcNetDevParser(NixParserBase):
    """
    Parse and process ``/proc/net/dev``
    """

    file = PurePosixPath("/proc/net/dev")

    @classmethod
    def parse(cls, to_parse: str) -> dict[str, dict[str, int]]:
        lines = _extract_lines(to_parse)

        if not lines:
            return {}

        # Inspired by https://stackoverflow.com/a/1052628
        cols_sects = lines[1].split("|")
        recv_cols = [f"recv_{c}" for c in cols_sects[1].split()]
        trans_cols = [f"trans_{c}" for c in cols_sects[2].split()]
        cols = recv_cols + trans_cols

        # keyed by interface name
        results = {}

        for line in lines[2:]:
            if line.find(":") < 0:
                continue

            iface, raw_data = line.split(":")
            if_data = {
                t[0]: int(t[1]) for t in zip(cols, raw_data.split(), strict=False)
            }

            results[iface] = if_data

        return results

    @classmethod
    def process(cls, to_process: dict[str, dict[str, int]], dev: DeviceData) -> None:
        # TODO: dev.interface
        for iface_name in to_process.keys():
            iface = dev.retrieve("interface", search={"name": iface_name})

            if not iface:
                iface = Interface(
                    name=iface_name,
                )

                if iface_name == "lo":
                    iface.type = "loopback"
                elif iface_name.startswith("eth"):
                    iface.type = "ethernet"

                dev.store("interface", iface, lookup="name")


class EtcPasswdParser(NixParserBase):
    """
    Parse ``/etc/passwd`` and return the extracted user data.

    Process adds the users to ``dev.users`` in the device data model.
    """

    file = PurePosixPath("/etc/passwd")

    @classmethod
    def parse(cls, to_parse: str) -> list[str]:
        users = []

        for line in to_parse.splitlines():
            # To read manpage: "man 5 passwd"

            # /etc/passwd contains one line for each user account,
            # with seven fields delimited by colons (“:”)
            sections = line.split(":")
            if len(sections) != 7:
                log.warning(f"Bad /etc/passwd line: {line}")
                continue

            # login name
            # optional encrypted password, "x" if in shadow file
            # numerical user ID
            # numerical group ID
            # user name or comment field
            # user home directory
            # optional user command interpreter
            #   If this field is empty, it defaults to the value /bin/sh
            user = {
                "login_name": sections[0],
                "password": sections[1] if sections[1] != "x" else "",
                "user_id": sections[2],
                "group_id": sections[3],
                "comment": sections[4],
                "home_directory": sections[5],
                "shell": sections[6],
            }

            users.append(user)

        return users

    @classmethod
    def process(cls, to_process: list[str], dev: DeviceData) -> None:
        for raw_user in to_process:
            dev.related.user.add(raw_user["login_name"])

            if raw_user["shell"]:
                dev.related.files.add(raw_user["shell"])

            user_obj = User(
                description=raw_user["comment"].strip().strip(","),
                id=raw_user["login_name"],
                name=raw_user["login_name"],
                uid=str(raw_user["user_id"]),
                gid=str(raw_user["group_id"]),
                extra={
                    "home_directory": raw_user["home_directory"],
                    "shell": raw_user["shell"],
                },
            )

            dev.store("users", user_obj, lookup="name")


class DateParser(NixParserBase):
    """
    Parse output of the ``date`` command.

    This gets timezone information, as well as baseline for what year it
    is for the purposes of timestamping logs from sources such as
    ``/var/log/messages``.
    """

    command = "date"

    @classmethod
    def parse(cls, to_parse: str) -> datetime.datetime | None:
        if not to_parse:
            return None

        return utils.parse_date(to_parse)

    @classmethod
    def process(cls, to_process: datetime.datetime, dev: DeviceData) -> None:
        if to_process.tzinfo:
            if not dev.geo.timezone:
                dev.geo.timezone = to_process.tzname()

        dev.extra["current_time"] = to_process


class EnvParser(NixParserBase):
    """
    Parse the output of the ``env`` command.

    Environment variables for current shell session
    """

    command = "env"

    @classmethod
    def parse(cls, to_parse: str) -> dict[str, str]:
        result = {}

        for line in to_parse.splitlines():
            if "=" not in line:
                log.trace(f"Skipping bad env line (missing '='): {line}")
                continue

            key, _, value = line.partition("=")

            result[key] = value

        return result

    @classmethod
    def process(cls, to_process: dict[str, str], dev: DeviceData) -> None:
        # TODO: do more with environment variables and data model
        dev.extra["env"] = to_process


# TODO: WIP. This currently extracts:
#   interface name
#   mtu
#   options (e.g. "POINTOPOINT,MULTICAST,NOARP")
#   state
#   link_type
#
# from peat.protocols.common import IPV4_RE, MAC_RE_COLON
# class IpAddrParser(NixParserBase):
#     """
#     Parse output of ``ip addr`` command.
#
#     Shows all network interfaces.
#     This is usually seen on modern Linux distributions
#     that install the ``iproute2`` package by default.
#     """
#
#     command = "ip addr"
#
#     @classmethod
#     def parse(cls, to_parse: str) -> dict[str, dict]:
#         if not to_parse:
#             return {}
#
#         interfaces =  [s.strip() for s in re.split(r"\d+: (\w+): ", to_parse) if s]
#         pairs = list(zip(interfaces[0::2], interfaces[1::2]))
#
#         if_pat = (
#             r"\<(?P<if_info>[\w,]+)\> "
#             r"mtu (?P<mtu>\d+) .* "
#             r"state (?P<state>\w+).*\s+"
#             r"link/(?P<link_type>\w+) "
#         )
#
#         all_ifs = {}
#         for if_name, if_raw in pairs:
#             print(if_name)
#             if_info = re.match(if_pat, if_raw).groupdict()
#             if_info["mtu"] = int(if_info["mtu"])
#
#             for line in if_raw.splitlines():
#                 line = line.strip()
#                 if line.startswith("link/none"):
#                     continue
#                 elif line.startswith("link/ether"):
#                     parts = line.split(" ")
#                     if_info["mac_addr"] = parts[1]
#                     if_info["mac_bcast"] = parts[3]
#                 elif line.startswith("link/"):
#                     parts = line.split(" ")
#                     # TODO: this is not the IP, usually 0.0.0.0
#                     if_info["ip_addr"] = parts[1]
#                     if_info["ip_bcast"] = parts[3]
#                 elif line.startswith("inet6"):
#                     inet6_pat = r"inet6 ([0-9a-fA-F:]+)/(\d{1,2})"
#                     pass
#                 elif line.startswith("inet"):
#                     inet4_pat = r"inet " + IPV4_RE + r"/(\d{1,2})"
#                     pass
#
#             all_ifs[if_name] = if_info
#
#         return False
#
#     @classmethod
#     def process(cls, to_process: dict[str, dict], dev: DeviceData) -> None:
#         pass


class IfconfigParser(NixParserBase):
    """
    Parse output of ``ifconfig -a`` command.

    Shows all network interfaces.
    This is usually seen on older Linux distributions
    that install the ``net-utils`` package by default,
    as well as BusyBox systems.
    """

    command = "ifconfig -a"

    @classmethod
    def parse(cls, to_parse: str) -> dict[str, dict]:
        if not to_parse:
            return {}

        # The interface parsing code below is a heavily adapted version of
        # @KnightWhoSayNi's ifconfig-parser library (MIT-licensed).
        # https://github.com/KnightWhoSayNi/ifconfig-parser
        # TODO: make the regex objects class attributes

        iface_re = re.compile(
            r"(?P<name>[a-zA-Z0-9:._-]+)\s+Link (type|encap):(?P<type>\S+\s?\S+\s?\S+)",
            re.IGNORECASE | re.ASCII,
        )
        mac_re = re.compile(
            r"(\s+HWaddr\s+\b(?P<mac>[0-9A-Fa-f:?]+))?\s+Queue:(?P<queue>\w+)",
            re.IGNORECASE | re.ASCII,
        )
        cap_re = re.compile(
            r"capabilities: (?P<capabilities>[\w ]+)\s", re.IGNORECASE | re.ASCII
        )
        ip_re = re.compile(
            r"\s+inet (?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
            r"\s+mask (?P<subnet_mask>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
            r"(\s+broadcast (?P<broadcast>(?:[0-9]{1,3}\.){3}[0-9]{1,3}))?"
            r"(\s+peer (?P<peer>(?:[0-9]{1,3}\.){3}[0-9]{1,3}))?",
            re.IGNORECASE | re.ASCII,
        )
        flags_re = re.compile(
            r"\W+(?P<flags>(?:\w+\s)+)(?:\s+)?"
            r"\s+MTU:(?P<mtu>\d+)"
            r"\s+metric:(?P<metric>[0-9]+)"
            r"\s+VR:(?P<vr>[0-9]+)\s+ifindex:(?P<ifindex>[0-9]+)",
            re.IGNORECASE | re.ASCII,
        )
        rx_re = re.compile(
            r"\s+RX packets:(?P<rx_packets>[0-9]+)"
            r"\s+mcast:(?P<rx_multicast>[0-9]+)"
            r"\s+errors:(?P<rx_errors>[0-9]+)"
            r"\s+dropped:(?P<rx_dropped>[0-9]+)",
            re.IGNORECASE | re.ASCII,
        )
        tx_re = re.compile(
            r"TX packets:(?P<tx_packets>[0-9]+)"
            r"\s+mcast:(?P<tx_multicast>[0-9]+)"
            r"\s+errors:(?P<tx_errors>[0-9]+)"
            r"\s+collisions:(?P<collisions>[0-9]+)"
            r"\s+unsupported proto:(?P<unsupported_protocol>[0-9]+)",
            re.IGNORECASE | re.ASCII,
        )
        bytes_re = re.compile(
            r"\s+RX bytes:(?P<rx_bytes>\w+)\s+TX bytes:(?P<tx_bytes>\w+)",
            re.IGNORECASE | re.ASCII,
        )

        re_vxworks = [iface_re, mac_re, cap_re, ip_re, flags_re, rx_re, tx_re, bytes_re]

        network_interfaces = re.finditer(iface_re, to_parse)
        positions = []

        while True:
            try:
                pos = next(network_interfaces)
                positions.append(max(pos.start() - 1, 0))
            except StopIteration:
                break

        if positions:
            positions.append(len(to_parse))

        if not positions:
            log.warning("ifconfig parsing failed: couldn't find interface positions")
            return {}

        all_interfaces = {}

        for chunk_start, chunk_end in itertools.pairwise(positions):
            chunk = to_parse[chunk_start:chunk_end]
            interface = {}

            for pattern in re_vxworks:
                match = re.search(pattern, chunk.replace("\t", "\n"))
                if match:
                    details = match.groupdict()
                    for k, v in details.items():
                        if isinstance(v, str):
                            interface[k] = v.strip()

            for key, value in interface.items():
                if key in ["capabilities", "flags"]:
                    interface[key] = [x.strip() for x in value.split(" ") if x.strip()]
                elif key[:2] in ["tx", "rx"] or key in [
                    "collisions",
                    "unsupported_protocol",
                ]:
                    try:
                        # Convert size strings like "24M" or "42" into a raw integer
                        interface[key] = humanfriendly.parse_size(value)
                    except Exception:
                        pass
                elif key in ["mtu", "metric", "vr", "ifindex"]:
                    try:
                        interface[key] = int(value)
                    except Exception:
                        pass

            if interface:
                all_interfaces[interface["name"]] = interface

        if not all_interfaces:
            log.warning("ifconfig parsing failed: no interfaces found")

        return all_interfaces

    @classmethod
    def process(cls, to_process: dict[str, dict], dev: DeviceData) -> None:
        for name, if_dict in to_process.items():
            iface = Interface(
                name=name,
                id=str(if_dict.get("ifindex", "")),
                mtu=if_dict.get("mtu"),
                ip=if_dict.get("ip", ""),
                mac=if_dict.get("mac", "").upper(),
                subnet_mask=if_dict.get("subnet_mask", ""),
            )

            # Interface type
            if_type = if_dict["type"].lower().replace(" ", "_")
            if "loopback" in if_type:
                iface.type = "loopback"
            else:
                iface.type = if_type

            # "fei0" is primary. "fei1" is secondary
            if name == "fei0":
                iface.description.description = "Primary interface"
            elif name == "fei1":
                iface.description.description = "Secondary interface"

            # Peer for Point to Point interfaces
            if if_dict.get("peer"):
                dev.related.ip.add(if_dict["peer"])

            # ifconfig flags reference:
            # https://docs.oracle.com/cd/E19253-01/816-5166/ifconfig-1m/index.html
            if "RUNNING" in if_dict["flags"]:
                iface.connected = True
            if "UP" in if_dict["flags"]:
                iface.enabled = True
            elif "DOWN" in if_dict["flags"]:
                iface.enabled = False

            for key, value in if_dict.items():
                if value is None:
                    continue

                # Add various keys to "extra" field
                if key in [
                    "queue",
                    "flags",
                    "capabilities",
                    "peer",
                    "metric",
                    "ifindex",
                    "vr",
                    "broadcast",
                ]:
                    iface.extra[key] = value
                # Store statistics in a "statistics" sub-dict in "extra"
                elif key[:2] in ["tx", "rx"] or key in [
                    "collisions",
                    "unsupported_protocol",
                ]:
                    if not iface.extra.get("statistics"):
                        iface.extra["statistics"] = defaultdict(dict)
                    if key[:2] == "tx":
                        iface.extra["statistics"]["transmitted"][key[3:]] = value
                    elif key[:2] == "rx":
                        iface.extra["statistics"]["received"][key[3:]] = value
                    else:
                        iface.extra["statistics"][key] = value

            dev.store("interface", iface, lookup=["name", "ip"])


class ArpParser(NixParserBase):
    """
    Parse and process output of ``arp -a`` command.

    ARP table, shows all known network devices.
    """

    command = "arp -a"

    @classmethod
    def parse(cls, to_parse: str) -> list[str]:
        return _extract_lines(to_parse)

    @classmethod
    def process(cls, to_process: list[str], dev: DeviceData) -> None:
        for line in to_process:
            parts = [x.strip() for x in line.split(" ") if x.strip()]

            for part in parts:
                # "(192.0.2.1)"
                part = utils.clean_replace(part, "", "()").strip()

                # IP address
                if utils.is_ip(part):
                    dev.related.ip.add(part)
                # MAC address
                elif part.count(":") == 5:
                    dev.related.mac.add(part.upper())


class SshdConfigParser(NixParserBase):
    """
    Parse and process ``/etc/ssh/sshd_config``.

    Cleanup the sshd_config to just lines with configs,
    excluding empty lines and comments.
    """

    file = PurePosixPath("/etc/ssh/sshd_config")

    @classmethod
    def parse(cls, to_parse: str) -> list[str]:
        return [line for line in _extract_lines(to_parse) if not line.startswith("#")]

    @classmethod
    def process(cls, to_process: list[str], dev: DeviceData) -> None:  # noqa: ARG003
        # TODO: dev.related.port
        # TODO: dev.services
        return None


class HostnameParser(NixParserBase):
    """
    Set dev.hostname to the output of the ``hostname`` command
    """

    command = "hostname"

    @classmethod
    def parse(cls, to_parse: str) -> str:
        return to_parse.strip()

    @classmethod
    def process(cls, to_process: str, dev: DeviceData) -> None:
        if to_process:
            dev.hostname = to_process


class LsRecursiveParser(NixParserBase):
    """
    Recursive ls of full file system.
    This assumes BusyBox's ``ls`` output.
    Other system's output may differ.

    Command: ``ls -lenAR /etc /boot /var/log /root /sysopt /sbin /pkg /bin /common /opt /lib``

    Args:

    - l: one column output
    - e: full date and time
    - n: numeric UIDs and GIDs instead of names
    - A: include files that start with ``.`` and exclude the ``.`` and ``..`` "files".
    - R: recurse

    """

    # TODO: do a full recursive in certain circumstances
    # command = "ls -lenAR /"
    #  /usr
    command = (
        "ls -lenAR /etc /boot /var/log /root /sysopt /sbin /pkg /bin /common /opt /lib"
    )

    @classmethod
    def parse(cls, to_parse: str) -> list[dict]:
        if not to_parse:
            return []

        # NOTE: humanfriendly split_paragraphs assumes "\n\n"
        # we can get CRLF (\r\n) back, so need to fix that
        if "\r\n" in to_parse:
            to_parse = to_parse.replace("\r\n", "\n")

        results = []

        for chunk in split_paragraphs(to_parse):
            lines = _extract_lines(chunk)

            # The first line of the chunk is the absolute
            # directory path, followed by a ":".
            # Example: "/etc/network:"
            par_dir = lines[0].rstrip(":")
            if not par_dir.endswith("/"):
                par_dir += "/"
            dir_path = PurePosixPath(par_dir)

            # TODO: combine with parsing code in peat/protocols/ftp.py
            # TODO: refer to this: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ls.html
            # and incorporate parsing code from the new Firewall module.

            # The lines following are the items in that directory
            #
            # Col 1: File type and permissions: type+user+group+world
            # Col 2: Number of hard links
            # Col 3: UID (numeric)
            # Col 4: GID (numeric)
            # Col 5: file size in bytes
            # Col 6-9: modification date and time
            # Col 10: name
            #
            # Standard file example:
            # "-rw-r--r--    1 0        0              194 Wed Jan 01 00:00:00 1970 interfaces"
            for line in lines[1:]:
                # Exclude failures to read files in /proc
                # "ls: /proc/1045/exe: cannot read link: No such file or directory"
                if "cannot read link" in line or "No such file or directory" in line:
                    continue

                parts = line.split()

                # File type
                raw_type = parts[0][0]

                # Add +1 offset for device files
                offset = 0
                if raw_type in ["b", "c"]:
                    offset = 1

                file_info = {
                    "type": raw_type,
                    "perms": parts[0][1:],
                    "uid": parts[2],
                    "gid": parts[3],
                    "mtime": utils.parse_date(
                        " ".join(parts[offset + 5 : offset + 10])
                    ),
                    "name": parts[offset + 10],
                    "parent": dir_path,
                }

                # Device files (in /dev) don't have a size.
                # Instead, they have two numbers. These represent
                # the major and minor device number for that device.
                # The major number is the driver associated with the device.
                # The minor number is only used by the driver specified by the major number.
                #
                # Example:
                # "crw-------    1 0        0           5,   1 Thu Jan  1 00:00:14 1970 console"  # noqa: E501
                #
                # b: block device
                # c: character device
                if raw_type in ["b", "c"]:
                    file_info["device_driver_major"] = int(parts[4].strip(","))
                    file_info["device_driver_minor"] = int(parts[5])
                else:
                    file_info["size"] = int(parts[4])

                # If symlink, save what it points to
                # NOTE: if ls fails to read the target, such as with
                # /proc/*/exe, then there won't be a target specified
                # (and thus no "->" string).
                if raw_type == "l" and "->" in line:
                    raw_target = parts[offset + 12]

                    # Direct: addgroup -> busybox
                    if "/" not in raw_target:
                        file_info["symlink_target"] = PurePosixPath(
                            dir_path, raw_target
                        )
                    # Relative: core -> ../proc/kcore
                    elif raw_target.startswith(".."):
                        # Convert "/dev/../proc/kcore" -> "/proc/kcore"
                        norm = os.path.normpath(par_dir + raw_target)
                        file_info["symlink_target"] = PurePosixPath(norm)
                    # Absolute: exe -> /usr/sbin/webserver
                    elif raw_target.startswith("/"):
                        file_info["symlink_target"] = PurePosixPath(raw_target)
                    else:
                        log.warning(f"Weird symlink: {raw_target}")
                        file_info["symlink_target"] = None

                results.append(file_info)

        return results

    @classmethod
    def process(cls, to_process: list[dict], dev: DeviceData) -> None:
        for f_data in to_process:
            # File type
            # -: regular file
            # d: directory
            # l: symbolic link
            # p: named pipe
            # c: character device
            # b: block device
            # s: socket
            if f_data["type"] == "d":
                f_type = "dir"
            elif f_data["type"] == "l":
                f_type = "symlink"
            else:
                f_type = "file"

            # Create path object from parent + name
            path = PurePosixPath(f_data["parent"], f_data["name"])

            # Add absolute path to host.related.files
            if f_type != "dir":
                dev.related.files.add(str(path))

            # TODO: add device_driver_major and device_driver_minor to file.extra
            file_obj = File(
                device=dev.get_comm_id(),
                directory=str(f_data["parent"]),
                extension=path.suffix if f_type == "file" else "",
                gid=int(f_data["gid"]),  # typecast to make sure it's an int
                peat_module=dev._module.__name__ if dev._module else "",
                path=path,
                mode=utils.file_perms_to_octal(f_data["perms"]),
                mtime=f_data["mtime"],
                name=f_data["name"],
                type=f_type,
                uid=int(f_data["uid"]),  # typecast to make sure it's an int
            )

            if file_obj.type == "file" and "size" in f_data:
                file_obj.size = f_data["size"]

            if file_obj.type == "symlink" and f_data.get("symlink_target"):
                file_obj.target_path = f_data["symlink_target"]

            if file_obj.uid == "0":
                file_obj.owner = "root"

            if file_obj.gid == "0":
                file_obj.group = "root"

            dev.files.append(file_obj)  # add to data model


class NetstatSocketsVxWorksParser(NixParserBase):
    """
    Parse output of "netstat -anP" command on VxWorks.

        -a: more sockets
        -n: numeric names instead of hostnames resolved
        -P: show the TID (task ID) that owns the socket

    """

    command = "netstat -anP"

    @classmethod
    def parse(cls, to_parse: str) -> list[str]:
        lines = _extract_lines(to_parse)
        sockets = []

        for line in lines:
            if line.startswith("INET") or "Recv-Q" in line:
                continue
            parts = line.split()

            if len(parts) < 6 or len(parts) > 7:
                log.warning(f"Bad netstat line with length {len(line)}: '{line}'")
                continue

            skt = {
                "protocol": parts[0],  # Prot
                "recv_q": int(parts[1]),  # Recv-Q
                "send_q": int(parts[2]),  # Send-Q
                "local_address": parts[3].rpartition(".")[0],  # Local Address
                "local_port": parts[3].rpartition(".")[2],
                "foreign_address": parts[4].rpartition(".")[0],  # Foreign Address
                "foreign_port": parts[4].rpartition(".")[2],
                # UDP and other non-TCP sockets don't have "STATE"
                "state": parts[5] if parts[0] == "TCP" else "",  # State
                # The TID is always the last part
                "tid": parts[-1],  # TID
            }
            sockets.append(skt)

        return sockets

    @classmethod
    def process(cls, to_process: list[dict], dev: DeviceData) -> None:
        for skt in to_process:
            # Use local_address to resolve the interface
            #   if interface doesn't exist, create it

            # TODO: add "connections" to data model

            # protocol "115" seems to be some sort of default
            # TCP and UDP
            # TODO: ipv6?
            if (
                skt["foreign_address"] == "0.0.0.0"
                and skt["foreign_port"] == "*"
                and skt["local_port"] != "*"
            ):
                transport = ""
                if not skt["protocol"].isdigit():
                    transport = skt["protocol"].lower()

                svc = Service(
                    port=int(skt["local_port"]),
                    transport=transport,
                    status="open",
                    listen_address=skt["local_address"],
                    process_pid=int(skt["tid"], 16),  # as integer
                    extra={
                        "receive_queue": skt["recv_q"],
                        "send_queue": skt["send_q"],
                        "task_id": skt["tid"],  # TID as hex
                    },
                )

                # TODO: associate with all interfaces
                if skt["local_address"] == "0.0.0.0":
                    # listening on all interfaces
                    pass
                elif skt["local_address"] == "127.0.0.1":
                    # listening on localhost
                    dev.store(
                        "service",
                        svc,
                        lookup="port",
                        interface_lookup={"ip": "127.0.0.1"},
                    )
                else:
                    log.warning(
                        f"netstat: unknown local_address '{skt['local_address']}'"
                    )

                # TODO: dev.store service

            # Add IPs and ports to related.ip and related.ports
            for key in ["local", "foreign"]:
                addr = skt[f"{key}_address"]
                if addr != "0.0.0.0" and utils.is_ip(addr):
                    dev.related.ip.add(addr)

                port = skt[f"{key}_port"]
                try:
                    dev.related.ports.add(int(port))
                except ValueError:
                    pass


def _extract_lines(data: str, exclude: str = "") -> list[str]:
    """
    Return list of lines that aren't empty and don't have excluded string.
    """
    if not data:
        return []

    lines = []

    for line in data.strip().splitlines():
        line = line.strip()
        if not line or (exclude and exclude in line):
            continue
        lines.append(line)

    return lines


def convert_filename(to_convert: str) -> str:
    """
    Take command string or file path and make it into
    something that can be saved to disk.
    """
    for pat in [" --", " -", " ", "/", ";", "{", "}"]:
        to_convert = to_convert.replace(pat, "_").replace("__", "_")
    to_convert = to_convert.replace("__", "_")
    to_convert = to_convert.strip().strip("_")
    return to_convert
