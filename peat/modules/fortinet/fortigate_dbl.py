"""
Parsers and processors for Fortigate "Debug Logs".

"Debug logs" are diagnostic data dumps that combine configuration information,
event logs, system status, system state, and other information in a
single large file with a custom format.
"""

import functools
import re
from datetime import timedelta
from pathlib import PurePosixPath

import humanfriendly

from peat import DeviceData, Event, File, Interface, consts, log, utils
from peat.parsing.arm_cpuid import ARM_CPU_IDS
from peat.protocols.common import IPV4_RE, MAC_RE_COLON


def parse_fg_debug_log(raw_data: str) -> dict[str, list[str]]:
    """
    Parses a raw Fortigate "Debug log" into a dict.
    """
    parsed_data = {}
    current_section = None

    for line in raw_data.splitlines():
        line = line.strip()
        if not line:  # remove empty strings
            continue

        # Detect section headers (lines that start with ###)
        section_match = re.match(r"^### (.+)$", line)
        if section_match:
            current_section = section_match.group(1)
            parsed_data[current_section] = []
            continue

        # Add data to the current section
        if current_section:
            parsed_data[current_section].append(line)

    return parsed_data


def extract_ips(lines: list[str]) -> set[str]:
    ip_addrs = set()

    for line in lines:
        # extract IPs from anywhere in the line
        for ip in re.findall(IPV4_RE, line):
            if utils.is_ip(ip) and ip.count("255") <= 1 and ip not in ["255.0.0.0", "0.0.0.0"]:
                ip_addrs.add(ip)

    return ip_addrs


def extract_macs(lines: list[str]) -> set[str]:
    macs = set()

    for line in lines:
        for mac in re.findall(MAC_RE_COLON, line):
            if utils.is_mac(mac) and mac != "00:00:00:00:00:00":
                macs.add(mac.upper())

    return macs


def process_fg_system_status(raw_status: list[str], dev: DeviceData) -> None:
    status = {}
    for line in raw_status:
        key, _, value = line.partition(":")
        key = utils.clean_replace(key, "_", " -/").lower()
        status[key] = value.strip()

    # Version
    if status.get("version"):
        # TODO: clean this up a bit
        dev.firmware.version = status["version"]

    # Serial number
    if status.get("serial_number"):
        dev.serial_number = status.pop("serial_number")

    # BIOS version
    if status.get("bios_version"):
        dev.boot_firmware.version = status["bios_version"]

    # Part number
    if status.get("system_part_number"):
        dev.part_number = status.pop("system_part_number")

    # Hostname
    if status.get("hostname"):
        dev.hostname = status["hostname"]
        dev.related.hosts.add(status["hostname"])

    # Device uptime
    if status.get("cluster_uptime"):
        # "29 minutes, 23 seconds"
        total_seconds = 0
        for chunk in status["cluster_uptime"].split(","):
            total_seconds += humanfriendly.parse_timespan(chunk.strip())

        dev.uptime = timedelta(seconds=total_seconds)

    dev.extra["system_status"] = status


def process_fg_crashlog(crashlog: list[str], dev: DeviceData) -> None:
    for line in crashlog:
        try:
            # Attempt to convert first part of line to an integer. If this
            # fails, then it's not a valid line.
            parts = line.split(" ")
            sequence = int(parts[0].partition(":")[0])
            msg = " ".join(parts[3:])

            event = Event(
                category={"host", "process"},
                created=utils.parse_date(f"{parts[1]} {parts[2]}"),
                dataset="crashlog",
                message=msg,
                original=line,
                sequence=sequence,
            )
            dev.store("event", event, lookup="message")

            # e.g. "/bin/sflowd", /bin/getty
            for path in re.findall(r"(/[\w/.-]+)", msg):
                dev.related.files.add(path)

            # TODO: associate process name and PID with Service
            # "process_id=1028, process_name="httpsd""
            if "process_name" in line:
                # pid = re.search(r"process_id=(\d+)", msg).group(1)
                pname = re.search(r'process_name="([^"]+)"', msg).group(1)
                dev.related.process.add(pname)
        except Exception as ex:
            log.trace3(f"Skipping bad Fortigate crashlog line: '{line}' (exception: {ex})")
            continue


def parse_fg_ls(ls_output: list[str], ls_command: str) -> list[dict]:
    """
    Parses the output of the "ls" command from the Fortigate debug log.

    Returns:
        The parsed ls entries, as a list of dicts with file information.
        Below is an example of a file information dict:

        .. code-block:: python

           {
               "type": "s",
               "perms": "rwxr-xr-x",
               "hard_link_count": 1,
               "uid": 0,
               "gid": 0,
               "mtime": "2025-09-09 00:00:00",
               "size": 0,
               "name": "example_filename",
               "link_target": null,
               "parent": "/tmp",
           }

    """

    # NOTE: Similar 'ls' command parsing code in PEAT:
    #   peat.parsing.command_parsers.LsRecursiveParser
    #   peat.protocols.ftp.FTP.dir()

    dir_path = ls_command.rsplit(maxsplit=1)[-1]

    # https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ls.html
    # hard links: https://unix.stackexchange.com/a/43047
    ls_exp = (
        r"(?P<mode>[a-zA-Z\-]{9,11})\s+"
        r"(?P<num_links>\d+)\b\s+"  # number of hard links
        r"(?P<uid>\d+)\b\s+"
        r"(?P<gid>\d+)\b\s+"
        r"(?P<mtime>[a-zA-Z0-9 :]+)\b\s+"
        r"(?P<size>\d+)\b\s+"
        r"(?P<filename>[^ ]+)"
        r"(?: \-> )?(?P<link_target>[^ ]+)?$"
    )
    results = []

    for line in ls_output:
        match = re.match(ls_exp, line)
        if not match:
            log.warning(f"Bad Fortigate 'ls' line: '{line}'")
            continue

        res = match.groupdict()

        # https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ls.html
        # d: Directory
        # b: Block special file
        # c: Character special file
        # l (ell): Symbolic link
        # p: FIFO
        # -: Regular file
        # s: sticky bit
        file_info = {
            "type": res["mode"][0],  # "d", "l", "-"
            "perms": res["mode"][1:],
            "hard_link_count": int(res["num_links"]),
            "uid": int(res["uid"]),
            "gid": int(res["gid"]),
            "mtime": utils.parse_date(res["mtime"]),
            "size": int(res["size"]),
            "name": res["filename"],
            "path": str(PurePosixPath(dir_path, res["filename"])),
            "parent": dir_path,
        }

        if res.get("link_target"):
            file_info["link_target"] = res["link_target"]

        results.append(file_info)

    return results


def process_fg_ls(ls_output: list[str], ls_command: str, dev: DeviceData) -> None:
    """
    Process the parsed results of the "ls" command into the PEAT data model.
    """
    parse_results = parse_fg_ls(ls_output, ls_command)

    dir_name = ls_command.rsplit(maxsplit=1)[-1].replace("/", "_").strip("_")
    dev.write_file(parse_results, f"file_list_{dir_name}.json")

    for file in parse_results:
        # File type
        # -: regular file
        # d: directory
        # l: symbolic link
        # p: named pipe
        # c: character device
        # b: block device
        # s: socket (or setuid)
        if file["type"] == "d":
            f_type = "dir"
        elif file["type"] == "l":
            f_type = "symlink"
        else:
            f_type = "file"

        path = PurePosixPath(file["path"])

        if file["type"] != "d":
            dev.related.files.add(file["path"])

        file_obj = File(
            device=dev.name if dev.name else dev.get_comm_id(),
            directory=file["parent"],
            extension=path.suffix if f_type != "dir" else "",
            gid=file["gid"],
            peat_module=dev._module.__name__ if dev._module else "",
            path=path,
            mode=utils.file_perms_to_octal(file["perms"]),
            mtime=file["mtime"],
            name=file["name"],
            size=file["size"],
            type=f_type,
            uid=file["uid"],
        )

        if file.get("link_target"):
            file_obj.target_path = PurePosixPath(file["link_target"])
            dev.related.files.add(file["link_target"])

        if file["uid"] == 0:
            file_obj.owner = "root"

        if file["gid"] == 0:
            file_obj.group = "root"

        # Don't deduplicate, there are multiple instances of files
        # for example, there are 5 instances of /tmp/KEY-FILE, one of
        # which is a symlink.
        dev.files.append(file_obj)


def parse_fg_hardware_cpu(lines: list[str]) -> dict[str, str | int | list[str]]:
    """
    Parse hardware information from the "get hardware cpu" debug log section.
    """
    # CPUID
    cpu = {}
    p_count = 0

    for line in lines:
        key, _, value = line.replace("\t", "").partition(": ")
        key = key.strip().lower()
        value = value.strip()

        if key == "processor":
            p_count += 1

        # Don't parse more than the first core, for simplicity
        # TODO: handle cases with multiple processors...unlikely
        if p_count > 1:
            continue

        if key == "cpu frequency":
            cpu["frequency"] = value.lower()
        elif key == "model name":
            cpu["model_string"] = value
            if value.startswith("ARM"):
                cpu["architecture"] = value.split()[0].lower()
        elif key == "cpu implementer":
            cpu["implementer_id"] = value.lower()
        elif key == "cpu part":
            cpu["part_id"] = value.lower()
        elif key == "features":
            cpu["features"] = value.split()

    if cpu.get("implementer_id"):
        impl = ARM_CPU_IDS.get(cpu["implementer_id"])
        if impl:
            cpu["vendor"] = impl["name"]
            if cpu.get("part_id") and impl["parts"].get(cpu["part_id"]):
                cpu["part"] = impl["parts"][cpu["part_id"]]

    cpu["processor_count"] = p_count

    return cpu


def process_fg_hardware_cpu(lines: list[str], dev: DeviceData) -> None:
    """
    Process parsed hardware information from the "get hardware cpu"
    debug log section into the PEAT data model.
    """
    cpu = parse_fg_hardware_cpu(lines)

    if cpu.get("vendor"):
        dev.hardware.cpu.vendor.name = cpu["vendor"]
    if cpu.get("part"):
        dev.hardware.cpu.model = cpu["part"]
    if cpu.get("model_string"):
        dev.hardware.cpu.product = cpu["model_string"]

    dev.hardware.cpu.description = f"{cpu['processor_count']} cores"
    if cpu.get("frequency"):
        dev.hardware.cpu.description += f", {cpu['frequency']}"

    if cpu.get("architecture"):
        dev.architecture = cpu["architecture"]


def parse_fg_hardware_memory(lines: list[str]) -> dict:
    """
    Parse hardware information from the "get hardware memory" debug log section.
    """
    raw = {}
    for line in lines:
        parts = line.split()
        raw[parts[0].replace(":", "").strip()] = {
            "count": int(parts[1]),
            "unit": parts[2],
            "bytes": humanfriendly.parse_size(f"{parts[1]} {parts[2]}"),
        }
    return raw


def process_fg_hardware_memory(lines: list[str], dev: DeviceData) -> None:
    mem = parse_fg_hardware_memory(lines)

    if mem.get("MemTotal"):
        dev.hardware.memory_total = mem["MemTotal"]["bytes"]
    if mem.get("MemFree"):
        dev.hardware.memory_available = mem["MemFree"]["bytes"]
    if mem.get("MemTotal") and mem.get("MemFree"):
        dev.hardware.memory_usage = mem["MemTotal"]["bytes"] - mem["MemFree"]["bytes"]


def process_fg_top(lines: list[str], dev: DeviceData) -> None:
    # TODO: extract uptime
    # "Run Time:  0 days, 0 hours and 31 minutes"
    for line in lines[2:]:
        dev.related.process.add(line.split()[0])


def process_fg_sys_flash_list(lines: list[str], dev: DeviceData) -> None:
    #   Image build timestamp
    #   backup firmware version
    #   storage space
    dev.extra["flash_images"] = lines

    for line in lines:
        # "Image build at Sep  9 2025 00:00:00 for b1234"
        if line.startswith("Image build"):
            res = re.search(
                r"(?P<timestamp>\b\w{3,5}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\b)\s+for\s+b(?P<build>\w+)",
                line,
                re.ASCII,
            )
            if res:
                if not dev.firmware.revision:
                    dev.firmware.revision = res.groupdict()["build"]
                if not dev.firmware.release_date:
                    dev.firmware.release_date = utils.parse_date(res.groupdict()["timestamp"])


def process_fg_interfaces(db_log: dict[str, list[str]], dev: DeviceData) -> None:
    log.debug("Processing Fortigate interface information from debug log")

    # Interface objects, keyed by device name, e.g. "port5"
    # This is updated as various sections of debug log are parsed
    # When all sections are parsed, interfaces are added to data model
    ifaces = {}  # type: dict[str, Interface]

    # "diagnose sys ha dump-by device"
    if db_log.get("diagnose sys ha dump-by device"):
        # "phydev= 0, mac=xx:xx:xx:xx:xx:xx, link_ok/o=0/0, devname='dmz'",
        for line in db_log["diagnose sys ha dump-by device"]:
            if not line.startswith("phydev"):
                continue
            match = re.match(
                r"phydev=\s*(?P<phydev>\d+),\s+mac=(?P<mac>[\w:]+),\s+.*\s+devname='(?P<devname>\w+)'",
                line,
            )
            if match:
                devname = match.groupdict()["devname"]
                mac = match.groupdict()["mac"].upper()

                # TODO: dev.retrieve() any existing interface
                ifaces[devname] = Interface(
                    name=devname,
                    mac=mac,
                    id=match.groupdict()["phydev"],
                )
                dev.related.mac.add(mac)

    # TODO: "diagnose sys ha dump-by debug-zone"
    # This is less useful, not sure if worth parsing
    # Maybe only parse if "dump-by device" isn't present
    # if db_log.get("diagnose sys ha dump-by debug-zone"):
    #     pass

    # "get hardware nic lan", etc.
    nic_keys = [k.split(" ")[-1] for k in db_log.keys() if k.startswith("get hardware nic")]

    for nic in nic_keys:
        # Some of the virtual interfaces, e.g. "npu0_vlink1",
        # won't be in the "diagnose" command outputs above.
        if nic not in ifaces:
            ifaces[nic] = Interface(name=nic)

        # e.g.: "get hardware nic lan"
        log_entry = f"get hardware nic {nic}"
        if db_log.get(log_entry) and len(db_log[log_entry]) > 1:
            info = {}

            for line in db_log[log_entry]:
                if "Command fail" in line:
                    break
                if line[0] in ["=", "["] or line[-1] == ":":
                    continue

                match = re.match(r"(.+)\b\s{2,}:?(.+)$", line)
                if match:
                    info[match.groups()[0].lower()] = match.groups()[1]

            if info.get("description"):
                ifaces[nic].description.description = info["description"]

            if info.get("current_hwaddr") and utils.is_mac(info["current_hwaddr"]):
                ifaces[nic].mac = info["current_hwaddr"].upper()
                dev.related.mac.add(info["current_hwaddr"].upper())

            if info.get("permanent_hwaddr") and utils.is_mac(info["permanent_hwaddr"]):
                ifaces[nic].hardware_mac = info["permanent_hwaddr"].upper()
                dev.related.mac.add(info["permanent_hwaddr"].upper())
                ifaces[nic].physical = True
                ifaces[nic].type = "ethernet"

            # Administrative status up/down
            if info.get("admin"):
                ifaces[nic].enabled = consts.str_to_bool(info["admin"])
            # "netdev status" and "link_status" I think roughly align
            if info.get("netdev status"):
                ifaces[nic].connected = consts.str_to_bool(info["netdev status"])

            if info.get("speed_setting"):
                ifaces[nic].speed = int(info["speed_setting"])
            if info.get("duplex") and info["duplex"].lower() in [
                "full",
                "half",
                "auto",
            ]:
                ifaces[nic].duplex = info["duplex"].lower()

            if info.get("rx pkts"):
                # received
                ifaces[nic].extra["received_packets"] = int(info["rx pkts"])
            if info.get("rx bytes"):
                ifaces[nic].extra["received_bytes"] = int(info["rx bytes"])
            if info.get("tx pkts"):
                ifaces[nic].extra["transmitted_packets"] = int(info["tx pkts"])
            if info.get("tx bytes"):
                ifaces[nic].extra["transmitted_bytes"] = int(info["tx bytes"])

    # add to data model
    for iface in ifaces.values():
        dev.store("interface", iface, lookup="name")


def process_fg_debug_log(db_log: dict[str, list[str]], dev: DeviceData) -> None:
    """
    Process the parsed output of the fortigate "debug log" into the PEAT data model.
    """

    # Processing is handled this way to simplify exception handling and logging
    processors = {
        "get system status": process_fg_system_status,
        "diagnose debug crashlog read": process_fg_crashlog,
        "diagnose ip address list": lambda d, dev: dev.related.ip.update(extract_ips(d)),
        "diagnose firewall iplist list": lambda d, dev: dev.related.ip.update(extract_ips(d)),
        # TODO: will this parse the macs?
        "diagnose firewall ipmac list": [
            lambda d, dev: dev.related.ip.update(extract_ips(d)),
            lambda d, dev: dev.related.mac.update(extract_macs(d)),
        ],
        "diagnose sys flash list": process_fg_sys_flash_list,
        "get hardware cpu": process_fg_hardware_cpu,
        "diagnose sys top-all 1 100 1": process_fg_top,
        # TODO: extract server-hostname
        # TODO: parse with normal config parser
        "show full-configuration system dns": lambda d, dev: dev.related.ip.update(extract_ips(d)),
        "fnsysctl ls -l /tmp": functools.partial(process_fg_ls, ls_command="fnsysctl ls -l /tmp"),
        # /dev/cmdb seems to be a Fortigate-specific path.
        # "CMDB" might mean "Configuration Management Database?"
        "fnsysctl ls -l /dev/cmdb": functools.partial(
            process_fg_ls, ls_command="fnsysctl ls -l /dev/cmdb"
        ),
        # /dev/shm: Shared memory, on a ramdisk filesystem usually
        "fnsysctl ls -l /dev/shm": functools.partial(
            process_fg_ls, ls_command="fnsysctl ls -l /dev/shm"
        ),
        "diagnose ip arp list": [
            lambda d, dev: dev.related.ip.update(extract_ips(d)),
            lambda d, dev: dev.related.mac.update(extract_macs(d)),
        ],
        "diagnose ip rtcache list": lambda d, dev: dev.related.ip.update(extract_ips(d)),
        # "get hardware memory" and "diagnose hardware sysinfo memory"  have same output
        # "diagnose" happens later in the dump and free memory is more accurate.
        "get hardware memory": process_fg_hardware_memory,
        "diagnose hardware sysinfo memory": process_fg_hardware_memory,
    }

    for section, func in processors.items():
        if not db_log.get(section):
            log.warning(f"Skipping debug log section '{section}' (empty data)")
            continue

        try:
            log.trace(f"Processing data from debug log section '{section}'")
            if isinstance(func, list):
                for f in func:
                    f(db_log[section], dev=dev)
            else:
                func(db_log[section], dev=dev)
        except Exception as ex:
            log.exception(f"Failed to process fortigate debug log section '{section}': {ex}")

    # Process interface information
    process_fg_interfaces(db_log, dev)

    # TODO: "diagnose test update info"
    #   => Logs

    # TODO: "fnsysctl df -k"
    #   dev.hardware.storage*

    # TODO: "get system session-helper-info list"
    # This is protocols the system is capable of using
    # Not sure if it's worth adding to Services model
    #   => related.port, related.protocol, services

    # TODO: New data model for routes?
    # "get router info routing-table all"
    # "get router info routing-table database"

    # TODO: "get system auto-update versions" => extract component versions

    # TODO: extract IPv6 addresses (a bit harder to do due to rules of v6)
    # "diagnose ipv6 address list"
    # "diagnose ipv6 neighbor-cache list"
    # "diagnose ipv6 route list"

    # TODO: "diagnose ip router command show show int" => interfaces
    # TODO: "diagnose ip route list"

    # TODO: parse these sections with parsers for the .conf file
    # "show full-configuration system global"
    # "show system interface"
    #   parse with same code as "config system interface"
