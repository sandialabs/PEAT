import copy
import csv
import re
import zlib
from pathlib import PurePath, PurePosixPath
from typing import Any, Literal

import olefile
from dateutil.parser import parse as date_parse
from pathvalidate import is_valid_filepath

from peat import (
    IO,
    DeviceData,
    Event,
    Interface,
    ParseError,
    Register,
    Service,
    consts,
    datastore,
    log,
    state,
    utils,
)
from peat import config as peat_config
from peat.data.data_utils import merge_models
from peat.protocols import clean_ipv4, split_ipv4_cidr

from .sel_consts import ANSI_CODES, LOGIC_KEYS

ConfigSectionType = list[str] | dict[str, str]
ConfigsType = dict[str, ConfigSectionType]


def parse_rdb(rdb_data: bytes) -> str:
    """
    Extract usable configuration from a SEL QuickSet database (``*.rdb`` file).

    Parse the binary data contained in a rdb project file and convert it
    to a string that is the same format used in SET_ALL.TXT.

    Args:
        rdb_data: Binary data from an ``.rdb`` project file

    Returns:
        Device configuration information parsed from the file, in the SET_ALL.TXT format
    """
    output = ""
    rdb_ole = olefile.OleFileIO(rdb_data)
    streams = rdb_ole.listdir(streams=True, storages=False)  # type: list[list[str]]

    for stream_list in streams:
        stream_path = "/".join(stream_list)
        data = rdb_ole.openstream(stream_path).read().decode("ascii", "replace")

        # Remove the file separator character
        data = data.replace("\x1c", "")

        # Remove the substitution character
        data = data.replace("\x1a", "")

        # Remove NUL characters that break CSV parser
        # An example of a file where these appear is 300G_000.rdb
        data = data.replace("\x00", "")

        if not data.endswith("\r\n"):
            data += "\r\n"

        # Format the DNP Binary map
        if "[DNPB]" in data:
            start = data.find('"')  # Find the start of the DNP Binary Memory Map
            dnpb_sub = data[start + 1 : -3]
            dnp_addresses = dnpb_sub.split(" ")
            data = "[DNPB]\r\n"
            idx = 1
            for address in dnp_addresses:
                data += f'BI_{idx},"{address}"\r\n'
                idx += 1
        output += data

    # Remove UI info stored by some configs
    start_index = output.find("INFO")
    output = output[start_index - 1 :]

    return output


def extract_sections(raw_text: str) -> dict[str, list[str]]:
    """
    Convert raw text of a config file into a dict with the text lines
    for each section.
    """
    cleaned_lines = [line.strip() for line in raw_text.splitlines() if line]

    raw_sections = {}
    current_section = ""  # Section name, e.g. "INFO", "P1", etc.

    for line in cleaned_lines:
        if re.match(r"^\[.*]$", line):
            # Set what the current section is and initialize it's dict
            current_section = line.strip("[]")
            raw_sections[current_section] = []
        else:
            if line.endswith(","):
                line += '""'  # Handle trailing commas in some configs
            elif line.endswith(',"'):
                line += '"'

            raw_sections[current_section].append(line)

    return raw_sections


def parse_ini_style(lines: list[str]) -> dict[str, str]:
    """
    INI-style syntax with key-value pairs.
    """
    result = {}

    for line in lines:
        if not line:
            log.warning(f"Failed parsing of INI-style line: {line}")
            continue

        key, _, value = line.strip().partition("=")
        result[key] = value

    return result


def extract_csv_lines(lines: list[str]) -> list[list[str]]:
    reader = csv.reader(lines)

    # Example line: ['N1', 'Notes', '\\SETTINGS\\SET_N1.TXT', '4d9a3b89']
    # This list comprehension does several things:
    #   Creates a list from the CSV.reader (which is a generator)
    #   Removes empty values from the line
    #   Removes extraneous whitespace from values
    parsed_lines = [[chunk.strip() for chunk in line] for line in reader if line]  # type: list[list[str]]

    return parsed_lines


def parse_csv_style(raw_lines: list[str], section_name: str) -> ConfigSectionType:
    """
    Parse lines of sections with CSV-style syntax. It's an odd and
    inconsistent format, but Python's CSV parser is apparently able
    to handle it with ablomb, so we use that instead of trying to
    write some crazy regex ourselves. A good example of weird formatting
    is from the SEL-451, look at the SET_ALL files in tests/ and examples/.
    """

    # Examples of lines:
    #   "URETRY1",3,2~10,U,,"Unsolicited Message Max Retry Attempts (2-10)"
    #   "AUTO_1","",,S,"",""
    #   RID,"Relay 1 RID","","","","Relay Identifier(30chars)"
    #   E50P,"N","","","","      Phase"
    #   RST9,"0","","","",""

    parsed_lines = extract_csv_lines(raw_lines)

    # ["\\SWCFG.ZIP"]
    if "STORAGE" in section_name:
        return [line[0].replace("\\", "/").strip() for line in parsed_lines]

    results = {}

    for line in parsed_lines:
        if "CLASSES" in section_name:
            # NOTE: For certain rdb files the header is missing,
            # which corrupts the parsing of the [CLASSES] section.
            # This appears to be happening in a number of the rdb files.
            if len(line) == 1:
                if "Saved " in line[0]:
                    if not results.get("SAVE_INFO"):
                        results["SAVE_INFO"] = []

                    results["SAVE_INFO"].append(line[0])
                else:
                    # NOTE: do NOT log the line itself, it could lead to decode
                    # errors when passed to logging if it's really nasty.
                    log.debug("Skipping malformed CLASSES line")

                continue

            results[line[0]] = {
                "class": line[0].strip(),
                "name": line[1].strip(),
            }

            # "\SETTINGS\SET_A1.TXT"
            # "SET_1.TXT"
            if len(line) > 2:
                f_path = line[2].replace("\\", "/").strip()
                results[line[0]]["file"] = f_path

            # "0x ef43c8e"
            # "0xd727d356"
            # "a9dd3ac2"
            # "30C0490A"
            if len(line) > 3:
                hex_thingy = line[3].replace("0x", "").strip().lower()
                results[line[0]]["hex_id"] = hex_thingy
        else:
            # Always have value and description, even if it's not present for
            # a particular section. This makes it easier to read from the dict.
            results[line[0]] = {
                "value": "",
                "description": "",
            }

            if len(line) > 1:  # sections L1-L6 only have a value
                results[line[0]]["value"] = line[1].strip()
            if len(line) > 2:
                results[line[0]]["description"] = line[-1].strip()

    return results


def parse_sections(raw_sections: dict[str, list[str]]) -> dict[str, ConfigSectionType]:
    # Instead of doing it line by line,
    # Grab the entire config at once, extract whole sections
    # at a time, then feed the contents of each section in Python's CSV
    # parser.
    #
    # This will work around the inconsistencies between how
    # relay configs are formatted, e.g. some devices don't use quotes
    # for all values.

    # [INFO] and [FRONTPANEL] sections are exceptions, those are INI-style key-value pairs
    #
    # [FRONTPANEL]

    configs = {}

    for section, lines in raw_sections.items():
        if not lines:
            continue

        # key-value pairs
        if "," not in lines[0] and len(lines[0].split("=")) == 2:
            configs[section] = parse_ini_style(lines)

        # CSV-thingy
        else:
            configs[section] = parse_csv_style(lines, section)

    return configs


def parse_config_data(config_text: bytes | str) -> dict[str, ConfigSectionType]:
    """
    Convert config file sections into a Python :class:`dict` structure.

    SEL config files structure is like a combination of INI and CSV file formats.
    Sections are in INI style, while variables may be in key=value structure or in
    a comma-separated CSV structure.

    Every config file starts with a ``[INFO]`` section, so this section ends up duplicated
    in every config file.

    SET_ALL.TXT contains all of the data from all of the config files.

    Example 1:

    .. code-block::

       [L3]
       TR,"OC+51PT+51GT+81D1T+LB3+50P1*SH0","","","",""
       TRCOMM,"0","","","",""
       TRSOTF,"0","","","",""

    Example 2:

    .. code-block::

       [INFO]
       RELAYTYPE=0351
       FID=SEL-351-5-R510-V0-Z103103-D20110429
       BFID=SLBT-3CF1-R102-V0-Z100100-D20091207
       PARTNO=035152B3A11XX1

    Args:
        config_file_data: complete contents of a config file, including all sections

    Returns:
        :class:`dict` representation of the config file values.
        Top level keys in the dict are config sections, e.g. ``"INFO"`` or ``"P1"``.
        Nested keys are individual values in those sections, e.g. ``"RELAYTYPE"`` OR ``"TRCOMM"``
    """
    if isinstance(config_text, bytes):
        config_text = config_text.decode("ascii")

    if not config_text:
        return {}

    try:
        extracted_sections = extract_sections(config_text)
        parsed_configs = parse_sections(extracted_sections)
        return parsed_configs
    except Exception:
        log.exception("Failed to parse SEL config data")
        return {}


def parse_cfg_txt(cfg_txt: bytes | str, dev: DeviceData) -> ConfigsType:
    """
    Parse contents of CFG.TXT, including the [INFO] and [CLASSES] sections.

    Args:
        cfg_txt: Data from a CFG.TXT config
        dev: :class:`~peat.data.models.DeviceData` instance to add data to

    Returns:
        Raw configs extracted from CFG.TXT
    """
    configs = parse_config_data(cfg_txt)

    if not configs:
        raise ParseError("No config sections extracted from CFG.TXT")

    if peat_config.DEBUG:
        dev.write_file(configs, "raw-cfg-configs.json")

    # Process the [INFO] and [CLASSES] sections
    process_info_classes(configs, dev)

    log.debug(f"Completed parsing CFG.TXT ({len(configs)} sections parsed)")

    return configs


def parse_set_all(
    set_all_data: bytes | str, dev: DeviceData | None = None
) -> tuple[dict[str, dict], DeviceData]:
    """
    Parse the data contained in SET_ALL.TXT.

    Args:
        set_all_data: Data from a SET_ALL config pulled from an relay
            or extracted from a RDB project file
        dev: :class:`~peat.data.models.DeviceData` instance to add data to

    Returns:
        Tuple with the device configuration information parsed from the file
        and the DeviceData object generated from the file data (or passed as
        argument to this function)
    """
    # Parse raw data from SET_ALL.TXT into a nested dict
    # NOTE: the 451 truncates config variable names longer than 7 characters
    configs = parse_config_data(set_all_data)

    if not configs:
        raise ParseError("No config sections extracted from SET_ALL")

    if not dev:
        dev = create_dev_from_configs(configs)

    if peat_config.DEBUG:
        dev.write_file(configs, "raw-setall-configs.json")

    # Process the [INFO] and [CLASSES] sections
    process_info_classes(configs, dev)

    # Extract network info
    process_network_configuration(configs, dev)

    # Update interface/network info
    dev.populate_fields()

    # Extract Modbus registers
    parse_and_process_modbus(configs, dev)

    # Extract DNP3 registers
    parse_and_process_dnp3(configs, dev)

    parsed_ids = parse_ids(configs)
    dev.extra.update(parsed_ids)

    device_info = {
        "protection_schemes": parse_protection_schemes(configs, dev.description.model),
        **parsed_ids,
    }

    for section, keys in LOGIC_KEYS.items():
        device_info[section.lower()] = parse_logic_section(configs, keys, section)

    log.trace(
        f"{len(configs)} SET_ALL config sections parsed: {', '.join(x for x in configs.keys())}"
    )
    log.debug(f"Completed parsing of SET_ALL ({len(configs)} sections parsed)")

    return device_info, dev


def process_info_classes(configs: ConfigsType, dev: DeviceData) -> None:
    """
    Process the [INFO] and [CLASSES] sections into the PEAT data model.
    """
    # Extract firmware info
    # NOTE: The INFO section should ALWAYS be present
    process_info_into_dev(configs["INFO"], dev)

    # Parse [CLASSES] section and put into related.files
    if configs.get("CLASSES"):
        if configs["CLASSES"].get("SAVE_INFO"):
            save_info = configs["CLASSES"]["SAVE_INFO"]  # type: list
            dev.extra["SAVE_INFO_FROM_CLASSES"] = copy.copy(save_info)

            # Extract logic save timestamp if it's listed
            # "Saved on 2/16/2023 at 10:14:22 PM"
            for msg in save_info:
                if not msg.startswith("Saved on"):
                    continue

                save_ts = utils.parse_date(msg.partition("Saved on ")[2])

                if save_ts and not dev.logic.created:
                    dev.logic.created = save_ts

                if save_ts and not dev.logic.last_updated:
                    dev.logic.last_updated = save_ts

        # Create Path objects from the file keys
        # This will parse the file path as well, if it's specified
        # "SET_1.TXT"
        # "\\SETTINGS\\SET_1.TXT"
        file_objs = [
            PurePosixPath(c["file"].replace("\\", "/"))
            for c in configs["CLASSES"].values()
            if isinstance(c, dict) and c.get("file")
        ]
        file_names = [f.name for f in file_objs]

        if file_names:
            dev.extra["files_from_classes"] = file_names
            dev.related.files.update(file_names)

    if configs.get("STORAGE"):
        # Add any filenames from [STORAGE] section, if they're files
        # Lines in this section can be random data too.
        for line in configs["STORAGE"]:
            if " " not in line and "." in line and len(line) > 3 and is_valid_filepath(line):
                file_obj = PurePosixPath(line)
                dev.related.files.add(file_obj.name)


def create_dev_from_configs(configs: ConfigsType) -> DeviceData:
    """
    Generate a :class:`~peat.data.models.DeviceData` object using the best
    available identification for a device (IP, name, etc.).
    """
    # NOTE: iteration happens 3 times here because we have to
    # scan for the settings key, e.g. "IPADDR", all the way before
    # checking for the next key (e.g. "RID" and "TID")

    # IP address
    for settings in configs.values():
        if "IPADDR" in settings:
            ip_addr = parse_ipaddr(settings).ip
            return datastore.get(ip_addr, "ip")

    # RID+TID generally in sections [1] through [6] or section [G1]
    for settings in configs.values():
        for id_key in ["RID", "TID"]:
            if id_key in settings:
                name = _getv(settings[id_key])
                if name:
                    return datastore.get(name, "name")

    # Fallback to SID (Station ID) if we can't find another identifier
    for settings in configs.values():
        if "SID" in settings:
            name = _getv(settings["SID"])
            if name:
                return datastore.get(name, "name")

    rand_id = consts.gen_random_dev_id()
    log.warning(
        f"Failed to find a suitable device ID while parsing "
        f"config, using an auto-generated ID instead\n"
        f"ID: {rand_id}"
    )

    # TODO: find a better fallback if we can't find a IP or ID
    return datastore.get(rand_id, "id")


def process_info_into_dev(info: dict, dev: DeviceData) -> None:
    """
    Put data from the info dict into the PEAT device data model.
    """
    # Make copy to mutate, so we can pop keys that
    # shouldn't go into dev.extra
    info = copy.deepcopy(info)

    if info.get("FID"):
        process_fid(info.pop("FID"), dev)

    if info.get("BFID"):
        process_fid(info.pop("BFID"), dev)

    if info.get("PARTNO"):
        dev.part_number = info.pop("PARTNO")

    # This comes from parsing status output and exit info
    if info.get("serial_number"):
        dev.serial_number = info.pop("serial_number")
    # This comes from the "id" command
    elif info.get("SERIALNO"):
        dev.serial_number = info.pop("SERIALNO")

    relaytype = info.pop("RELAYTYPE", None)
    if relaytype and not dev.description.model:
        dev.description.model = relaytype.strip("0")

    # Add any remaining info that hasn't been processed
    # to dev.extra (hence the .pop() calls above).
    dev.extra.update(info)

    if not dev.name:
        name = info.get("device_name")
        ident = info.get("device_identifier")

        if not ident:
            ident = info.get("DEVID")

        if name and ident:
            dev.name = f"{name} - {ident}"
        elif name:
            dev.name = name
        elif ident:
            dev.name = ident


def process_fid(id_string: str, dev: DeviceData) -> None:
    """
    Get data from the FID string and put it into the PEAT device data model.
    """
    fid_info = parse_fid(id_string)

    if not fid_info:
        return

    if "model" in fid_info:  # FID (Firmware ID)
        dev.description.model = fid_info.pop("model")
        dev.description.product = fid_info.pop("product")
        fw_obj = dev.firmware
    else:  # BFID (Boot Firmware ID)
        fw_obj = dev.boot_firmware

    if "settings_version" in fid_info:
        settings_version = fid_info.pop("settings_version")
        fw_obj.extra["settings_version"] = settings_version

    for key, value in fid_info.items():
        if hasattr(fw_obj, key):
            setattr(fw_obj, key, value)


def parse_ipaddr(settings: dict) -> Interface:
    """
    Parse ``IPADDR`` section out of a port config (e.g., ``P5``).

    IP/ethernet interfaces. Usually port 5 (P5), though it could
    potentially be other interfaces.
    """
    iface = Interface(type="ethernet")

    # NOTE: examples of values for "settings" are in test_parse_ipaddr
    if "SUBNETM" in settings:
        # 351: subnet mask is a separate value
        iface.ip = clean_ipv4(_getv(settings["IPADDR"]))
        iface.subnet_mask = clean_ipv4(_getv(settings["SUBNETM"]))
    else:
        # Subnet mask is part of the address in CIDR "slash"
        # notation on the SEL-451 and possibly other models.
        ip_addr = _getv(settings["IPADDR"])
        if "/" in ip_addr:
            ip_addr, iface.subnet_mask = split_ipv4_cidr(ip_addr)
        iface.ip = clean_ipv4(ip_addr)

    if "DEFRTR" in settings:
        gw = _getv(settings["DEFRTR"])
        if gw:
            iface.gateway = clean_ipv4(gw)

    return iface


def process_port_settings(
    port_id: Literal["1", "2", "3", "4", "5", "F"],
    settings: dict[str, dict | str],
    dev: DeviceData,
) -> None:
    """
    Process parsed port settings into the device data model.
    """
    log.trace(f"Processing port settings for port {port_id} from {dev.get_id()}")

    iface = Interface(
        name=f"Port {port_id}",
    )

    if "EPORT" in settings:
        iface.enabled = value_is_enabled(_getv(settings["EPORT"]))

    if "IPADDR" in settings:
        # Ethernet interfaces
        merge_models(iface, parse_ipaddr(settings))
    else:
        # Serial interfaces
        # Generally, these are are port 1-3 and port F
        if settings.get("PROTO"):
            app_proto = _getv(settings["PROTO"]).replace("DNP", "DNP3").lower()
            iface.application = app_proto
        elif "PROTO" not in settings and port_id == "F":
            iface.application = "sel"

        if settings.get("SPEED"):
            speed = _getv(settings["SPEED"])

            # Possible value for SPEED may be "SYNC" on some models,
            # according to SEL documentation
            if speed.upper() != "SYNC":
                iface.baudrate = int(speed)

            iface.type = "serial"

        if "BITS" in settings:
            iface.data_bits = int(_getv(settings["BITS"]))
        elif "DATABIT" in settings:  # 411L, 487E, some 451's
            iface.data_bits = int(_getv(settings["DATABIT"]))

        if "PARITY" in settings:
            parity = _getv(settings["PARITY"]).upper()

            if parity == "O":
                parity = "odd"
            elif parity == "E":
                parity = "even"
            elif parity == "N":
                parity = "none"
            else:
                log.warning(f"Unknown parity value: {parity} (device: {dev.get_id()})")
                parity = ""

            iface.parity = parity

        if "STOP" in settings:  # 2411, 2015+ firmwares (possibly earlier)
            iface.stop_bits = int(_getv(settings["STOP"]))
        elif "STOPBIT" in settings:
            # 451, 411L, and others
            iface.stop_bits = int(_getv(settings["STOPBIT"]))

        if "RTSCTS" in settings and value_is_enabled(_getv(settings["RTSCTS"])):
            iface.flow_control = "rts/cts"
        elif settings.get("SPEED"):
            iface.flow_control = "none"

        if "T_OUT" in settings:
            iface.extra["inactivity_timeout"] = float(_getv(settings["T_OUT"]))

        if "MAXACC" in settings:
            iface.extra["max_privilege_level"] = _getv(settings["MAXACC"])

        # 311L: "PROTO" on P1 can be "TELNET".
        # Per the SEL documentation (311L-1-7_IM_20191107):
        # "To enable Telnet-to-relay communications on PORT 5 and
        #  PORT6, the PORT 1 PROTO setting must be set to TELNET.
        #  Setting PROTO = TELNET disables PORT 1 for EIA-485 communications."
        # NOTE: PROTO field may not be present for PF on newer firmwares
        if settings.get("PROTO"):
            if _getv(settings["PROTO"]) == "TELNET":
                iface.enabled = False

        for key in ["TPORT", "TIDLE"]:
            if key in settings:
                iface.extra[key] = _getv(settings[key])

    # Service configurations
    # TODO: break this out into a function
    # TODO: utility functions for setting processing (alternate keys, type casts)

    services = []

    if settings.get("FTPUSER") or settings.get("FTPSERV"):
        ftp_svc = Service(protocol="ftp", transport="tcp", port=21)

        if settings.get("FTPSERV"):
            ftp_svc.enabled = value_is_enabled(_getv(settings["FTPSERV"]))
        elif settings.get("EFTPSERV"):
            ftp_svc.enabled = value_is_enabled(_getv(settings["EFTPSERV"]))

        if settings.get("FTPIDLE"):
            ftp_svc.extra["idle_timeout"] = float(_getv(settings["FTPIDLE"]))

        if settings.get("FTPUSER"):
            ftp_svc.extra["user"] = _getv(settings["FTPUSER"])
            dev.related.user.add(_getv(settings["FTPUSER"]))

        if settings.get("FTPANMS"):
            anon_login_enabled = value_is_enabled(_getv(settings["FTPANMS"]))
            ftp_svc.extra["anonymous_login_enabled"] = anon_login_enabled

        if settings.get("FTPAUSR"):
            ftp_svc.extra["anonymous_access_level"] = _getv(settings["FTPAUSR"])

        services.append(ftp_svc)

    for svc_name in [
        "HTTP",
        "TELNET",
        "GSE",
        "MMSFS",
        "DNP",
        "MODBUS",
        "SNTP",
        "61850",
        "PMIP",
    ]:
        # "EHTTP", "ETELNET", etc.
        if settings.get(f"E{svc_name}"):
            protocol = svc_name.lower()

            if svc_name in ["GSE", "61850"]:
                protocol = "iec61850"
            elif svc_name == "DNP":
                protocol = "dnp3"
            elif svc_name == "PMIP":
                protocol = "c37.118"

            svc = Service(
                protocol=protocol,
                enabled=value_is_enabled(_getv(settings[f"E{svc_name}"])),
            )

            if protocol == "http":
                svc.transport = "tcp"

                if settings.get("HTTPPOR"):
                    svc.port = int(_getv(settings["HTTPPOR"]))
                elif settings.get("HTTPPORT"):
                    svc.port = int(_getv(settings["HTTPPORT"]))

                if settings.get("HIDLE"):
                    svc.extra = {"idle_timeout": float(_getv(settings["HIDLE"]))}
                elif settings.get("HTTPIDLE"):
                    svc.extra = {"idle_timeout": float(_getv(settings["HTTPIDLE"]))}

            elif protocol == "telnet":
                svc.transport = "tcp"

                if settings.get("TPORT"):
                    svc.port = int(_getv(settings["TPORT"]))
                # 311L: "Telnet Port for Card Access"
                elif settings.get("TPORTC"):
                    svc.port = int(_getv(settings["TPORTC"]))

                if settings.get("TIDLE"):
                    svc.extra["idle_timeout"] = float(_getv(settings["TIDLE"]))

            elif protocol == "sntp":
                svc.transport = "udp"

                if settings.get("SNTPPORT"):
                    svc.port = int(_getv(settings["SNTPPORT"]))
                elif settings.get("SNTPPOR"):
                    svc.port = int(_getv(settings["SNTPPOR"]))

                if settings.get("SNTPPSIP"):
                    svc.extra["sntp_primary_ip"] = clean_ipv4(_getv(settings["SNTPPSIP"]))
                    dev.related.ip.add(svc.extra["sntp_primary_ip"])
                elif settings.get("SNTPPIP"):
                    svc.extra["sntp_primary_ip"] = clean_ipv4(_getv(settings["SNTPPIP"]))
                    dev.related.ip.add(svc.extra["sntp_primary_ip"])

                if settings.get("SNTPBSIP"):
                    svc.extra["sntp_backup_ip"] = clean_ipv4(_getv(settings["SNTPBSIP"]))
                    dev.related.ip.add(svc.extra["sntp_backup_ip"])
                elif settings.get("SNTPBIP"):
                    svc.extra["sntp_backup_ip"] = clean_ipv4(_getv(settings["SNTPBIP"]))
                    dev.related.ip.add(svc.extra["sntp_backup_ip"])

                if settings.get("SNTPRATE"):
                    svc.extra["sntp_rate"] = int(_getv(settings["SNTPRATE"]))
                elif settings.get("SNTPRAT"):
                    svc.extra["sntp_rate"] = int(_getv(settings["SNTPRAT"]))
                if settings.get("SNTPTO"):
                    svc.extra["sntp_timeout"] = float(_getv(settings["SNTPTO"]))

            elif protocol == "dnp3":
                if settings.get("DNPNUM"):
                    svc.port = int(_getv(settings["DNPNUM"]))
                elif settings.get("DNPPNUM"):
                    svc.port = int(_getv(settings["DNPPNUM"]))
                if settings.get("DNPADR"):
                    svc.protocol_id = _getv(settings["DNPADR"])
                if settings.get("DNPID"):
                    # "DNP ID for Object 0, Var 246 (20 characters)"
                    svc.extra["dnp3_id"] = _getv(settings["DNPID"])
                if settings.get("DNPMAP"):
                    svc.extra["session_map"] = _getv(settings["DNPMAP"])

                dnp3_stations = []

                for idx in range(1, 7):
                    st = {}

                    if settings.get(f"DNPIP{idx}"):
                        # "IP Address (zzz.yyy.xxx.www)"
                        st["ip"] = clean_ipv4(_getv(settings[f"DNPIP{idx}"]))
                        dev.related.ip.add(st["ip"])

                    if settings.get(f"DNPTR{idx}"):
                        # "Transport Protocol (UDP,TCP)"
                        st["transport"] = _getv(settings[f"DNPTR{idx}"]).lower()

                    if settings.get(f"DNPUDP{idx}"):
                        # "UDP Response Port (REQ, 1025-65534)"
                        st["port"] = int(_getv(settings[f"DNPUDP{idx}"]))
                        dev.related.ports.add(st["port"])

                    if settings.get(f"REPADR{idx}"):
                        # "DNP Address to Report to (0-65519)"
                        st["report_address"] = _getv(settings[f"REPADR{idx}"])

                    if settings.get(f"DNPMAP{idx}"):
                        # "DNP Session Map (1-5)"
                        st["session_map"] = _getv(settings[f"DNPMAP{idx}"])

                    if settings.get(f"DNPINA{idx}"):
                        # "Seconds to Send Data Link Heartbeat (0-7200)"
                        st["heartbeat_timeout"] = int(_getv(settings[f"DNPINA{idx}"]))

                    if settings.get(f"DNPCL{idx}"):
                        # "Enable Control Operations (Y,N)"
                        cne = value_is_enabled(_getv(settings[f"DNPCL{idx}"]))
                        st["control_operations_enabled"] = cne

                    if settings.get(f"DNPID{idx}"):
                        st["dnp3_id"] = _getv(settings[f"DNPID{idx}"])

                    if st:
                        st["station_num"] = idx
                        dnp3_stations.append(st)

                if dnp3_stations:
                    svc.extra["dnp3_stations"] = dnp3_stations

            elif protocol == "modbus":
                if iface.type == "ethernet":
                    svc.transport = "tcp"
                    svc.port = 502

                endpoints = []

                for idx in range(1, 4):
                    endp = {}

                    if settings.get(f"MODIP{idx}"):
                        endp["ip"] = clean_ipv4(_getv(settings[f"MODIP{idx}"]))
                        dev.related.ip.add(endp["ip"])

                    if settings.get(f"MTIMEO{idx}"):
                        endp["timeout"] = float(_getv(settings[f"MTIMEO{idx}"]))

                    if endp:
                        endp["endpoint_num"] = idx
                        endpoints.append(endp)

                if endpoints:
                    svc.extra["modbus_endpoints"] = endpoints

            elif protocol == "c37.118":
                # TODO: improve processing of PMU fields, want to add a
                #   separate local service for each PMU that's configured,
                #   based on it's configuration (TCP,UDP_S,UDP_T,UDP_U)
                #   Refer to "Ethernet Operation" section in SEL documentation
                # C37.118 is TCP (port 4712) or UDP (port 4713)
                # Reference: https://wiki.wireshark.org/IEEE%20C37.118
                endpoints = []

                for idx in range(1, 2):
                    endp = {}
                    if settings.get(f"PMOTS{idx}"):
                        # TODO: resolve to actual transport method
                        #   Possible values: (OFF,TCP,UDP_S,UDP_T,UDP_U)
                        endp["transport_scheme"] = str(_getv(settings[f"PMOTS{idx}"]))
                        endp["enabled"] = bool(endp["transport_scheme"].lower() != "off")

                    if settings.get(f"PMOIPA{idx}"):
                        endp["ip"] = clean_ipv4(_getv(settings[f"PMOIPA{idx}"]))
                        dev.related.ip.add(endp["ip"])

                    if settings.get(f"PMOTCP{idx}"):
                        endp["tcp_local_port"] = int(_getv(settings[f"PMOTCP{idx}"]))
                        dev.related.ports.add(endp["tcp_local_port"])

                    if settings.get(f"PMOUDP{idx}"):
                        endp["udp_remote_port"] = int(_getv(settings[f"PMOUDP{idx}"]))
                        dev.related.ports.add(endp["udp_remote_port"])

                    if endp:
                        endp["endpoint_num"] = idx
                        endpoints.append(endp)

                if endpoints:
                    svc.extra["c37_endpoints"] = endpoints

            services.append(svc)

    # Store interface in the data model, followed by the services
    dev.store("interface", iface)

    for service in services:
        if service.port:
            dev.related.ports.add(service.port)

        if service.protocol:
            dev.related.protocols.add(service.protocol)

        dev.store("service", service, interface_lookup={"name": iface.name})


def process_network_configuration(configs: dict[str, dict], dev: DeviceData) -> None:
    """
    Process relay network information into the data model.
    """
    for section, settings in configs.items():
        # NOTE: 311L doesn't have "EPORT"
        if "EPORT" not in settings and "PROTO" not in settings and "IPADDR" not in settings:
            continue

        port_id = "".join(section[1:]).upper()  # 5 for P5, F for PF
        process_port_settings(port_id, settings, dev)


def parse_ids(configs: dict[str, dict]) -> dict[str, str | dict[str, str]]:
    """
    Extract and parse various relay IDs from a set of configs.

    These include:

    - RID (Relay ID)
    - SID (Station ID)
    - TID (Terminal ID)

    Args:
        configs: parsed SET_ALL as a dict

    Returns:
        Parsed relay IDs, including cleaned values, raw values,
        and the relay IDs for each settings group (e.g. the ID for group 1).

        .. code-block:: python
           :caption: Example of returned data from parse_ids

           {
               "relay_id_by_group": {"1": "GENERATOR", "2": "GENERATOR"},
               "station_id_by_group": {},
               "terminal_id_by_group": {"1": "TERMINAL", "2": "TERMINAL"},
               "relay_id": "generator",
               "station_id": "",
               "terminal_id": "terminal",
               "raw_rid": "GENERATOR",
               "raw_sid": "",
               "raw_tid": "TERMINAL",
           }
    """

    ids = {
        "relay_id_by_group": {},
        "station_id_by_group": {},
        "terminal_id_by_group": {},
        "relay_id": "",
        "station_id": "",
        "terminal_id": "",
        "raw_rid": "",
        "raw_sid": "",
        "raw_tid": "",
    }

    table = {
        "RID": "relay_id",
        "SID": "station_id",
        "TID": "terminal_id",
    }

    for config, settings in configs.items():
        for ident, desc in table.items():
            if ident not in settings:
                continue

            id_val = settings[ident]["value"]

            # "relay_id_by_group"
            ids[f"{desc}_by_group"][config] = id_val

            if config in ["1", "G1"]:
                # "raw_rid"
                ids[f"raw_{ident.lower()}"] = id_val
                # "relay_id"
                ids[desc] = clean_id(id_val)

    return ids


# TODO: consolidate Modbus+DNP3 register parsing logic into single function
def parse_and_process_modbus(configs: dict[str, dict], dev: DeviceData) -> None:
    """
    Put Modbus registers into the data model as
    :class:`~peat.data.models.Register` objects.

    Args:
        configs: parsed SET_ALL as a dict
        dev: device object to add the data to
    """

    # TODO: unit test

    for config, settings in configs.items():
        # M, M1, M2, etc.
        if not config[0] == "M" or not re.match(r"^M\d?$", config, re.ASCII):
            continue

        # TODO: [M1] is "monitoring and metering" on SEL-487E
        if dev.description.model == "487E" and config[1].isdigit():
            continue

        log.debug(f"Parsing and processing Modbus data from section {config}")

        # MOD_031,"MWH3I"
        for regaddr, field in settings.items():
            if not regaddr.startswith("MOD"):
                log.warning(f"Unknown modbus register: {regaddr}")
                continue

            # "MOD_031" => "031"
            addr = regaddr[4:]

            # Strip leading zeros
            if len(addr) == addr.count("0"):  # just zeroes
                addr = "0"
            else:
                addr = addr.lstrip("0")

            reg = Register(
                address=addr,
                description=field["description"],
                group=config,
                name=regaddr,
                protocol="modbus",
            )

            # If no value, or value is marked as "NA", then still create
            # a register, but mark it as disabled.
            if not field["value"] or field["value"] == "NA":
                reg.enabled = False
            else:
                io = IO(
                    name=field["value"],
                )
                dev.store("io", io, lookup="name")

                reg.enabled = True
                reg.io = io.name

            dev.store("registers", reg)


def parse_and_process_dnp3(configs: dict[str, dict], dev: DeviceData) -> None:
    """
    Put DNP3 registers and inferred IO-points into the data model as
    :class:`~peat.data.models.Register` and
    :class:`~peat.data.models.IO` objects.

    Args:
        configs: parsed SET_ALL as a dict
        dev: device object to add the data to
    """

    # TODO: unit tests for all formats, [D1], [DNPB], [DNPA]
    #   Example files as well.
    # TODO: unit test with Modbus and DNP3 points.

    td_table = {
        "BI": ("binary", "input"),
        "BO": ("binary", "output"),
        "AI": ("analog", "input"),
        "AO": ("analog", "output"),
    }

    for config, settings in configs.items():
        # DNPA, DNPB, D1, D2, D3, etc.
        if not config[0] == "D" or (not config[1].isdigit() and not config.startswith("DNP")):
            continue

        log.debug(f"Parsing and processing DNP3 data from section {config}")

        for regaddr, field in settings.items():
            # DNPA and DNPB are from 311L and 387, and possibly others.
            #
            # 387:
            #   DNPAI "DNP Analog Input Map Settings"
            #   DNPAO "DNP Analog Output Map Settings"
            #   DNPBI "DNP Binary Input Map Settings"
            #   DNPBO "DNP Binary Output Map Settings"
            #
            # [DNPA]
            # DNPA,""
            # [DNPB]
            # BI_1,""
            #
            # "DNPA" == "DNPA"
            if regaddr == config:
                if not field["value"] or field["value"] in ["NA", "0"]:
                    continue

                if not dev.extra.get(f"{config}_analog_inputs"):
                    dev.extra[f"{config}_analog_inputs"] = {}

                vals = field["value"].split(" ")

                for idx, val in enumerate(vals):
                    # TODO: create Register and IO objects for DNPA/DNPB
                    dev.extra[f"{config}_analog_inputs"][str(idx)] = val

            # if does not start with BI, BO, AI, AO,
            # then parse as a variable, e.g.
            # MINDIST or MAXDIST
            if len(regaddr) < 3 or regaddr[:2] not in td_table:
                if not field["value"] or field["value"] == "NA" or not regaddr:
                    continue

                io = IO(
                    name=regaddr,
                )
                dev.store("io", io, lookup="name")

                continue

            # "BI_00" => "00"
            addr = regaddr[3:]

            # "BI_00" => "binary", "input"
            reg_type, direction = td_table[regaddr[:2]]

            # Strip leading zeros
            if len(addr) == addr.count("0"):  # just zeroes
                addr = "0"
            else:
                addr = addr.lstrip("0")

            reg = Register(
                address=addr,
                description=field["description"],
                # Associate register with a DNP3 group, e.g D1, D3
                group=config,
                measurement_type=reg_type,
                name=regaddr,
                protocol="dnp3",
                # TODO: determine register read/write settings for SEL
                # read_write="",
            )

            # If no value, or value is marked as "NA", then still create
            # a register, but mark it as disabled.
            if not field["value"] or field["value"] == "NA":
                reg.enabled = False
            else:
                io = IO(
                    direction=direction,
                    name=field["value"],
                    type=reg_type,
                )
                dev.store("io", io, lookup="name")

                reg.enabled = True
                reg.io = io.name

            dev.store("registers", reg)


def parse_protection_schemes(
    configs: dict[str, dict], device_type: str = ""
) -> dict[str, str | list]:
    protection_schemes = {}  # type: dict[str, Union[str, list]]

    for section, settings in configs.items():
        if "487e" in device_type.lower() and isinstance(settings, dict):
            proto = []
            for setting, fields in settings.items():
                if "PROTSEL" in setting.upper() and fields["value"]:
                    proto.append(fields["value"])
            if proto:
                protection_schemes[section] = proto
        else:
            if re.match(r"^S?\d$", section):
                for setting, fields in settings.items():
                    # TODO: set flag if scheme is enabled based on global
                    #       flag configuring if setting is enabled.
                    if re.match(r"^E\d", setting) and re.match(r"Y|YES|ON|[1-9]", fields["value"]):
                        if setting[1:] in ANSI_CODES:
                            code = setting[1:]
                            protection_schemes[code] = ANSI_CODES[code]
                    elif re.match(r"^\d", setting):
                        voltage_elements = (
                            r"^(27TN.59N|27TN|27AUX|27X|27.50|27P|27S|"
                            r"36|59NU|59N|59B|59P|59X|59Q|87V|91)"
                        )
                        try:
                            if (
                                re.match(voltage_elements, setting)
                                and fields["value"] not in ("N", "0.00", "OFF")
                                and settings["EVOLT"]["value"] == "Y"
                            ):
                                code = re.match(voltage_elements, setting).group(1)
                                if code in ANSI_CODES:
                                    scheme = ANSI_CODES[code]
                                else:
                                    scheme = "UNKNOWN"
                                protection_schemes[code] = scheme
                        except Exception:
                            pass

    return protection_schemes


def parse_logic_section(
    configs: dict[str, dict], logic_keys: list[str], logic_type: str
) -> dict[str, dict[str, str]]:
    logic = {}

    for section, settings in configs.items():
        logic[section] = {}

        for logic_key in logic_keys:
            if logic_key not in settings:
                continue

            value = settings[logic_key]["value"]

            # NOTE: close logic used to compare value != 0, which
            # was never valid (at least for a while) since the values
            # are always strings after getting parsed out of the config.
            if logic_type == "TRIP_LOGIC" or value != "0":
                logic[section][logic_key] = value

        if not logic[section]:  # Delete groups that have no logic
            logic.pop(section)

    return logic


def extract_fid(data: bytes | str) -> str:
    return extract_string(data, r"FID\s?=\s?(SEL[\w\-]+)\s")


def extract_bfid(data: bytes | str) -> str:
    return extract_string(data, r"BFID\s?=\s?([\w\-]+)\s")


def extract_cid(data: bytes | str) -> str:
    return extract_string(data, r"CID\s?=\s?(\w+)\s")


def extract_part_number(data: bytes | str) -> str:
    return extract_string(data, r"part\s?(?:number|num):?\s+(\w+)\s", flags=re.IGNORECASE)


def extract_serial_number(data: bytes | str) -> str:
    return extract_string(data, r"serial\s?(?:number|num):?\s+(\w+)\s", flags=re.IGNORECASE)


def extract_selboot_checksum(data: bytes | str) -> str:
    return extract_string(
        data, r"selboot:?\s.*checksum:?\s+(\d+)\s", flags=re.IGNORECASE | re.DOTALL
    )


def extract_string(data: bytes | str, regex: str, flags=None) -> str:
    """
    Extract a string from arbitrary data.
    """
    if isinstance(data, bytes):
        data = data.decode("ascii")

    re_flags = re.ASCII
    if flags:
        re_flags |= flags

    result = re.search(regex, data, re_flags)

    if result is not None:
        return result.groups()[0]

    return ""


def parse_fid(id_string: str) -> dict[str, str]:
    """
    Parse the ``FID`` and ``BFID`` strings into a :class:`dict` with
    the relay model and firmware information.

    - Model: "SEL-351"
    - Variant (??): "5" (some devices may not have this portion)
    - Release: "R510" (major release, generally new or changed features)
    - Point release: "V0" (minor release, usually fixes or minor changes)
    - Settings version: "Z103103" (indicates what version of SEL ACCSELERATOR software to use)
    - Firmware release date: "D20110429" (2011-04-29, or April 29, 2011)

    Args:
        id_string: Firmware ID string to parse, e.g. FID or BFID

    Returns:
        Information extracted from the firmware ID

            - ``id`` (the full FID/BFID string)
            - ``version`` ("V0")
            - ``revision`` ("R322")
            - ``settings_version`` ("Z025013")
            - ``release_date`` (datetime object)
            - (FID-only) ``model`` ("451")
            - (FID-only) ``product`` ("SEL-451-5")
    """
    if not id_string:
        log.warning(f"parse_fid got an empty FID (Raw value: '{id_string}')")
        return {}

    id_string = id_string.replace("\r", "").replace("\n", "")
    sfid = [x.strip() for x in id_string.split("-") if x]

    if len(sfid) == 3:
        return {"id": id_string, "revision": sfid[2]}

    if len(sfid) < 5:
        log.error(f"Failed to parse firmware ID '{id_string}': length less than 5")
        return {}

    # Parse backwards to handle variable parts (SLBT-3CF1 vs BOOTLDR)
    release_date = sfid.pop().strip("D")  # D20120321
    if "XXXXX" in release_date:
        release_datetime = None
    else:
        release_datetime = utils.parse_date(release_date)
    settings_version = sfid.pop()  # Z100100
    version = sfid.pop()  # V0
    revision = sfid.pop()  # R200

    info = {
        "id": id_string,
        "version": version,
        "revision": revision,
        "settings_version": settings_version,
        "release_date": release_datetime,
    }

    if sfid[0] == "SEL":
        info["model"] = sfid[1]  # "351"
        info["product"] = "-".join(sfid)  # "SEL-351-5"

    return info


def parse_status_output(lines: list[str]) -> dict:
    """
    Parse status command output.

    This data can be retrieved via Telnet or Serial with the ``sta`` command
    or scraped from the HTTP web interface device status page.

    The data extracted will vary by device model.
    This can then be processed by ``process_info_into_dev()``.

    Data that may be extracted:

    - ``device_name``: Device name (``"STATION A"``)
    - ``device_identifier``: Device identifier (``"Relay 1"``)
    - ``device_time``: Current date and time on the device
        (:class:`~datetime.datetime` instance)
    - ``FID``: FID string
    - ``CID``: CID string (``"F029"``)
    - (TODO) Temperature
    - (TODO) Self-test results for components (RAM, ROM, FPGA, etc.)
    - (TODO) Voltages and currents

    Args:
        lines: Extracted status info lines

    Returns:
        Data extracted from the command output
    """
    # TODO: this function needs a lot of work. Should refactor to work
    #   as a regex on the raw response text instead of line parsing, since
    #   the output of 'sta' varies significantly between devices/versions.
    #   Also, operate on raw text, don't rely on lines being preprocessed

    if not lines:
        log.warning("No data passed to parse_status_output")
        return {}

    info = {}

    if len(lines) == 1:
        info["FID"] = lines[0].split("=")[1].strip()
        return info

    id_time = re.search(
        r"(?P<dev_id>[\w\-. ]+)\s+"
        r"Date: (?P<date>\d+/\d+/\d{2,4})\s+"
        r"Time: (?P<time>\d+:\d+:[\d.]+)",
        lines[0],
        re.ASCII,
    )

    if id_time:
        # "THERMOMETER", "FEEDER 1", "SEL-700G", "Relay 1"
        info["device_identifier"] = id_time["dev_id"].strip()
        info["device_time"] = date_parse(f"{id_time['date']} {id_time['time']}")
    else:
        log.debug(f"Failed to match 'sta' output for line {repr(lines[0])}")

    if "Time Source" in lines[1]:
        # "GENERATOR RELAY                          Time Source: Internal"
        name_ts = re.search(
            r"(?P<dev_name>[\w\-. ]+)\s+Time Source: (?P<time_source>\w+)",
            lines[1],
            re.ASCII,
        )

        if name_ts:
            info["device_name"] = name_ts["dev_name"].strip()
            info["time_source"] = name_ts["time_source"].strip()
    else:
        # "STATION A"
        info["device_name"] = lines[1].strip()

    # Finish early if there are only two lines
    if len(lines) <= 2:
        return info

    try:
        if "FID" in lines[2] and "CID" in lines[2]:
            fid_cid = [x.strip() for x in re.split(r"\s{2,}", lines[2]) if x]
            info["FID"] = fid_cid[0].split("=")[1].strip()
            info["CID"] = fid_cid[1].split("=")[1].strip()

        elif "serial num" in lines[2].lower():
            serial_fid = [x.strip() for x in re.split(r"\s{2,}", lines[2]) if x]
            info["serial_number"] = serial_fid[0].split("=")[1].strip()
            info["FID"] = serial_fid[1].split("=")[1].strip()

            cid_partnum = [x.strip() for x in re.split(r"\s{2,}", lines[3]) if x]
            info["CID"] = cid_partnum[0].split("=")[1].strip()
            info["part_number"] = cid_partnum[1].split("=")[1].strip()

        elif "serial no" in lines[2].lower():
            sn_line = f"{lines[2]} {lines[3]}"
            result = re.match(
                (
                    r".+erial.+\s+=\s+(?P<serial_number>\w+)\s+"
                    r"FID\s+=\s+(?P<FID>[\w\-]+)\s+"
                    r"CID\s+=\s+(?P<CID>\w+)\s*"
                ),
                sn_line,
                re.ASCII,
            )
            info.update(result.groupdict())

        elif lines[2].startswith("FID="):
            info["FID"] = lines[2].split("=")[1].strip()

    except Exception:
        log.exception("Failed to parse FID from status lines")
        log.error(f"Bad lines: {lines}")

    # TODO: parse voltages and currents
    # TODO: parse self-test statuses
    # TODO: parse temperature

    return info


def parse_ver_output(data: str) -> dict[str, str]:
    data = data.strip()

    results = {
        "FID": extract_fid(data),
        "BFID": extract_bfid(data),
        "CID": extract_cid(data),
        "part_number": extract_part_number(data),
        "serial_number": extract_serial_number(data),
    }

    # ldata = data.lower()
    # # 311L
    # if ldata.startswith("partnumber") or ldata.startswith("part number"):
    #     flash_size = extract_string

    # # 451 and 351S?
    # else:
    #     pass

    if not any(results.values()):
        log.warning("Failed to parse any data from 'ver' output")
        return {}

    return results


def event_data_present(data: bytes | str) -> bool:
    if isinstance(data, bytes):
        data = data.decode("ascii")

    data = data.lower().strip()

    if not data or "data available" in data or "history buffer empty" in data:
        return False
    else:
        return True


def parse_and_process_events(
    data: bytes | str, dataset: str, dev: DeviceData
) -> tuple[list[dict], dict]:
    log.info(f"Parsing events in {dataset} from {dev.get_id()}")

    if isinstance(data, bytes):
        data = data.decode("ascii")

    # TODO: error state should be better propagated to callers,
    # e.g. the caller should be able to differentiate between
    # no events returned because there are no events vs.
    # no events returned because a parsing error occurred.

    raw_lines = split_lines(data)  # type: list[str]

    if not raw_lines:
        return [], {}

    if not event_data_present(raw_lines[0]):
        log.debug(f"No event data present for {dataset}")
        return [], {}

    info = {}

    try:
        if "cser" in dataset.lower():
            events, info = parse_cser(raw_lines)
        elif "ser" in dataset.lower():
            events, info = parse_ser(raw_lines)
        elif "chistory" in dataset.lower():
            events, info = parse_chistory(raw_lines)
        elif "history" in dataset.lower() or dataset.lower() == "his":
            events, info = parse_history(raw_lines)
        else:
            log.error(f"Invalid SER/HISTORY filename: {dataset}")
            state.error = True
            return [], info
    except Exception:
        log.exception(f"Failed to parse events in {dataset} from {dev.get_id()}")
        state.error = True
        return [], info

    if info:
        process_info_into_dev(info, dev)

    if not events:
        log.warning(f"No events in {dataset} from {dev.get_id()}")
        return [], info

    process_events(events, dev, dataset=dataset)

    log.info(f"Extracted {len(events)} events from {dataset} from {dev.get_id()}")

    return events, info


def parse_ser(raw_lines: list[str]) -> tuple[list[dict], dict]:
    """
    Parse output of ``SER.TXT``, the ``ser`` command, or the ``ser`` web page.

    Examples of SER data:

    - SER.TXT pulled via FTP or Telnet
    - Output from 'ser' command (via Telnet or serial)
    - "ser" page in the web interface

    Returns:
        Events and status info. Events will be empty if there are no events.
        Status info will be empty if no front matter was present.
    """

    try:
        # Find the header line for the actual events
        header_index = next(
            idx for idx, line in enumerate(raw_lines) if "#" in line and "date" in line.lower()
        )
    except StopIteration:
        log.warning("No events found in SER output, attempting to parse status info")
        return [], parse_status_output(raw_lines)

    status_info = {}

    # Process the status information front matter
    if header_index != 0 and "SEL-2032" not in raw_lines[0]:
        status_info = parse_status_output(raw_lines[:header_index])

    # Filter to just the lines with the events
    event_lines = raw_lines[header_index + 1 :]
    events = []

    for line in event_lines:
        if line and line[0].isdigit():
            # line spacing may be 1 character or two, but event values
            # can also have single spaces, e.g. "Relay Powered Up".
            # To handle this, we use a regex...
            #
            # 1024 12/09/2020  18:08:43.048    SALARM                       Deasserted
            # 213  01/15/2021  17:09:45.504    Relay Powered Up
            # 214  01/13/2021  10:17:40.740    SALARM                       Deasserted
            result = re.match(
                (
                    r"(?P<seq>\d+)\s+"
                    r"(?P<date>\S+)\s+"
                    r"(?P<time>\S+)\s+"
                    r"(?P<element>(?:\w| \w)+)\s*"
                    r"(?P<state>(?:\w| \w)+)?"
                ),
                line,
                re.ASCII | re.IGNORECASE,
            )

            if not result:
                log.warning(
                    f"Failed to parse SER events due to unexpected format.\nRaw line: '{line}'"
                )
                return [], status_info

            values = result.groupdict()

            event = {
                "sequence": int(values["seq"]),
                "date": values["date"],
                "time": values["time"],
                "original": line,
                "element": values["element"],
                "state": "" if not values.get("state") else values["state"],
            }

            events.append(event)

    return events, status_info


# TODO: combine duplicate logic between parse_history(), parse_ser_events(),
#   and sel_http.SELHTTP.get_historical_events()
def parse_history(raw_lines: list[str]) -> tuple[list[dict], dict]:
    """
    Parse output of ``HISTORY.TXT``.

    Returns:
        Events and status info. Events will be empty if there are no events.
        Status info will be empty if no front matter was present.
    """
    # Find the header line for the actual events
    try:
        header_index = next(
            idx for idx, line in enumerate(raw_lines) if "#" in line and "date" in line.lower()
        )
    except StopIteration:
        log.warning("No events found in HISTORY output, attempting to parse status info")
        return [], parse_status_output(raw_lines)

    status_info = {}

    # Process the status information front matter
    if header_index != 0:
        status_info = parse_status_output(raw_lines[:header_index])

    # Filter to just the lines with the events
    event_lines = raw_lines[header_index + 1 :]
    events = []

    # TODO: parse 351 history format
    # "#     DATE      TIME     EVENT   LOCAT  CURR  FREQ GRP SHOT TARGETS"

    for line in event_lines:
        if line and line[0].isdigit():
            result = re.match(
                (
                    r"(?P<num>\d+)\s+"
                    r"(?P<ref>\S+)\s+"
                    r"(?P<date>\S+)\s+"
                    r"(?P<time>\S+)\s+"
                    r"(?P<event>(?:\w| \w)+)\s+"
                    r"(?P<current>[\d\.]+)\s+"
                    r"(?P<freqx>[\d\.]+)\s+"
                    r"(?P<targets>[\w\d\.]+)\s*"
                ),
                line,
                re.ASCII | re.IGNORECASE,
            )

            if not result:
                log.warning(
                    f"Failed to parse HISTORY events due to unexpected format.\nRaw line: {line}"
                )
                return [], status_info

            values = result.groupdict()

            event = {
                "sequence": int(values["ref"]),
                "date": values["date"],
                "time": values["time"],
                "original": line,
                "event": values["event"],  # "Trip"
                "current": float(values["current"]),  # 1.00
                "frequency": float(values["freqx"]),  # 60.0
                "targets": values["targets"],  # "11000000"
            }

            events.append(event)

    return events, status_info


def extract_csv_dicts(lines: list[str]) -> tuple[dict[str, str], list[dict[str, str]]]:
    header = next(iter(csv.DictReader(lines[:2])))
    device_info = {
        "serial_number": header.get("SERIAL NO", ""),
        "FID": header.get("FID", "").split("=")[-1],
        "CID": header.get("CID", ""),
    }

    rows = list(csv.DictReader(lines[2:]))

    return device_info, rows


def parse_cser(lines: list[str]) -> tuple[list[dict], dict]:
    """
    Extract and parse events and device info from ``CSER.TXT``.

    Returns:
        Events and device info (FID, CID, and serial number).
    """
    device_info, rows = extract_csv_dicts(lines)

    events = []
    last_key = list(rows[0].keys())[-1]  # "0A31"

    for row, line in zip(rows, lines[3:], strict=False):
        event = {
            "sequence": int(row["REC_NUM"]),
            "date": row["DATE"],
            "time": row["TIME"],
            "original": line,
            "element": row["ELEMENT"],
        }

        # Handle special lines, like "Relay Powered Up"
        if not row[last_key]:
            row[last_key] = row["STATE"]
            row["STATE"] = ""
        event["state"] = row["STATE"]

        events.append(event)

    return events, device_info


def parse_chistory(lines: list[str]) -> tuple[list[dict], dict]:
    """
    Extract and parse events and device info from ``CHISTORY.TXT``.

    Returns:
        Events and device info (just the FID generally with CHISTORY).
    """
    device_info, rows = extract_csv_dicts(lines)

    events = []

    for row, line in zip(rows, lines[3:], strict=False):
        date = f"{row['MONTH']}/{row['DAY']}/{row['YEAR']}"
        time = f"{row['HOUR']}:{row['MIN']}:{row['SEC']}.{row['MSEC']}"

        event = {
            # NOTE: for CHISTORY, "REC_NUM" is just it's order in the file
            # The actual sequence number is REF_NUM (REF, not REC, easy to miss)
            "sequence": int(row["REF_NUM"]),
            "date": date,
            "time": time,
            "original": line,
            "event": row["EVENT"],  # "Trip"
            "current": float(row["CURRENT"]),  # 1.00
            "frequency": float(row["FREQX"]),  # 60.0
            "targets": row["TARGETS"],  # "11000000"
        }

        events.append(event)

    return events, device_info


def process_events(raw_events: list[dict], dev: DeviceData, dataset: str) -> None:
    """
    Process events into the data model.

    Args:
        raw_events: list of events extracted from an event file
            (SER, CSER, HISTORY, CHISTORY)
        dev: device object to add events to
        dataset: Dataset of the events, e.g. ``ser``, ``CSER.TXT``, ``HISTORY.TXT``
    """
    for raw_event in raw_events:
        event_category = {"host"}  # type: set[str]
        event_type = set()  # type: set[str]
        extra = {}

        # SER/CSER
        if raw_event.get("element"):
            pass
            # Examples of element values:
            # 'Relay', 'Power-up', 'Settings changed', '51G', 'OUT101', 'Group change'
            event_element = raw_event["element"].lower()  # type: str

            if "change" in event_element:
                event_category.add("configuration")
                event_type.add("change")
            elif "power" in event_element and "up" in event_element:
                event_type.add("start")
            elif "archive cleared" in event_element:
                # "SER archive cleared"
                event_category.update({"database", "file"})
                event_type.update({"change", "deletion"})

            action = event_element.replace(" ", "-")  # type: str

            # Examples of event state:
            # 'Enabled', 'Group 1', 'Class P 5', 'Asserted', 'Deasserted'
            event_state = raw_event["state"].lower()
            if "assert" in event_state:
                event_type.add("change")
                action = f"{event_state}-{event_element}"

            if raw_event["element"] and raw_event["state"]:
                message = f"{raw_event['element']} {raw_event['state']}"
            else:
                message = raw_event["element"]

        # HISTORY/CHISTORY
        elif raw_event.get("event"):
            action = raw_event["event"].lower()

            if "trip" in action:
                event_type.add("change")
                message = (
                    f"Trip {raw_event['targets']} "
                    f"(Current: {raw_event['current']}"
                    f"- Frequency: {raw_event['frequency']}"
                )
            else:
                message = raw_event["event"]

            extra["current"] = raw_event["current"]
            extra["frequency"] = raw_event["frequency"]
            extra["targets"] = raw_event["targets"]

        else:
            log.error("Invalid events")
            return

        event = Event(
            action=action,
            category=event_category,
            # date: "09/13/2022" (Month/Day/Year)
            # time: "16:09:12.264"
            created=date_parse(f"{raw_event['date']} {raw_event['time']}"),
            dataset=dataset,
            kind={"event"},
            message=message,
            original=raw_event["original"],
            provider=dev.get_id(),
            # TODO: should sequence be reverse order for SER/CSER?
            # Since "1" in the log is actually the newest event, not the oldest?
            sequence=int(raw_event["sequence"]),
            type=event_type,
            extra=extra,
        )

        if not dev._module:
            event.module = "SELRelay"
        else:
            event.module = dev._module.__name__

        # If a event exists with the same sequence number, update it.
        # Otherwise, it's a new event and don't bother comparing values.
        dev.store("event", event, lookup="sequence")


def extract_cid_content(data: bytes) -> str:
    if not data:
        return ""

    decompressed = zlib.decompress(data)

    # NOTE utf-8-sig is required to remove the
    # Byte Order Mark (BOM) that gets prepended in some cases.
    decoded = decompressed.decode("utf-8-sig")

    return decoded


def process_cid_file(data: bytes, filepath: PurePath, dev: DeviceData) -> str:
    """
    .CID files are zlib-compressed data (zlib-header 0x7801 - No Compression/low).
    The only known CID file currently is ``SET_61850.CID``, which contains XML data.

    This function decompresses the zlib data and saves the decoded text to a new file.
    """
    log.info(f"Extracting data from CID file '{filepath.name}'")

    if not data:
        log.warning(f"Empty data for CID file {filepath.name}")
        return ""

    try:
        extracted = extract_cid_content(data)

        ext = "txt"
        if "<?xml version" in extracted:
            ext = "xml"

        dev.write_file(extracted, f"{filepath.stem}_decompressed.{ext}")

        if not extracted:
            log.warning(f"No data extracted from CID file {filepath.name}")

        return extracted
    except Exception as ex:
        log.error(f"Failed to extract CID file {filepath.name}: {ex}")
        return ""


def _getv(val: dict | Any) -> Any:
    """
    Helper function to handle if a value is either
    in a dict or the value itself.
    """
    if isinstance(val, dict) and "value" in val:
        return val["value"]
    return val


def is_enabled(conf: dict) -> bool:
    return value_is_enabled(conf.get("value", ""))


def value_is_enabled(value: str) -> bool:
    return bool(value.upper() in ("Y", "YES", "ON", "1"))


def clean_id(id_str: str) -> str:
    cleaned = utils.clean_replace(id_str, "_", " ,!:")
    return re.sub("_{2,}", "_", cleaned).strip("_")


def split_lines(val: bytes | str) -> list[str]:
    if isinstance(val, bytes):
        val = val.decode("ascii")
    return [x.strip() for x in val.strip().splitlines() if x]
