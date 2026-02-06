"""
Parsing of files from Sage RTUs.

Works with 2400 and 3030M models, and should work with others.

Authors

- Christopher Goes
- Ryan Vrecenar
"""

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import datetime
from pathlib import PurePath, PurePosixPath
from typing import IO, Any, Final

from peat import DeviceData, log, utils
from peat.data.models import Event, Interface, User

ElasticType = None | int | bool | str | float


def _convert_to_elastic(_input: str) -> ElasticType:
    """
    Cast input to inferred type (int, bool, None) for Elasticsearch.
    """
    try:
        return int(_input)
    except Exception:
        try:
            return float(_input)
        except Exception:
            if _input == "N":
                return False
            elif _input == "Y":
                return True
            elif _input.upper() == "NONE":
                return None
            else:
                return _input


def _store_dict_items(elem_tree: ET.Element, element_dict: dict[str, ElasticType]) -> None:
    for item in elem_tree.items():
        try:
            element_dict[item[0]] = int(item[1])
        except Exception:
            if item[1] == "N":
                element_dict[item[0]] = False
            elif item[1] == "Y":
                element_dict[item[0]] = True
            else:
                element_dict[item[0]] = item[1]


def _parse_element_into_dict(element: ET.Element, info: dict, key_map: dict) -> None:
    if element.tag in key_map and element.text and element.text.lower() != "changeme":
        info[key_map[element.tag]] = element.text.strip()


def parse_access_xml(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse users and access permissions out of ``ACCESS.XML``.
    """
    access_info = {}

    root = ET.fromstring(f_handle.read())

    access_info["users"] = []
    for user in root:
        user_info: dict[str, Any] = {
            "id": user.get("ID", ""),
        }

        if user.get("SESTIMEOUT"):
            user_info["session_timeout"] = int(user.attrib["SESTIMEOUT"])

        for elem in user:
            if elem.tag == "DESC" and elem.text:
                user_info["description"] = elem.text
            elif elem.tag == "PASSWORD" and elem.text:
                user_info["password"] = elem.text
            elif elem.tag == "ACCESS":
                user_info["permissions"] = {}
                _store_dict_items(elem, user_info["permissions"])

        access_info["users"].append(user_info)

    if not access_info["users"]:
        return

    device_info["access_info"] = access_info


def process_access_xml(dev: DeviceData, info: dict) -> None:
    """
    Process data extracted from ``ACCESS.XML`` into the PEAT device data model.
    """
    users = info["users"]
    for user_info in users:
        user = User(
            description=user_info.get("description", ""),
            id=user_info.get("id", ""),
            name=user_info.get("id", ""),
        )

        if user_info.get("session_timeout"):
            user.extra["session_timeout"] = user_info["session_timeout"]

        if user_info.get("permissions"):
            user.extra["sage_permissions"] = user_info["permissions"]
            # Add any permissions that are enabled to set of permissions for user
            # e.g. if FTP="Y", then "FTP" would be added to user.permissions
            for perm_key, perm_value in user_info["permissions"].items():
                if perm_value is True:
                    user.permissions.add(perm_key)

        dev.store("users", user)


def parse_rtu_setup(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``rtusetup.xml``.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    info = {}

    root = ET.fromstring(f_handle.read())

    cpu = root.findall("CPU")
    if not cpu:
        log.warning("No 'CPU' element found in rtusetup.xml")
        return
    cpu = cpu[0]

    rtu_key_map = {
        "NAME": "name",
        "APPFILE": "app_file",
        "PARTNO": "part_number",
        "HWVER": "hw_ver",
        "USERID": "user_id",
        "SERIALNUM": "serial_number",
        "MFGNAME": "manufacturer_name",
        "RUNMODE": "run_mode",
        "TYPE": "model",
    }

    rtu = cpu.findall("RTU")
    if not rtu:
        log.warning("No 'RTU' element found in rtusetup.xml")
    else:
        rtu = rtu[0]

        for elem in rtu:
            _parse_element_into_dict(elem, info, rtu_key_map)

        vxworks = rtu.findall("VXWORKS")
        if not vxworks:
            log.warning("No 'VXWORKS' element found in rtusetup.xml")
        else:
            for elem in vxworks[0]:
                if not elem.text or elem.text == "ChangeMe":
                    continue

                if elem.tag == "VXCREATED":
                    os_date = datetime.strptime(elem.text, "%b %d %Y")
                    info["vx_created"] = os_date.isoformat(sep="-")
                elif elem.tag == "VXVERSION":
                    info["vx_version"] = elem.text.strip()

    config_tree = cpu.findall("CONFIG")
    if not config_tree:
        log.warning("No 'CONFIG' element found in rtusetup.xml")
    else:
        for elem in config_tree[0]:
            if not elem.text or elem.text == "ChangeMe":
                continue

            if elem.tag == "NAME":
                info["config_version"] = elem.text
            elif elem.tag == "LASTDATE":
                try:
                    fw_date = datetime.strptime(elem.text, "%m-%d-%y")
                except ValueError:
                    # Date can be '19' or '2019', must handle both accordingly
                    fw_date = datetime.strptime(elem.text, "%m-%d-%Y")
                info["config_timestamp"] = fw_date.isoformat(sep="-")
            elif elem.tag == "REVISION":
                info["config_revision"] = elem.text

    device_info["rtusetup_info"] = info


def process_rtusetup_info(dev: DeviceData, info: dict) -> None:
    """
    Process data extracted from ``rtusetup.xml`` into the PEAT device data model.
    """
    if info.get("name"):
        dev.description.description = info["name"]
    if info.get("app_file"):
        dev.related.files.add(info["app_file"])
    if info.get("part_number") and not dev.part_number:
        dev.part_number = info["part_number"]
    if info.get("user_id"):
        dev.related.user.add(info["user_id"])
    if info.get("serial_number") and not dev.serial_number:
        dev.serial_number = info["serial_number"]
    if info.get("run_mode") and not dev.run_mode:
        dev.run_mode = info["run_mode"]
    if info.get("model") and not dev.description.model:
        dev.description.model = info["model"]
    if info.get("vx_created") and not dev.os.timestamp:
        dev.os.timestamp = utils.parse_date(info["vx_created"])


def parse_tte(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``tte.xml`` to find time trigger ethernet settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    tte_settings = {}
    root = ET.fromstring(f_handle.read())
    entry = 0

    for tte_elem in root:
        entry_iter = f"entry_{entry}"
        tte_settings[entry_iter] = {}
        for tte_item in tte_elem.items():
            if tte_item[1] != "":
                tte_settings[entry_iter][tte_item[0]] = _convert_to_elastic(tte_item[1])
        entry += 1

    tte_settings["note"] = "Time Triggered Ethernet"
    device_info["tte"] = tte_settings


def parse_time_elements(_time: ET.Element, device_info: dict) -> None:
    """
    From TIME branch in ElementTree in time, parse out version
    and date of update for OS.
    """
    time_settings = {}

    for item in _time.items():
        time_settings[item[0]] = _convert_to_elastic(item[1])

    for element in _time:
        time_settings[element.tag] = {}
        for item in element.items():
            time_settings[element.tag][item[0]] = _convert_to_elastic(item[1])

    device_info["time_settings"] = time_settings


def parse_gblfrz_elements(gblfrz: ET.Element, device_info: dict) -> None:
    """
    From GBLFRZ branch in ElementTree in time, parse out version
    and date of update for OS.
    """
    gblfrz_settings = {}

    _store_dict_items(gblfrz, gblfrz_settings)

    device_info["gblfrz_settings"] = gblfrz_settings


def parse_gps_elements(gps: ET.Element, device_info: dict) -> None:
    """
    From GPS branch in ElementTree in time, parse out version
    and date of update for OS.
    """
    gps_settings = {}

    for item in gps.items():
        gps_settings[item[0]] = _convert_to_elastic(item[1])

    device_info["gps_settings"] = gps_settings


def parse_time(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse xml tree from ``time.xml`` to find ``time``, ``gblfrz``, and ``gps`` settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    root = ET.fromstring(f_handle.read())

    _time = root.findall("TIME")[0]
    parse_time_elements(_time, device_info)

    gblfrz = root.findall("GBLFRZ")[0]
    parse_gblfrz_elements(gblfrz, device_info)

    gps = root.findall("GPS")[0]
    parse_gps_elements(gps, device_info)


def bootline_parse(bootline: str | dict) -> dict[str, str]:
    """
    Parse useful information out of vxworks bootline string,
    which is embedded in ``bootline.xml``.
    """
    if isinstance(bootline, str):
        bootline_dict = {}
        cleaned = bootline.strip().replace(",0)", ",0) ").replace("host:", "host=")
        sections = [x.strip() for x in cleaned.split(" ") if x.strip()]

        for section in sections:
            parts = section.split("=")
            bootline_dict[parts[0]] = parts[1]
    else:
        bootline_dict = bootline

    # e: ethernet ip
    # b: blackplane IP (optional)
    # h: host IP
    # g: gateway IP
    # f: flags
    # tn: target name
    # s: startup script (optional)
    # o: other
    _key_map = {
        "e": "ethernet_ip",
        "b": "backplane_ip",
        "h": "host_ip",
        "g": "gateway_ip",
        "f": "flags",
        "tn": "target_name",
        "s": "startup_script",
        "o": "other",
    }

    info = {}

    for key, value in bootline_dict.items():
        if key in _key_map:
            key = _key_map[key]
        info[key] = _convert_to_elastic(value)

    # Handle if in format "192.0.2.1:ffffff00"
    for e_key in ["ethernet", "backplane", "host", "gateway"]:
        if ":" in info.get(f"{e_key}_ip", ""):
            ip, subnet_mask = _parse_eth_str(info[f"{e_key}_ip"])
            info[f"{e_key}_ip"] = ip
            info[f"{e_key}_subnet_mask"] = subnet_mask

    return info


def _parse_eth_str(eth_val: str) -> tuple[str, str]:
    """
    Parse string format "IP:Subnet", with the subnet being hex-encoded.
    Example: ``"192.0.2.1:ffffff00"``
    """
    ip = eth_val[: eth_val.index(":")]

    h_subnet = eth_val[eth_val.index(":") + 1 :]
    subnet_bytes = (h_subnet[0:2], h_subnet[2:4], h_subnet[4:6], h_subnet[6:8])
    subnet_mask = ".".join([f"{int(n, 16)}" for n in subnet_bytes])

    return ip, subnet_mask


def parse_bootline_xml(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``bootline.xml`` to find boot options including default
    IP address, location of operating system, hostname, username and password.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    root = ET.fromstring(f_handle.read())
    bootline = root.findall("BOOTLINE")[0]
    device_info["bootline_from_xml"] = bootline_parse(bootline.attrib)


def process_bootline(dev: DeviceData, data: dict[str, str]) -> None:
    """
    Process data extracted from VxWorks bootline into the PEAT device data model.
    """
    boot_file = data.get("file")
    if not boot_file and data.get("host") and "/" in data["host"]:
        boot_file = data["host"]

    if boot_file:
        b_path = PurePosixPath(boot_file)
        dev.related.files.add(str(b_path))
        dev.firmware.file.path = b_path
        dev.firmware.file.directory = str(b_path.parent)
        dev.firmware.file.name = b_path.name
        dev.firmware.file.type = "file"

    if data.get("ethernet_ip") and utils.is_ip(data["ethernet_ip"]):
        dev.related.ip.add(data["ethernet_ip"])

        iface = dev.retrieve("interface", {"ip": data["ethernet_ip"]})

        if not iface:
            iface = Interface(
                ip=data["ethernet_ip"],
                subnet_mask=data.get("ethernet_subnet_mask", ""),
                gateway=data.get("gateway_ip", ""),
                type="ethernet",
            )
            dev.store("interface", iface, lookup="ip")
        else:
            if not iface.subnet_mask and data.get("ethernet_subnet_mask"):
                iface.subnet_mask = data["ethernet_subnet_mask"]
            if not iface.gateway and data.get("gateway_ip") and utils.is_ip(data["gateway_ip"]):
                iface.gateway = data["gateway_ip"]

    if data.get("backplane_ip"):
        dev.related.ip.add(data["backplane_ip"])

    if data.get("host_ip") and utils.is_ip(data["host_ip"]):
        dev.related.ip.add(data["host_ip"])

    if data.get("gateway_ip") and utils.is_ip(data["gateway_ip"]):
        dev.related.ip.add(data["gateway_ip"])

    if data.get("raw_bootline"):
        dev.firmware.extra["bootline"] = data["raw_bootline"]


def parse_ether(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``ethernet.xml`` to find route settings and
    ethernet port settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    ether_settings = {}
    root = ET.fromstring(f_handle.read())
    entry = 0

    for ether_elem in root:
        ether_iter = f"entry_{entry}"
        ether_settings[ether_iter] = {}

        # Save ethernet parameters including ID, Password, Name, etc
        for item in ether_elem.items():
            ether_settings[ether_iter][item[0]] = item[1]

        # Save Routes
        routes_elem = ether_elem.findall("ROUTES")
        if not routes_elem:
            log.warning("Failed to find 'ROUTES' element in ether_elem")
            continue

        routes = ether_elem.findall("ROUTES")[0]
        routes_settings = {}

        for route in routes:
            route_fields = route.items()

            # Route_ID uses first route field which is value of ID
            route_id = route_fields[0][1]

            for field in route_fields[1:]:
                routes_settings[field[0]] = _convert_to_elastic(field[1])

            ether_settings[ether_iter][f"route_{route_id}"] = routes_settings

        entry += 1

    device_info["ethernet"] = ether_settings


def parse_firewall_rule(firewall_line: str, firewall_rule: dict) -> None:
    delimiters = "block in ", "from ", " to ", " port = "
    regex_pattern = "|".join(map(re.escape, delimiters))

    # Split on grammar, drop null first byte
    firewall_syntax = re.split(regex_pattern, firewall_line)[1:]
    proto = firewall_syntax[0].rstrip() if not firewall_syntax[0] == "" else None

    firewall_rule["protocol"] = proto
    firewall_rule["from_cdir"] = firewall_syntax[1]
    firewall_rule["to_cdir"] = firewall_syntax[2]

    # Hard coded assumption, port = is last term
    if "port = " in firewall_line:
        firewall_rule["port"] = firewall_syntax[-1]


def parse_firewall(f_handle: IO[bytes], device_info: dict) -> None:
    firewall_rules = {}
    lines = f_handle.read().decode("utf-8")

    i = 0
    for line in lines.split("\n"):
        # Remove comments from firewall rules
        if len(line.lstrip()) > 1 and line.lstrip()[0] != "#" and line.lstrip()[0:2] != "//":
            i += 1
            firewall_rules[f"entry_{i}"] = {}
            firewall_entry = firewall_rules[f"entry_{i}"]
            firewall_entry["original_rule"] = line
            firewall_entry["semantic_rule"] = {}
            parse_firewall_rule(line, firewall_entry["semantic_rule"])
        else:
            continue

    device_info["firewall_settings"] = firewall_rules


def parse_isagraf(f_handle: IO[bytes], device_info: dict) -> None:
    isagraf_data = f_handle.read().decode("utf-8")
    isagraf_version = isagraf_data.split(" ")[1]

    device_info["isagraf"] = {}
    device_info["isagraf"]["version"] = isagraf_version.rstrip()
    device_info["isagraf"]["note"] = "Soft Logic Controller, including runtime, and dev tools"


def parse_startup_script(f_handle: IO[bytes], device_info: dict) -> None:
    script_data = f_handle.read().decode("utf-8")
    device_info["startup_script"] = script_data


def parse_vxworks_script(f_handle: IO[bytes], device_info: dict) -> None:
    script_data = f_handle.read().decode("utf-8")
    device_info["vxworks_script"] = script_data


def parse_private_key(f_handle: IO[bytes], device_info: dict) -> None:
    key_data = f_handle.read().decode("utf-8")
    device_info["server_private_key"] = key_data


def parse_certificate(f_handle: IO[bytes], device_info: dict) -> None:
    cert_data = f_handle.read().decode("utf-8")
    device_info["server_certificate"] = cert_data


def parse_ike_config(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ike_data = ""
    lines = f_handle.read().decode("utf-8")

    for line in lines.split("\n"):
        # Remove comments from firewall rules
        if len(line.lstrip()) > 0 and not line.lstrip()[0] == "#":
            ike_data += line

    device_info["ike"]["config"] = ike_data


def parse_ike_ca(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ca_data = f_handle.read().decode("utf-8")
    device_info["ike"]["telvent_cert_auth"] = ca_data


def parse_ike_privkey(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ca_data = f_handle.read().decode("utf-8")
    device_info["ike"]["privkey"] = ca_data


def parse_ike_cert(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ca_data = f_handle.read().decode("utf-8")
    device_info["ike"]["cert"] = ca_data


def parse_port_comm_settings(proto: ET.Element, port_settings: dict[str, ElasticType]) -> None:
    comms = proto.findall("COMM")[0]
    comm_settings = {}

    _store_dict_items(comms, comm_settings)

    port_settings["comm_settings"] = comm_settings


def parse_port_proto_settings(
    proto_name: str, proto: ET.Element, port_settings: dict[str, ElasticType]
) -> None:
    protocol_field = proto.findall(proto_name)[0]
    _store_dict_items(protocol_field, port_settings["protocol"])

    for child in protocol_field:
        _store_dict_items(child, port_settings["protocol"])

    # TODO
    """
    protocol_params = protocol_field.findall('AO_MAP')[0]
    store_dict_items(protocol_params, port_settings['protocol'])

    protocol_params = protocol_field.findall('AI_MAP')[0]
    store_dict_items(protocol_params, port_settings['protocol'])
    """


def parse_port(f_handle: IO[bytes], device_info: dict) -> None:
    if "ports" not in device_info:
        device_info["ports"] = {}

    port_settings = {}

    port = ET.fromstring(f_handle.read())
    proto = port.findall("PROTOCOL")[0]

    for item in port.items():
        if not item[0] == "VER" and not item[0] == "PNT":
            port_settings[item[0]] = item[1]
        elif item[0] == "PNT":
            port_name = item[1]

    for item in proto.items():
        if item[0] == "TYPE":
            if not item[1] == "NONE":
                port_settings["protocol"] = {}
                port_settings["protocol"]["name"] = item[1]
                parse_port_comm_settings(proto, port_settings)
                parse_port_proto_settings(item[1], proto, port_settings)
            else:
                port_settings["protocol"] = None

    device_info["ports"][f"port_{port_name}"] = port_settings


def parse_features(f_handle: IO[bytes], device_info: dict) -> None:
    features = ET.fromstring(f_handle.read())
    protocols = features.findall("PROTOCOLS")[0]

    device_info["feature_protocols"] = {}
    for proto in protocols:
        device_info["feature_protocols"][proto.text] = {}
        for item in proto.items():
            device_info["feature_protocols"][proto.text][item[0]] = _convert_to_elastic(item[1])


def parse_3835(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    c3835 = root.findall("C3835")
    cards = {}

    for i in c3835:
        # Set key for cards dict
        devid = ""
        card = {}

        for item in i.items():
            if item[0] == "DEVID":
                devid = item[1]
            else:
                card[item[0]] = _convert_to_elastic(item[1])

        cards[devid] = card

    device_info["c3835"] = cards


def parse_dcana(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    dcana_settings = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            grandchild_dict = {}
            for item in grandchild.items():
                if item[0] == "PNT":
                    key = item[1]
                else:
                    grandchild_dict[item[0]] = _convert_to_elastic(item[1])
                child_dict[key] = grandchild_dict

        dcana_settings[child.tag] = child_dict

    device_info["dcana_settings"] = dcana_settings


def parse_calc(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    calc = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

            for grand_child in child:
                grand_child_dict = {}

                # Traverse children scope and append to dictionary
                key = ""
                for item in grand_child.items():
                    if item[0] == "PN":
                        key = item[1]
                    else:
                        grand_child_dict[item[0]] = _convert_to_elastic(item[1])
                    if key != "":
                        child_dict[key] = grand_child_dict

        calc[child.tag] = child_dict

    device_info["calc"] = calc


def parse_rtu_sts(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    rtu_settings = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

            for grand_child in child:
                grand_child_dict = {}
                for item in grand_child.items():
                    if item[0] == "PNT":
                        key = item[1]
                    else:
                        grand_child_dict[item[0]] = _convert_to_elastic(item[1])
                    child_dict[key] = grand_child_dict

        rtu_settings[child.tag] = child_dict

    device_info["rtu_settings"] = rtu_settings


def parse_timing(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    timing_settings = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        timing_settings[child.tag] = child_dict

    device_info["timing_parameters"] = timing_settings


def parse_sfb(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    sfb_cards = {}

    for child in root:
        devid = child.items()[0]
        sfb_type = child.items()[1]

        child_dict = {}
        child_dict[sfb_type[0]] = _convert_to_elastic(sfb_type[1])
        sfb_cards[devid[1]] = child_dict

    device_info["sfb_cards"] = sfb_cards


def parse_acc_rate(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    acc_param = root.findall("ACC_PARAM")

    acc_rate = {}
    for device in acc_param:
        device_acc_param = {}
        for item in device.items():
            if item[0] == "DEVID":
                key = f"DevID_{item[1]}"
            else:
                device_acc_param[item[0]] = _convert_to_elastic(item[1])
        acc_rate[key] = device_acc_param

    device_info["acc_param"] = acc_rate


def parse_alarming(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    alarm_child = root.findall("ALARMS")[0]

    alarms = {}
    for item in alarm_child.items():
        alarms[item[0]] = _convert_to_elastic(item[1])

    for map_child in alarm_child:
        for item in map_child.items():
            alarms[f"{map_child.tag}_{item[0]}"] = _convert_to_elastic(item[1])

    device_info["alarming"] = alarms


def parse_alarms(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    alarm_child = root.findall("ALARMS")[0]

    alarms = {}
    for device in alarm_child:
        alarm_pnt = {}
        for item in device.items():
            if item[0] == "PNT":
                key = item[1]
            else:
                alarm_pnt[item[0]] = _convert_to_elastic(item[1])
        alarms[key] = alarm_pnt

    device_info["alarms"] = alarms


def parse_almdev(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    dev_attrb = root.findall("DEVICE_ATTRIBUTES")[0]
    almdev = {}

    for child in dev_attrb:
        attribute = {}
        for item in child.items():
            attribute[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            for item in grandchild.items():
                attribute[item[0]] = _convert_to_elastic(item[1])

        almdev[child.tag] = attribute

    device_info["almdev"] = almdev


def parse_bbdi(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    bbdi = {}

    for item in root.items():
        bbdi[item[0]] = _convert_to_elastic(item[1])

    points = root.findall("POINTS")[0]

    for child in points:
        point = {}
        point_items = child.items()
        key = ""

        for item in point_items:
            if item[0] == "PNT":
                key = item[1]

        for item in point_items:
            if item[0] != "PNT":
                point[item[0]] = _convert_to_elastic(item[1])

        bbdi[key] = point

    device_info["bbdi"] = bbdi


def parse_cbc(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    cbc = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            grandchild_dict = {}
            for item in grandchild.items():
                if item[0] == "PNT" or item[0] == "NUM":
                    key = item[1]
                else:
                    grandchild_dict[item[0]] = _convert_to_elastic(item[1])
                child_dict[key] = grandchild_dict

        cbc[child.tag] = child_dict

    device_info["cbc_config"] = cbc


def parse_ast(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    ast = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            grandchild_dict = {}

            for item in grandchild.items():
                if item[0] == "PNT" or item[0] == "NUM":
                    key = item[1]
                else:
                    grandchild_dict[item[0]] = _convert_to_elastic(item[1])
                child_dict[key] = grandchild_dict

            for ggchild in grandchild:
                ggchild_dict = {}
                for item in ggchild.items():
                    if item[0] == "PNT" or item[0] == "NUM":
                        gkey = item[1]
                    else:
                        ggchild_dict[item[0]] = _convert_to_elastic(item[1])
                    child_dict[f"{grandchild.tag}_{gkey}"] = ggchild_dict

        ast[child.tag] = child_dict

    device_info["ast_config"] = ast


def parse_anunctor(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    annunciator = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            gchild_items = grandchild.items()
            child_dict[gchild_items[0][1]] = _convert_to_elastic(gchild_items[1][1])
        annunciator[child.tag] = child_dict

    device_info["annunciator"] = annunciator


def parse_com_assignments(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    com_assignments = {}

    for port in root:
        port_items = port.items()
        # First entry is Num
        key = port_items[0][1]

        child_dict = {}
        for item in port_items[1:]:
            child_dict[item[0]] = _convert_to_elastic(item[1])
        com_assignments[f"port_{key}"] = child_dict

    device_info["com_assignments"] = com_assignments


def parse_sprcodes(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    spr_codes = {}

    for spr_code in root:
        spr_items = spr_code.items()

        # First entry is PNT
        key = spr_items[0][1]
        spr_codes[key] = _convert_to_elastic(spr_items[1][1])

    device_info["spr_code_map"] = spr_codes


def parse_leds(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    leds = {}

    for child in root:
        led_dict = {}

        for grandchild in child:
            gchild_items = grandchild.items()
            key = gchild_items[0][1]
            led_dict[key] = {}
            for item in gchild_items[1:]:
                led_dict[key][item[0]] = _convert_to_elastic(item[1])
        leds[child.tag] = led_dict

    device_info["leds"] = leds


def parse_relays(f_handle: IO[bytes], device_info: dict) -> None:
    # TODO: may be losing items from Relay tree, double check from config again
    root = ET.fromstring(f_handle.read())
    relay_tree = root.findall("RELAYS")[0]
    relays = {}

    for child in relay_tree:
        relay_dict = {}
        child_items = child.items()
        key = child_items[0][1]

        for item in child_items[1:]:
            relay_dict[item[0]] = _convert_to_elastic(item[1])

        relays[key] = relay_dict

    device_info["relays"] = relays


def parse_nrgcalc(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())

    nrgcalc_tree = root.findall("NRGCALC_PARAM")[0]
    nrgcalcs = {}
    nrgcalcs["note"] = "Energy Calc Parameters"

    # Set top level fields
    for item in nrgcalc_tree.items():
        nrgcalcs[item[0]] = _convert_to_elastic(item[1])

    for child in nrgcalc_tree:
        child_dict = {}
        child_items = child.items()

        if child.tag == "DI_LIST":
            for grandchild in child:
                gc_dict = {}
                gc_items = grandchild.items()
                key = gc_items[0][1]

                for item in gc_items[1:]:
                    gc_dict[item[0]] = _convert_to_elastic(item[1])

                nrgcalcs[f"di_list_{key}"] = gc_dict
        else:
            key = child_items[0][1]
            for item in child_items[1:]:
                child_dict[item[0]] = _convert_to_elastic(item[1])

            ais = []
            for grandchild in child:
                gc_dict = {}
                gc_items = grandchild.items()

                for item in gc_items:
                    gc_dict[item[0]] = _convert_to_elastic(item[1])

                ais.append(gc_dict)

            child_dict["ais"] = ais
            nrgcalcs[key] = child_dict

    device_info["nrgcalc_settings"] = nrgcalcs


def parse_bbrelay(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            gchild_dict = {}
            gchild_items = grandchild.items()
            key = gchild_items[0][1]

            for item in gchild_items[1:]:
                gchild_dict[item[0]] = _convert_to_elastic(item[1])

            child_dict[f"bb_{key}"] = gchild_dict

    device_info["bb_relays"] = child_dict


def parse_btstconf(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    btests = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for gchild in child:
            gchild_dict = {}
            for element in gchild:
                elem_dict = {}
                items = element.items()
                key = items[0][1]

                for item in items[1:]:
                    elem_dict[item[0]] = _convert_to_elastic(item[1])
                gchild_dict[key] = elem_dict

            child_dict[gchild.tag] = gchild_dict

        btests[child.tag] = child_dict

    device_info["btest_config"] = btests


def parse_aci(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())

    fmr = root.findall("FMR")[0]
    fmr_dict = {}
    fmr_dict["note"] = "Oracle/Cisco ATG Customer Intellegence?"

    for item in fmr.items():
        fmr_dict[item[0]] = _convert_to_elastic(item[1])

    device_info["aci_db"] = fmr_dict


def parse_aci1250(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    aci = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for gchild in child:
            gchild_dict = {}

            for item in gchild.items():
                gchild_dict[item[0]] = _convert_to_elastic(item[1])

            for element in gchild:
                items = element.items()
                for item in items:
                    gchild_dict[item[0]] = _convert_to_elastic(item[1])

                if element.tag == "SENSOR":
                    for sensor in element:
                        elem_dict = {}

                        sensor_items = sensor.items()
                        skey = sensor_items[0][1]

                        for item in sensor_items[1:]:
                            elem_dict[item[0]] = _convert_to_elastic(item[1])

                        gchild_dict[f"sensor {skey}"] = elem_dict

            child_dict[gchild.tag] = gchild_dict

        aci[child.tag] = child_dict

    device_info["aci1250_config"] = aci


def parse_userlog_settings_xml(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``userlog.xml`` to find logging settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    userlog_settings = {}
    root = ET.fromstring(f_handle.read())

    userlog = root.findall("USRLOG_PARAM")[0]
    for item in userlog.items():
        if item[0] == "TASK_ENABLED":
            userlog_settings["userlog_enabled"] = _convert_to_elastic(item[1])
        elif item[0] == "NUM_EVENTS":
            userlog_settings["userlog_num_events"] = _convert_to_elastic(item[1])

    device_info["userlog_settings"] = userlog_settings


def parse_cmdlog_settings_xml(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    cmdlog_settings = {}

    for child in root:
        for item in child.items():
            cmdlog_settings[item[0]] = _convert_to_elastic(item[1])

    device_info["cmdlog_settings"] = cmdlog_settings


def parse_soelog_settings_xml(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    soelog_settings = {}

    for child in root:
        for item in child.items():
            soelog_settings[item[0]] = _convert_to_elastic(item[1])

    device_info["soelog_settings"] = soelog_settings


def parse_ipcom_syslog(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse ``syslog`` and ``syslog.0`` files from ``ipcom/`` directory on the Sage.
    """
    # TODO: unit test
    data = f_handle.read().decode()
    events = []
    lines = [x.strip() for x in data.strip().splitlines() if x.strip()]

    for line in lines:
        parts = [x.strip() for x in line.split(": ") if x.strip()]

        event = {
            "timestamp": parts[0],
            "raw_task": parts[1],
            # "iptelnets" which is actually "ipcom_telnetspawn" in task list
            # However, the Task ID here actually resolves to ipcom_telnetd
            "short_task_name": parts[1].split("[")[0],
            "task_id": parts[1].split("[")[1].split("]")[0],
            "level": parts[2],
            "service_name": parts[3].replace(":", "").strip(),
            "message": ": ".join(parts[4:]),
            "original": line,
        }

        events.append(event)

    if not device_info.get("ipcom_syslog_events"):
        device_info["ipcom_syslog_events"] = []

    device_info["ipcom_syslog_events"].extend(events)


def process_ipcom_syslog(dev: DeviceData, events: list[dict]) -> None:
    """
    Process parsed ``ipcom/syslog`` events into the PEAT device data model.
    """
    for e_dict in events:
        event = Event(
            category={"network", "process", "session"},
            created=utils.parse_date(e_dict["timestamp"]),
            dataset="ipcom_syslog",
            kind={"event"},
            message=e_dict["message"],
            module="Sage",
            original=e_dict["original"],
            outcome="failure" if "error" in e_dict["level"].lower() else "unknown",
            provider=dev.ip,
            type={"connection"},
            extra={
                "raw_task": e_dict["raw_task"],
                "short_task_name": e_dict["short_task_name"],
                "task_id": e_dict["task_id"],
                "service_name": e_dict["service_name"],
                "level": e_dict["level"].lower(),
            },
        )

        if "error" in e_dict["level"].lower():
            event.type.add("error")
        if "ipcom_accept" in event.message:
            event.type.add("access")

        dev.store("event", event)


def parse_logfiles(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse the contents of ``SYSLOG.LOG``, ``USERLOG.LOG``, and ``soelog.txt``.

    This creates a list of dicts with structured event information.

    Known locations of logfiles:

    - ``/ata0a/Webfiles/LOGS/SYSLOG.LOG``
    - ``/ata0a/Webfiles/LOGS/USERLOG.LOG``
    - ``/ramDrv/soelog.txt``
    """
    data = f_handle.read().decode()

    # Replace NUL characters with spaces
    data = re.sub("[\x00]", " ", data)

    lines = [x.strip() for x in data.strip().splitlines() if x.strip()]

    # First line with "NextSlot" can be ignored.
    if "NextSlot" in lines[0]:
        lines = lines[1:]

    # SYSLOG.LOG has events across two separate lines
    if "DT=" not in data:
        lines = ["\n".join(x) for x in zip(lines[0::2], lines[1::2], strict=False)]

    events = []

    for raw_line in lines:
        # USERLOG.LOG, soelog.txt
        if raw_line.startswith("<REC"):
            # ID: identifier? NOTE: these are NOT sequential by time
            # DT: date. Ex: 01/01/2025
            # TM: time. Ex: 00:00:00.000

            # USERLOG.LOG: ID, DT, TM, TYPE, TXT
            #   TYPE: "Logged Out"
            #   TXT: "192.0.2.20-FTP, Admin"

            # soelog.txt: ID, DT, TM, VAL, PN, DN
            #   VAL: "0" or "1"
            #   PN: "MAX LOGIN FAILURES EXCEEDED"
            #   DN: "RTU Internal Status"

            line_tag = ET.fromstring(raw_line)
            pairs = {k.strip(): v.strip() for k, v in line_tag.attrib.items()}

            event = {
                "timestamp": f"{pairs['DT']} {pairs['TM']}",
                # NOTE: the events in the file are not listed in order of sequence!
                # HOWEVER, the ID= field is an integer that IS a proper ordered sequence.
                "id": int(pairs["ID"]),
                "original": raw_line,
                "extra": {},
            }

            # USERLOG.LOG
            if pairs.get("TYPE"):
                event["message"] = f"{pairs['TYPE']} {pairs['TXT']}"

                # logged in => 192.0.2.1-TSHELL, Admin, LCL_DB
                # logged out => 192.0.2.1-TSHELL, Admin
                # logged in => 192.0.2.1-FTP, Admin, LCL_DB
                # logged out => 192.0.2.1-FTP, Admin
                if "logged" in pairs["TYPE"].lower() and pairs["TXT"].count(".") >= 3:
                    dash_parts = pairs["TXT"].partition("-")
                    event["extra"]["ip"] = dash_parts[0].strip()
                    comma_parts = dash_parts[2].split(",")
                    event["extra"]["service"] = comma_parts[0].strip()
                    if event["extra"]["service"] == "TSHELL":
                        event["extra"]["service"] = "Telnet"
                    event["extra"]["user"] = comma_parts[1].strip()
                # Power Up => RTU Started Up, Mode: NORMAL
                elif "Mode:" in pairs["TXT"]:
                    event["extra"]["mode"] = pairs["TXT"].split("Mode:")[1].strip()

            # soelog.txt
            if pairs.get("VAL"):
                event["extra"]["VAL"] = int(pairs["VAL"])
                event["message"] = pairs["PN"]
                # This seems to always be "RTU Internal Status"
                event["extra"]["DN"] = pairs["DN"]
                if pairs["DN"] != "RTU Internal Status":
                    event["message"] += " " + pairs["DN"]

        # SYSLOG.LOG
        else:
            line = re.sub(r" {2,}", " ", raw_line).strip()

            chunks = line.split("\n")
            m_parts = chunks[0].strip().split(" ")

            event = {
                "id": int(m_parts[0]),
                "timestamp": " ".join(m_parts[1:2]),
                "message": chunks[1].strip(),
                "original": raw_line,
                "extra": {
                    # This seems to always be "startup"
                    "stage": m_parts[3],
                    # "GPST task"
                    # "m1_uif"
                    # "startup"
                    # "inCrashMode"
                    "task": " ".join(m_parts[4:]),
                },
            }

        events.append(event)

    # TODO: return a list instead of mutating device_info
    if not device_info.get("raw_events"):
        device_info["raw_events"] = []

    device_info["raw_events"].extend(events)


def process_logfile_events(dev: DeviceData, events: list[dict]) -> None:
    for e_dict in events:
        event = Event(
            created=utils.parse_date(e_dict["timestamp"]),
            dataset="logfiles",
            kind={"event"},
            message=e_dict["message"],
            module="Sage",
            original=e_dict["original"],
            provider=dev.ip,
            sequence=e_dict["id"],
            extra={**e_dict["extra"]},
        )

        if event.extra.get("TYPE"):  # USERLOG.LOG
            event.dataset = "userlog"
        elif event.extra.get("DN"):  # soelog.txt
            event.dataset = "soelog"
        elif event.extra.get("stage"):  # SYSLOG.LOG
            event.dataset = "syslog_file"
        else:  # shouldn't ever hit this branch
            event.dataset = "unknown_log_file"

        lower_msg = event.original.lower()

        if event.extra.get("TYPE"):
            e_type = event.extra["TYPE"].lower()

            event.action = e_type.replace(" ", "-")

            if "power" in e_type:
                event.category.add("host")
                event.type.add("start")

            elif e_type.startswith("logged"):
                event.category.add("authentication")
                event.category.add("session")
                event.outcome = "success"
                event.type.add("access")

                if "logged in" in e_type:
                    event.type.add("start")
                elif "logged out" in e_type:
                    event.type.add("end")

        # NOTE: rtu_sts.xml lists the possible event strings for soelog.txt

        if "logged in" in lower_msg:
            event.outcome = "success"

        if "login" in lower_msg or "logged in" in lower_msg:
            event.category.add("authentication")
            event.type.add("access")

        if "login failure" in lower_msg:
            event.type.add("denied")

        # "LOGIN FAILURE"
        # "TIME SRC FAIL"
        if "failure" in lower_msg or "fail " in lower_msg:
            event.outcome = "failure"

        if "startup" in event.original.lower() or "started up" in event.original.lower():
            event.type.add("start")

        if event.extra.get("ip"):
            dev.related.ip.add(event.extra["ip"])
            dev.related.user.add(event.extra["user"])
            event.category.add("network")
            event.type.add("access")
            event.type.add("connection")

        dev.store("event", event)


def parse_file(path: PurePath, f_handle: IO[bytes], device_info: dict) -> bool:
    """
    Parse a Sage file using the appropriate parsing function, and update
    the ``device_info`` dict with extracted data from that file.

    Returns:
        Bool indicating if a parsing function was found for the file.
    """
    f_name_lower = path.name.lower()

    # TODO: return dicts from functions instead of mutating device_info inside functions

    if f_name_lower in FILE_PROCESSING_MAP:
        FILE_PROCESSING_MAP[f_name_lower](f_handle, device_info)
    else:
        path_str = path.as_posix()

        if re.match(r"firewall/.*\.cfg", path_str, re.IGNORECASE):
            parse_firewall(f_handle, device_info)
        elif re.match(r"xml/port.*\.xml", path_str, re.IGNORECASE):
            parse_port(f_handle, device_info)
        # syslog or syslog.{x} (where x=an integer, e.g. "syslog.0")
        elif path.name.startswith("syslog") and len(path.name) in [6, 8]:
            parse_ipcom_syslog(f_handle, device_info)
        else:
            # File is not one of interest, continue
            log.trace2(f"Skipping file '{path}' (no parser for it)")
            return False

    return True


# tar => FTP:
#   xml/* => /ata0a/Webfiles/xml/*
#   ethernet.xml => /ata0a/ethernet.xml
#   bootline.xml => /ata0a/bootline.xml
#   isagraf/ISaGRAF.TXT => /ata0a/Webfiles/ISaGRAF/ISaGRAF.TXT
#   scripts/* => /ata0a/scripts/*
#   server.key => /ata0a/ssl/private/server.key
#   server.crt => /ata0a/ssl/cert/server.crt
#   ike/* => /ata0a/ike/*


# Dynamic function dispatch to the appropriate parser based on the input file
# NOTE: keys must be lowercase to ensure filenames match properly in all cases
FILE_PROCESSING_MAP: Final[dict[str, Callable]] = {
    "syslog.log": parse_logfiles,
    "userlog.log": parse_logfiles,
    "soelog.txt": parse_logfiles,
    "syslog": parse_ipcom_syslog,
    "syslog.0": parse_ipcom_syslog,
    "access.xml": parse_access_xml,
    "rtusetup.xml": parse_rtu_setup,
    "tte.xml": parse_tte,
    "userlog.xml": parse_userlog_settings_xml,
    "time.xml": parse_time,
    "ethernet.xml": parse_ether,
    "bootline.xml": parse_bootline_xml,
    "isagraf.txt": parse_isagraf,
    "startup.scp": parse_startup_script,
    "vxworks_start.scp": parse_vxworks_script,
    "server.key": parse_private_key,
    "server.crt": parse_certificate,
    "ike.cfg": parse_ike_config,
    # "ike/ca_store/telvent_ca.cer": parse_ike_ca,
    "telvent_ca.cer": parse_ike_ca,
    # "ike/private/priv0.key": parse_ike_privkey,
    "priv0.key": parse_ike_privkey,
    # "ike/cert/cert0.cer": parse_ike_cert,
    "cert0.cer": parse_ike_cert,
    "features.xml": parse_features,
    "c3835.xml": parse_3835,
    "dcana.xml": parse_dcana,
    "timing.xml": parse_timing,
    "calc.xml": parse_calc,
    "rtu_sts.xml": parse_rtu_sts,
    "sfb.xml": parse_sfb,
    "acc_rate.xml": parse_acc_rate,
    "alarms.xml": parse_alarms,
    "alarming.xml": parse_alarming,
    "almdev.xml": parse_almdev,
    "bbdi.xml": parse_bbdi,
    "cbcconf.xml": parse_cbc,
    "astconf.xml": parse_ast,
    "anunctor.xml": parse_anunctor,
    "cmdlog.xml": parse_cmdlog_settings_xml,
    "comasign.xml": parse_com_assignments,
    "sprcodes.xml": parse_sprcodes,
    "soelog.xml": parse_soelog_settings_xml,
    "leds.xml": parse_leds,
    "relays.xml": parse_relays,
    "nrgcalc.xml": parse_nrgcalc,
    "bbrelay.xml": parse_bbrelay,
    "btstconf.xml": parse_btstconf,
    "aci.xml": parse_aci,
    "aci1250.xml": parse_aci1250,
}
