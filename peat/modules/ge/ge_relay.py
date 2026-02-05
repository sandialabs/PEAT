import copy
import re
from pathlib import Path

from bs4 import BeautifulSoup

from peat import (
    DeviceData,
    DeviceError,
    DeviceModule,
    Event,
    Interface,
    IPMethod,
    consts,
    log,
    state,
    utils,
)
from peat.protocols import HTTP, clean_mac

# TODO: these devices may support HTTPS in some cases, should we handle that somehow?
# TODO: make a "GEHTTP" subclass of HTTP to more cleanly implement custom functionality


class GERelay(DeviceModule):
    """
    PEAT module for GE Multilin Relays.

    Listening services

    - HTTP (TCP 80)

    Web pages

    - /IEC61850InfoMenu.htm
    - /CustomerSupport.htm
    - /ProcessCardMenu.htm
    - /DeviceInfoMenu.htm
        - /DisplayDump.htm
        - /DNPPoints.htm
        - /HF03DisableStatus.htm
        - /FlexInteger.htm
        - /FlexAnalog.htm
        - /FlexLogicParameters.htm

    - /memoryMap.htm
        - ?0x<HEXADDRESS>

    - /USBStats.htm
    - /FaultReport.htm
    - /RoutingAndArpTable.htm
    - /EventRecorder.htm
        - ?<# of alerts, 0 to show all>

    - /DefaultSettingsDiagnostics.htm
    - /FlexOperandStates.htm

    Authors

    - Christopher Goes
    - Daniel Hearn, Idaho National Laboratory (INL)
    """

    device_type = "Relay"
    vendor_id = "GE"
    vendor_name = "General Electric"
    brand = "Multilin"
    can_parse_dir = True

    # NOTE: F35 has not been tested with PEAT after integration changes
    supported_models = ["D30", "F35", "N60", "T60", "L90"]

    URLS = {
        "default_settings_diagnostics": "/DefaultSettingsDiagnostics.htm",
        "dnp_points": "/DNPPoints.htm",
        "event_recorder": "/EventRecorder.htm?0",
        "flex_analog": "/FlexAnalog.htm",
        "flex_integer": "/FlexInteger.htm",
        "flex_logic": "/FlexLogicParameters.htm",
        "flex_operand_states": "/FlexOperandStates.htm",
        "mb_map_product_info": "/memoryMap.htm?0x0000",
        "mb_map_administrator": "/memoryMap.htm?0x0D00",
        "routing": "/RoutingAndArpTable.htm",
        "usb_stats": "/USBStats.htm",
    }

    # Source for signatures: https://github.com/pnnl/ssass-e
    # License: BSD-3
    MODEL_SIGS = {  # Signatures of models we know of
        "D30 Distance Relay": "D30",
        "N60 Network Relay": "N60",
        "T60 Transformer": "T60",
        "L90 Line Relay": "L90",
    }

    @classmethod
    def _verify_http(cls, dev: DeviceData) -> bool:
        """
        Verify GERelay by checking for strings in homepage.
        """
        cls.log.debug(f"Verifying {dev.ip} using HTTP")
        try:
            with HTTP(
                ip=dev.ip,
                port=dev.options["http"]["port"],
                timeout=dev.options["http"]["timeout"],
            ) as http:
                response = http.get()
                if not response or not response.content:
                    return False

                data = response.content.decode()
                lower_data = data.lower()
                verified = False

                # TODO: use process_header_data() for this
                for sig, model in cls.MODEL_SIGS.items():
                    if sig.lower() in lower_data:
                        verified = True
                        dev.description.model = model
                        break
                if not verified and (
                    "ge power" in lower_data and "relay" in lower_data
                ):
                    verified = True
                    if "f35 " in lower_data:
                        dev.description.model = "F35"

                if verified:
                    cls.log.info(f"Verified {dev.ip} via HTTP")
                    # Source: https://github.com/pnnl/ssass-e
                    # License: BSD-3
                    if "Revision   " in data:
                        try:
                            fw_id = data.partition("Revision   ")[2].split("<")[0]
                            dev.firmware.version = fw_id.strip()
                        except Exception as ex:
                            cls.log.warning(f"Failed to parse firmware version: {ex}")
                    return True
        except Exception:
            cls.log.exception(
                f"failed to verify {dev.ip} via HTTP due to an unhandled exception"
            )

        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        raw_pages = cls._download_pages(dev)
        if not raw_pages:
            cls.log.error(f"No pages were downloaded from {dev.ip}!")
            return False

        page_tables = cls._parse_pages(raw_pages)
        if not page_tables:
            return False

        relay_data = cls._process_pages(dev, page_tables)
        if not relay_data:
            return False

        return True

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """
        This will parse a directory of scraped HTML files. It is intended to be
        used for testing and development of PEAT, such as generation of test
        data.
        """
        if not file.is_dir():
            raise DeviceError(f"{file.name} must be a directory")
        if not dev:
            dev = DeviceData()

        raw_pages = {}
        for d_type, f_name in cls.URLS.items():
            f_name = f_name.replace("/", "")
            if "?" in f_name:
                f_name = f_name.replace("?", "") + ".html"

            path = list(file.glob(f"*{f_name}"))
            if not path:
                raise DeviceError(f"Failed to find file '{f_name}' in '{file}'")
            if len(path) > 1:
                raise DeviceError(f"Multiple versions of file '{f_name}' in '{file}'")

            raw_pages[d_type] = path[0].read_text(encoding="utf-8")

            # Hack to make PEAT tests work. I'm fine with this since
            # GERelay._parse() was originally created to use for
            # PEAT test data generation in the first place.
            f_name = path[0].name
            for model in cls.supported_models:
                m_str = f"{model.lower()}_"
                if f_name.startswith(m_str):
                    f_name = f_name.replace(m_str, "")
                    break
            dev.related.files.add(f_name)

        page_tables = cls._parse_pages(raw_pages)

        cls._process_pages(dev, page_tables)

        cls.update_dev(dev)

        return dev

    @classmethod
    def _download_pages(cls, dev: DeviceData) -> dict[str, str]:
        raw_pages = {}
        cls.log.info(f"Downloading pages from {dev.ip}")

        # NOTE: flex_logic and flex_operand_states take a long time (html page
        # takes a long time to load).

        with HTTP(
            ip=dev.ip,
            port=dev.options["http"]["port"],
            timeout=dev.options["http"]["timeout"],
        ) as http:
            for d_type, path in cls.URLS.items():
                url = f"http://{dev.ip}{path}"
                page_data = cls._get_page(http, dev, url)
                if page_data:
                    raw_pages[d_type] = cls._get_page(http, dev, url)

        cls.log.info(f"Finished downloading pages from {dev.ip}")
        return raw_pages

    @classmethod
    def _get_page(cls, http: HTTP, dev: DeviceData, url: str) -> str:
        cls.log.info(f"Downloading {url}")
        response = http.get(url=url, dev=dev)
        if response and response.text:
            return response.text
        cls.log.warning(f"Failed to download {url}")
        state.error = True
        return ""

    @staticmethod
    def _parse_pages(raw_pages: dict[str, str]) -> dict[str, dict]:
        return {
            d_type: parse_ge_html(data, key_value_pairs=d_type in ["usb_stats"])
            for d_type, data in raw_pages.items()
        }

    @classmethod
    def _process_pages(cls, dev: DeviceData, page_tables: dict) -> dict | None:
        relay_data = copy.deepcopy(page_tables)

        # Process header information from each page (IP, name, model, etc.)
        for tables in relay_data.values():
            if "page_header" in tables:
                process_header_data(dev, tables.pop("page_header"))
                if dev.id and dev.name and "ge_html_files" in dev.id:
                    dev.id = dev.name
                elif dev.id and dev.ip and "ge_html_files" in dev.id:
                    dev.id = dev.ip

        dev.write_file(page_tables, "parsed-page-data.json")

        # Issue warnings to make code a bit cleaner
        for d_type in cls.URLS.keys():
            if not relay_data.get(d_type):
                cls.log.warning(f"No '{d_type}' data on {dev.ip}")

        # Flatten if there's only one table
        for d_type, tables in relay_data.items():
            if len(tables) == 1:
                relay_data[d_type] = tables.popitem()[1]

        # TODO: default_settings_diagnostics isn't getting used anywhere
        #   Memory values
        #   Modbus registers
        #   Setting names (add this as a Set to .extra)
        #
        # TODO: add to dev.memory (Memory model) from DefaultSettingsDiagnostics
        #   flash_address => value_hex
        #   value_hex: 00 00 (2 bytes of memory), 00 00 00 00 (4 bytes of memory)
        #   extrapolate address using flash_address as offset
        #       Set memory reads dataset as "Event #1, <date> <time>"
        #       Combine all reads for a event into a single Memory object
        #       annotate with setting_name and modbus_address
        # if relay_data.get("default_settings_diagnostics"):
        #     for table_name, table in relay_data["default_settings_diagnostics"].items():
        #         if table_name == "collected_data":
        #             pass  # TODO
        #         elif "event" in table_name:
        #             pass  # TODO
        #         else:
        #             cls.log.warning(
        #                 f"Unknown DefaultSettingsDiagnostics table: {table_name}"
        #             )

        # TODO: add Register models for DNP3 registers
        # if relay_data.get("dnp_points"):
        #     dnp_points = relay_data["dnp_points"]

        # TODO: add to dev.registers for Modbus points?
        for row in relay_data.get("mb_map_administrator", []):
            if row.get("value") and row.get("name") in [
                "GDOI KDC IP",
                "OCSP Server IP",
                "SCEP Server IP",
            ]:
                if utils.is_ip(row["value"]):
                    dev.related.ip.add(row["value"])

        # Process device metadata from "Product Info" ModbusMap page
        for row in relay_data.get("mb_map_product_info", []):
            if not row.get("name") or not row.get("value"):
                cls.log.warning(f"Bad mb_map_product_info row: {row}")
                continue

            # TODO: other interesting fields
            #   "UR Product Type"
            #   "Modification Number"
            #   "CPU Module Serial Number"  (dev.module.*?)
            #   "CPU Supplier Serial Number"  (dev.module.*?)
            #   "Main Board HW ID"
            #   "Daughter Board HW ID"

            if row["name"] == "Product Version":
                dev.firmware.version = row["value"]
            elif row["name"] == "Serial Number":
                dev.serial_number = row["value"]
            elif row["name"] == "Manufacturing Date":
                dev.manufacturing_date = utils.parse_date(row["value"])
            elif row["name"] == "Order Code":
                dev.firmware.id = row["value"]
                dev.firmware.extra["order_code"] = row["value"]
                # Extract device model from start of order code
                dev.description.model = row["value"].split("-")[0]
            elif row["name"] == "Ethernet MAC Address":
                # Convert MAC: "DC3752FFFFFF" => "DC:37:52:FF:FF:FF"
                dev.extra["mac_address"] = ":".join(re.findall(r"..", row["value"]))
            elif row["name"] == "FPGA Version":
                dev.boot_firmware.id = "FPGA"
                dev.boot_firmware.version = row["value"]
            elif row["name"] == "FPGA Date":
                dev.boot_firmware.release_date = utils.parse_date(row["value"])
            else:
                dev.extra[convert_key(row["name"])] = row["value"]

        # Network interfaces
        for port in relay_data.get("routing", {}).get("port_status", []):
            iface = Interface(
                connected=(
                    True if port.get("link_status", "").upper() == "UP" else False
                ),
                enabled=(
                    True if port.get("function", "").upper() == "ENABLED" else False
                ),
                name=port.get("port", ""),
                id=port.get("port", ""),
                extra={
                    "link_status": port.get("link_status", ""),
                    "redundancy": port.get("redundancy", ""),
                    "active_if_redundancy": str(port.get("active_if_redundancy", "")),
                    "port": port.get("port", ""),
                },
            )

            # "127.0.0.1" check is to avoid duplicating "lo0" interface
            if port.get("ip_address") and port["ip_address"] != "127.0.0.1":
                iface.type = "ethernet"
                iface.ip = port["ip_address"]

                if port.get("subnet_mask"):
                    iface.subnet_mask = port["subnet_mask"]

                if relay_data["routing"].get("ipv4_routing_table"):
                    for route in relay_data["routing"]["ipv4_routing_table"]:
                        if iface.ip == route.get("gateway", "") and route.get("if"):
                            iface.name = route["if"]
                            break

            if port.get("ip_address") == dev.ip and "mac_address" in dev.extra:
                dev.mac = clean_mac(dev.extra.pop("mac_address"))
                iface.mac = dev.mac

            dev.store("interface", iface)

        lo_found = False
        for v4_route in relay_data.get("routing", {}).get("ipv4_routing_table", []):
            if "/" not in v4_route.get("destination", ""):
                dev.related.ip.add(v4_route["destination"])

            if "." in v4_route.get("gateway", ""):
                dev.related.ip.add(v4_route["gateway"])
            elif ":" in v4_route.get("gateway", ""):
                dev.related.mac.add(clean_mac(v4_route["gateway"]))

            # Add localhost "lo0" interface standalone
            if not lo_found and v4_route.get("if") == "lo0":
                lo_iface = Interface(
                    connected=True,
                    enabled=True,
                    name="lo0",
                    hostname="localhost",
                    ip="127.0.0.1",
                    type="ethernet",
                )
                dev.store("interface", lo_iface)
                lo_found = True

        # TODO: ipv6 routing table entries (ipv6_routing_table)

        # Process ARP table entries
        for arp in relay_data.get("routing", {}).get("arp_table", []):
            dev.related.ip.add(arp.get("internet_address", ""))
            dev.related.mac.add(clean_mac(arp.get("physical_address", "")))

        # Add the fact that there's a USB interface I guess
        if relay_data.get("usb_stats"):
            u_stats = relay_data["usb_stats"]
            usb_iface = Interface(
                type="usb",
                # TODO: use to determine enabled/active status:
                #   usb_initialized, usb_configured, usb_enumerated,
                #   rx_frame_count, tx_frame_count
                # speed=0,  # TODO: usb_speed, "Full Speed: 12Mbit/s"
                extra=copy.deepcopy(u_stats),
            )
            if "metric" in usb_iface.extra:
                del usb_iface.extra["metric"]
            dev.store("interface", usb_iface)

        # Process logic. Currently this is just cleaning up the fields,
        # someday we should turn this into useful logic.
        for logic_section in ["flex_logic", "flex_operand_states"]:
            if not relay_data.get(logic_section):
                continue
            try:
                cleaned_logic = []
                for logic_entry in relay_data[logic_section]:
                    cleaned_entry = {}

                    for key, value in logic_entry.items():
                        clean_key = utils.clean_replace(key, "", "(),. ")

                        if "ok_" in clean_key:
                            cleaned_entry[clean_key] = bool(value)
                        elif clean_key == "value_decimal":
                            cleaned_entry["value"] = int(value)
                        # Trim the hex value since there's no reason to keep it
                        elif clean_key != "value_hex":
                            cleaned_entry[clean_key] = value

                    cleaned_logic.append(cleaned_entry)

                relay_data[logic_section] = cleaned_logic
            except Exception:
                cls.log.exception(f"Error processing {logic_section}")

        # Process logs
        if relay_data.get("event_recorder"):
            cls._process_event_recorder(dev, relay_data["event_recorder"])

        # Dump data with any post-processing applied
        dev.write_file(relay_data, "processed-data.json")

        cls.update_dev(dev)

        dev.extra.update(relay_data)

        # Remove extraneous data we've already processed
        for key in [
            "flex_analog",
            "flex_integer",
            "flex_logic",
            "flex_operand_states",
            "event_recorder",
            "mb_map_product_info",
            "mb_map_administrator",
        ]:
            if key in dev.extra:
                del dev.extra[key]

        return relay_data

    @classmethod
    def _process_event_recorder(
        cls, dev: DeviceData, event_recorder: list[dict]
    ) -> None:
        """
        Process GE device logs (event recorder) into the PEAT data model.
        """
        try:
            for raw in event_recorder:
                action = utils.clean_replace(raw["event_cause"], "-", " /()").lower()
                action = action.replace("'", "").replace("--", "-").strip("-")
                event = Event(
                    action=action,
                    category={"host"},
                    created=utils.parse_date(raw["time_and_date"]),
                    dataset="event_recorder",
                    kind={"event"},
                    module=cls.__name__ if not dev._module else dev._module.__name__,
                    original=raw["event_cause"],
                    sequence=int(raw["event_number"]),
                    type={"info"},
                )

                lowercase = raw["event_cause"].lower()
                if any(x in lowercase for x in ["closed", "open", "trigger"]):
                    event.outcome = "success"
                    event.type.add("change")
                if "change" in lowercase:
                    event.category.add("configuration")
                    event.type.add("change")
                if "power" in lowercase:
                    event.type.add("change")
                if "failure" in lowercase:
                    event.outcome = "failure"
                    event.type.add("error")
                    event.type.remove("info")

                dev.store("event", event, lookup="sequence")
        except Exception:
            cls.log.exception(
                f"error while processing 'event_recorder' data for {dev.ip}"
            )
            state.error = True


GERelay.ip_methods = [
    IPMethod(
        name="GE Relay HTTP homepage",
        description=str(GERelay._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=GERelay._verify_http,
        reliability=7,
        protocol="http",
        transport="tcp",
        default_port=80,
    ),
]


def process_header_data(dev: DeviceData, header: list) -> None:
    if not header:
        return

    prod_rev = header[0].partition("Revision")
    dev.firmware.version = prod_rev[2].strip()

    if not dev.description.model:
        prod = prod_rev[0].strip()
        for sig, model in GERelay.MODEL_SIGS.items():
            if sig.lower() in prod.lower():
                dev.description.model = model
                break
        else:
            dev.extra["product_identifier"] = prod
            dev.description.model = prod.partition(" ")[0]

    name_ip = header[1].partition("IP Address: ")

    ip = name_ip[2].strip()
    if not dev.ip:
        dev.ip = ip
    if ip != dev.ip:
        log.warning(f"Configured IP {ip} does not match current IP {dev.ip}!")
        dev.related.ip.add(ip)

    name = name_ip[0].partition("Relay Name: ")[2].strip()
    if dev.name and name != dev.name:
        log.warning(f"Configured Name {name} does not match current name {dev.name}")
    dev.name = name


def parse_ge_html(text: str, key_value_pairs: bool = False) -> dict[str, list[dict]]:
    """
    HTML parsing for pages scraped from GE devices.

    Originally based on code by Ryan Vrecenar in ``sel_http.py.read_html()``.

    Args:
        text: the raw HTML text to parse
        key_value_pairs: If a table should be parsed as key-value pairs.
            This mainly applies to the USBStats page, but it could apply
            to other pages as well.
    """
    soup = BeautifulSoup(text, features=consts.BS4_PARSER)
    table_elements = soup.find_all("table")
    if not table_elements:
        return {}

    # If "multi-table" (e.g., DNPPoints.htm), then rows with one <TD/>
    # (one column) is a new table/ There will only be two <TABLE/>
    # elements: the header, and the "table" with multiple tables.

    results = {}
    page_name = "_UNKNOWN_PAGE_NAME"

    # Iterate over all "<TABLE/>" elements
    for table_num, table_element in enumerate(table_elements):
        table_name = f"unknown_table_{table_num}"
        tables = []  # type: list[dict]
        rows = []  # type: list[list[str]]

        # Find rows in html table objects
        for row_index, row in enumerate(table_element.find_all("tr")):
            if not row:  # skip empty
                rows.append([])  # preserve row indices
                continue

            # Find columns in each row
            cols = row.find_all("td")

            if not cols:  # skip empty
                rows.append([])  # preserve row indices
                continue

            if len(cols) == 1:
                table_name = convert_key(clean_text(cols[0].getText()))
                tables.append({"name": table_name, "index": row_index})
                rows.append([])  # preserve row indices
                continue

            # Iterate over columns
            cleaned = [clean_text(pos.getText()) for pos in cols]
            rows.append([c for c in cleaned if c])

        if "click_here" in table_name:
            page_name = table_name.split("click_here")[0]
            results["page_header"] = rows[0]
            continue

        if len(rows) < 3 or key_value_pairs:  # key-value pairs
            row_values = {}
            for r in rows[1:]:
                if r and len(r) > 1:
                    row_values[convert_key(r[0])] = r[1].strip()
            results[table_name] = row_values
            continue

        # In the case of no table header (e.g. EventRecorder or FlexAnalog)
        if not tables:
            tables.append({"name": page_name, "index": -1})

        header = []  # type: list[str]
        for tbl_idx, table in enumerate(tables):
            header_row = rows[table["index"] + 1]
            if not header:
                header = [convert_key(h) for h in header_row]
            if header and len(header_row) == len(header):
                tbl_header = header
            else:  # header specific to this table
                tbl_header = [convert_key(h) for h in header_row]

            if tbl_idx + 1 < len(tables):
                end_row_idx = tables[tbl_idx + 1]["index"]
            else:
                end_row_idx = len(rows)

            table_values = []  # type: list[dict[str, Union[str, int]]]

            for tr_vals in rows[table["index"] + 2 : end_row_idx]:
                if not tr_vals:
                    continue
                row_values = {
                    col: value.strip()
                    for col, value in zip(tbl_header, tr_vals, strict=False)
                }  # type: dict[str, Union[str, int]]
                table_values.append(row_values)

            results[table["name"]] = table_values

    return results


def clean_text(data: str) -> str:
    """
    Attempt to remove whitespace and new line characters.
    """
    return data.replace("\\\\n", "").replace("\\n", "").lstrip().rstrip()


def convert_key(key: str) -> str:
    return utils.clean_replace(key, "", "():,.").replace(" ", "_").lower()
