import ipaddress
import re
import traceback
from collections import defaultdict
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from requests.auth import HTTPDigestAuth

from peat import DeviceData, Event, Interface, Memory, Service, log, utils
from peat.protocols import HTTP, clean_mac
from peat.protocols.enip.vendor_ids import VENDOR_NAMES


class ClxHTTP(HTTP):
    """
    HTTP interface for Allen-Bradley ControlLogix Ethernet communication modules.

    Supported communication modules and functions

    - EN2TR: all functions except ``serverlog``
        - ``memory``
        - ``network``
        - ``home``
        - ``device_identity``
        - ``syslog``
        - ``diagnetwork``
        - ``modules``
        - ``module_list``
    - EWEB: all functions except ``memory``, ``syslog``, and ``device_identity``
        - ``network``
        - ``home``
        - ``serverlog``
        - ``diagnetwork``
        - ``modules``
        - ``module_list``
    - L8 CPU (built-in Ethernet): ``network`` (no other functions work)
        - ``network``
    """

    MEMORY_GROUPS = [
        {
            # rokform/SysListDetail?name=WatchDog%20Log&id=216&comp=Apex
            "name": "watchdog_log",
            "page": "WatchDog",
            "search": "WatchDog Log",
            # "ids": ["216", "185"],
        },
        {
            # rokform/SysListDetail?name=Internal%20Memory&id=217&comp=Apex
            "name": "internal_memory",
            "page": "Internal%20Memory",
            "search": "Internal Memory",
            # "ids": ["217", "186"],
        },
        {
            # rokform/SysListDetail?name=Parameter%20Area&id=218&comp=Apex
            "name": "parameter_area",
            "page": "Parameter%20Area",
            "search": "Parameter Area",
            # "ids": ["218", "187"]
        },
    ]

    HOME = "home.asp"
    """Device metadata page."""

    SERVERLOG = "serverlog.asp"
    """HTTP server log page."""

    DIAGNETWORK = "diagnetwork.asp"
    """Network diagnostics page."""

    CHASSIS_WHO = "chassisWho.asp"
    """Page with a list of modules."""

    UPTIME_RE = re.compile(
        r"((?P<years>\d+) years)?[ ,]*"
        r"((?P<months>\d+) months)?[ ,]*"
        r"((?P<days>\d+) days)?[ ,]*"
        r"(?P<hours>\d{1,2})h:(?P<minutes>\d{1,2})m:(?P<seconds>\d{1,2})"
        r"\.?(?P<milliseconds>\d{3})?s",
        re.ASCII | re.IGNORECASE,
    )

    SYSLOG_PAGE_RE = re.compile(
        r"rokform/SysListDetail\?name=Full List&id=(\d+)&comp=SysLog",
        re.ASCII | re.IGNORECASE,
    )

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.syslog_page_id = ""
        self.memory_page_ids = {}

    @staticmethod
    def _clean_data(data: dict) -> dict:
        clean = {}

        for key, value in data.items():
            key = key.replace("\u00a0?", "").strip()
            if isinstance(value, str):
                # Replace multiple spaces with a single space
                value = re.sub(" {2,}", " ", value.replace("\t", " ")).strip()
            clean[key] = value

        return clean

    @classmethod
    def _extract_rows(cls, text: str, start: int, **kwargs) -> list[list]:
        table = cls.gen_soup(text).find("table", **kwargs)
        rows = table.find_all("tr")[start:]
        return [r.find_all("td") for r in rows]

    @classmethod
    def _extract_list(cls, text: str, start: int = 1, **kwargs) -> list[dict]:
        """
        Table with rows of values, and with keys defined in the columns.

        Transforms into a list of dict, with the dict keys associated with
        the column names and values being the values from that row.
        """
        rows = cls._extract_rows(text, start, **kwargs)
        labels = [str(column.string) if column.string else str(column.text) for column in rows[0]]

        return [
            {label: str(val.string) for label, val in zip(labels, row, strict=False)}
            for row in rows[1:]
        ]

    @classmethod
    def _extract_tabular(cls, text: str, start: int = 1, **kwargs) -> dict:
        """Table with rows of key-value pairs."""
        return {
            row[0].string: row[1].string
            for row in cls._extract_rows(text, start, **kwargs)
            if len(row) == 2
        }

    @staticmethod
    def _convert_serial_num(value: str) -> str:
        """
        Convert Rockwell serial number from Hexadecimal to int.
        """
        try:
            if not value or not value.strip():
                return ""
            return str(int(value.strip(), 16))
        except Exception:
            return value

    def get_memory(self) -> dict[str, dict[str, str]]:
        """
        Extracts and aggregates memory information from several pages.
        """
        memory_info = {}

        if not self.memory_page_ids and not self._cache_memory_page_ids():
            self.log.warning("Failed to get memory: couldn't find memory page IDs")
            return {}

        for mg in self.MEMORY_GROUPS:
            pid = self.memory_page_ids.get(mg["name"])
            if not pid:
                self.log.warning(
                    f"No cached page ID for '{mg['name']}' "
                    f"(page doesn't exist on this comm module model)"
                )
                continue

            page = f"rokform/SysListDetail?name={mg['page']}&id={pid}&comp=Apex"
            memory_data = self.retrieve_memory_page(page)

            memory_info[mg["name"]] = memory_data
            self.log.info(f"Read memory for {mg['name']} (page id: {pid})")

        return memory_info

    def _cache_memory_page_ids(self) -> bool:
        """
        Get the page IDs of the memory-related pages.
        """
        self.log.debug("Attempting to find memory page IDs")

        apex = self.get("rokform/SysDataDetail?name=Apex")
        if not apex or not apex.text:
            return False

        for group in self.MEMORY_GROUPS:
            pat = r"rokform/SysListDetail\?name={}&id=(\d+)&comp=Apex".format(group["search"])
            match = re.search(pat, apex.text, re.ASCII | re.IGNORECASE)
            if match:
                self.memory_page_ids[group["name"]] = match.groups()[0]

        self.log.trace(f"Memory page IDs: {self.memory_page_ids}")
        return True

    def retrieve_memory_page(self, memory_page: str) -> dict:
        """
        Parses memory from webpage to the values as a hex string.
        """
        page = self.get(memory_page, use_cache=False)
        if not page or not page.text:
            return {}

        blob, by_offset = self.parse_memory_page(page.text)
        if not blob:
            return {}

        return {
            "blob": blob,
            "lines_by_offset": by_offset,
            "timestamp": page.response_timestamp,
        }

    @classmethod
    def parse_memory_page(cls, text: str) -> tuple[str, dict[str, str]]:
        rows = cls._extract_rows(text, start=1, width="100%", cellpadding=4)
        binary_blob = ""
        by_offset = {}

        for row in rows:
            line_value = ""
            for offset in row[1:-1]:
                line_value += cls.add_padding(offset.string[2:])

            binary_blob += line_value
            line_key = cls.add_padding(row[0].string[2:])
            by_offset[line_key] = line_value

        return binary_blob, by_offset

    @staticmethod
    def add_padding(input_data: str) -> str:
        """
        Adds padding for memory values, e.g. convert ``01`` to ``00000001``.
        """
        return "0" * (8 - len(input_data)) + input_data

    @classmethod
    def process_memory(cls, dev: DeviceData, memory_regions: dict) -> None:
        """
        Add data from the parsed memory to a
        :class:`~peat.data.models.DeviceData` object.
        """
        log.info(f"Processing memory reads from {dev.ip} (this may take a while)")
        blobs = defaultdict(dict)

        for r_name, region in memory_regions.items():
            if isinstance(region["timestamp"], str):
                ts = region["timestamp"]
            else:
                ts = region["timestamp"].isoformat()

            blobs[r_name][ts] = region["blob"]

            memory = Memory(
                # TODO: where in memory is this actually? ask our Rockwell experts
                address=next(iter(region["lines_by_offset"].keys())),
                # Set "created" to the time the page was pulled by PEAT
                created=region["timestamp"],
                dataset=r_name,  # "watchdog_log", "internal_memory", etc.
                device=dev.ip,
                # TODO: size (calculate this)
                value=region["blob"],
            )
            dev.memory.append(memory)

        dev.write_file(blobs, "memory-blobs.json")

    def get_network(self) -> dict[str, dict | list]:
        """
        Extracts and aggregates network information from several pages.
        """
        self.log.info("Pulling network information...")

        network_information = {
            "arp_table": self.retrieve_net_table("arp"),
            "icmp_statistics": self.retrieve_statistics("icmp"),
            "if_statistics": self.retrieve_statistics("if"),
            "ip_statistics": self.retrieve_statistics("ip"),
            "ip_routes": self.retrieve_net_table("iproute"),
            "tcp_statistics": self.retrieve_statistics("tcp"),
            "tcp_connections": self.retrieve_net_table("tcpconn"),
            "udp_statistics": self.retrieve_statistics("udp"),
            "udp_table": self.retrieve_net_table("udptable"),
        }

        return network_information

    def retrieve_statistics(self, name: str) -> dict[str, str]:
        """
        Retrieves and parses a page of statistics into a dictionary.
        """
        page = self.get(f"rokform/advancedDiags?pageReq={name}", use_cache=False)

        if not page or not page.text:
            return {}

        return self.parse_statistics(page.text)

    @classmethod
    def parse_statistics(cls, text: str) -> dict[str, str]:
        """
        Parse and extract a network statistics from HTML text.
        """
        return cls._extract_tabular(text, cellpadding=2)

    def retrieve_net_table(self, name: str) -> list[dict[str, str]]:
        """
        Retrieves and parses a table from a network information
        page into a dictionary.
        """
        page = self.get(f"rokform/advancedDiags?pageReq={name}", use_cache=False)

        if not page or not page.text:
            return []

        return self.parse_net_table(page.text)

    @classmethod
    def parse_net_table(cls, text: str) -> list[dict[str, str]]:
        """
        Parse and extract a network data table from HTML text.
        """
        return cls._extract_list(text, cellpadding=2)

    @classmethod
    def _make_svc(cls, dev: DeviceData, svc_info: dict, transport: str) -> None:
        port = svc_info.get("Local Port")

        if not port:
            return

        port = int(port)

        _protocol_lookups = {
            68: "bootp",
            80: "http",
            161: "snmp",
            2221: "enip_secure",
            2222: "enip",
            44818: "cip",
        }
        protocol_name = _protocol_lookups.get(port, "")

        dev.related.ports.add(port)
        dev.related.protocols.add(protocol_name)

        to_search = {"port": port, "transport": transport}

        # TODO: should service be added to all ethernet interfaces?
        # (since localaddress == 0.0.0.0)?
        existing_service = dev.retrieve("service", search=to_search)
        if existing_service:
            if isinstance(existing_service, list):
                log.warning(f"Multiple services found: {existing_service}")
                existing_service = existing_service[0]
            # hack to not overwrite existing "verified" status with "open"
            if existing_service.status != "verified":
                existing_service.status = "open"
            if not existing_service.protocol and protocol_name:
                existing_service.protocol = protocol_name
        else:
            # If the "protocol" field is blank, then it fails to add the
            # service because the matching logic is flawed and thinks
            # it's a duplicate or something.
            new_service = Service(
                port=port, protocol=protocol_name, status="open", transport=transport
            )
            dev.store("service", new_service)

    @classmethod
    def process_network(cls, dev: DeviceData, info: dict) -> None:
        """
        Add data from the parsed network information pages to a
        :class:`~peat.data.models.DeviceData` object.
        """
        # ARP table, has MACs and IPs
        for arp_entry in info.get("arp_table", []):
            mac = clean_mac(arp_entry["Physical Address"])
            dev.related.mac.add(mac)
            dev.related.ip.add(arp_entry.get("Net Address"))
            # infer MAC if it's not known from IP in arp table
            if not dev.mac and mac and arp_entry["Net Address"] == dev.ip:
                dev.mac = mac

        # Interface info
        if info.get("if_statistics") and info["if_statistics"].get("MAC address"):
            mtu = int(info["if_statistics"]["MTU"])
            description = info["if_statistics"]["Description"]

            mac = clean_mac(info["if_statistics"]["MAC address"])
            dev.related.mac.add(mac)

            if not dev.interface:
                interface = Interface(
                    enabled=True, name=description, mac=mac, mtu=mtu, type="ethernet"
                )
                dev.store("interface", interface)
            else:
                for iface in dev.interface:
                    if mac == iface.mac:
                        iface.name = description
                        iface.mtu = mtu
                        break

                    if description == iface.name:
                        iface.mac = mac
                        iface.mtu = mtu
                        break

        # udp_table: listening ports (0.0.0.0-only), infer service names
        for udp in info.get("udp_table", []):
            dev.related.ip.add(udp.get("Local Address"))

            if udp.get("Local Address") == "0.0.0.0" and udp.get("Local Port"):
                cls._make_svc(dev, udp, "udp")
            elif udp.get("Local Port"):
                try:
                    dev.related.ports.add(int(udp["Local Port"]))
                except Exception:
                    pass

        # tcp_connections: listening ports (0.0.0.0-only), infer service names
        for conn in info.get("tcp_connections", []):
            dev.related.ip.add(conn.get("Local Address"))
            dev.related.ip.add(conn.get("Remote Address"))

            if conn.get("State") == "LISTEN" and conn.get("Local Address") == "0.0.0.0":
                cls._make_svc(dev, conn, "tcp")
            elif conn.get("Local Port"):
                try:
                    dev.related.ports.add(int(conn["Local Port"]))
                except Exception:
                    pass

        # ip_routes: IP routing table
        for ip_route in info.get("ip_routes", []):
            # Infer the subnet of the route using destination and subnet mask
            # If any of the interfaces on the device have an IP that lies in
            # that subnet and doesn't have a known subnet mask, then set the
            # subnet mask to the mask derived from the IP route.
            dest = ip_route.get("Destination", "")
            raw_mask = ip_route.get("Mask", "")
            if not dest or not raw_mask:
                continue

            subnet_mask = ".".join(reversed(raw_mask.split(".")))
            try:
                network = ipaddress.ip_network(f"{dest}/{subnet_mask}")
            except Exception as ex:
                log.warning(f"Failed to parse ip_route '{ip_route}': {ex}")
                continue

            for interface in dev.interface:
                if not interface.ip:
                    continue
                iface_ip = ipaddress.ip_address(interface.ip)
                if not interface.subnet_mask and iface_ip in network:
                    interface.subnet_mask = subnet_mask

        dev.extra["network"] = info

    def get_home(self) -> dict:
        """
        Home page with basic information about device.
        """
        page = self.get(self.HOME, use_cache=False)  # uptime changes every time

        if not page or not page.text:
            return {}

        data = self._extract_tabular(page.text, start=0, width="100%", cellpadding=4)
        return self._clean_data(data)

    @classmethod
    def parse_home(cls, text: str) -> dict:
        """
        Parse ``home.asp`` HTML data.
        """
        data = cls._extract_tabular(text, start=0, width="100%", cellpadding=4)
        return cls._clean_data(data)

    @classmethod
    def process_home(cls, dev: DeviceData, info: dict) -> None:
        """
        Add data from the parsed home page to a
        :class:`~peat.data.models.DeviceData` object.
        """
        if not info:
            return
        if not dev.extra.get("http_home_info"):
            dev.extra["http_home_info"] = {}

        if info.get("Device Name"):
            name = info.pop("Device Name").strip()
            if not dev.name:
                dev.name = name
            elif dev.name != name:
                log.warning(
                    f"Device name '{dev.name}' != HTTP name '{name}', "
                    f"which could be weird/interesting"
                )
                dev.extra["http_home_info"]["device_name"] = name

        if info.get("Ethernet Address (MAC)"):
            mac = clean_mac(info.pop("Ethernet Address (MAC)").strip())
            dev.related.mac.add(mac)
            if not dev.mac:
                dev.mac = mac
            elif dev.mac != mac:
                log.warning(
                    f"Device MAC '{dev.mac}' != HTTP MAC '{mac}', which could be weird/interesting"
                )
                dev.extra["http_home_info"]["ethernet_address_mac"] = mac

        if info.get("IP Address"):
            ip = info.pop("IP Address").strip()
            if not dev.ip:
                dev.ip = ip
            elif dev.ip != ip:
                log.warning(
                    f"Device IP '{dev.ip}' != HTTP IP '{ip}', which could be weird/interesting"
                )
                dev.extra["http_home_info"]["ip_address"] = ip

        if not dev.firmware.release_date and info.get("Firmware Version Date"):
            fw_release_timestamp = utils.parse_date(info.pop("Firmware Version Date"))
            dev.firmware.release_date = fw_release_timestamp

        if not dev.uptime and info.get("Uptime"):
            raw_uptime = info.pop("Uptime").strip()
            parsed_uptime = cls._parse_uptime(raw_uptime)

            if parsed_uptime:
                # dev.uptime = int(parsed_uptime.total_seconds())
                dev.uptime = parsed_uptime
                dev.start_time = utils.utc_now() - parsed_uptime
            else:
                log.warning(f"Failed to parse uptime: {raw_uptime}")
                dev.extra["http_home_info"]["uptime"] = raw_uptime

        if not dev.description.description and info.get("Device Description"):
            dev.description.description = info.pop("Device Description").strip()

        if not dev.geo.name and info.get("Device Location"):
            dev.geo.name = info.pop("Device Location").strip()

        if info:
            for og_key, value in info.items():
                if value and value.strip():
                    key = utils.clean_replace(og_key, "", "()").replace(" ", "_").lower()

                    # NOTE: this is usually the serial number of the
                    # communication adapter, not the CPU.
                    if key == "serial_number":
                        value = cls._convert_serial_num(value)
                    elif key == "status" and not dev.status:
                        dev.status = value.strip()

                    dev.extra["http_home_info"][key] = value.strip()

        if not dev.extra["http_home_info"]:
            del dev.extra["http_home_info"]

    @classmethod
    def _parse_uptime(cls, uptime_string: str) -> timedelta | None:
        """
        Parse a uptime string, e.g. ``28 days, 15h:43m:33.775s`` or
        ``28 days, 16h:53m:45s``.
        """
        # I spent more time than was probably warranted on this. Time is hard.
        uptime_res = cls.UPTIME_RE.search(uptime_string)
        if not uptime_res:
            return None

        ut = uptime_res.groupdict()

        days = 0
        if ut.get("years"):
            days += int(ut["years"]) * 365
        if ut.get("months"):
            days += int(ut["months"]) * 31
        if ut.get("days"):
            days += int(ut["days"])

        kwargs = {
            "days": days,
            "hours": int(ut["hours"]),
            "minutes": int(ut["minutes"]),
            "seconds": int(ut["seconds"]),
        }
        if ut.get("milliseconds"):
            kwargs["milliseconds"] = int(ut["milliseconds"])

        return timedelta(**kwargs)

    def get_device_identity(self) -> dict:
        """
        Get Device Identity page data.
        """
        page = self.get("rokform/SysDataDetail?name=Device%20Identity", use_cache=False)

        if not page or not page.text:
            return {}

        return self.parse_device_identity(page.text)

    @classmethod
    def parse_device_identity(cls, text: str) -> dict:
        """
        Parse device identity page data.
        """
        data = cls._extract_tabular(text, width="100%", cellpadding=4)
        return cls._clean_data(data)

    @classmethod
    def process_device_identity(cls, dev: DeviceData, info: dict) -> None:
        if info and not dev.extra.get("http_device_identity"):
            dev.extra["http_device_identity"] = {}

        for og_key, value in info.items():
            if value and value.strip():
                key = utils.clean_replace(og_key, "", "()/").replace(" ", "_").lower()
                if key == "serial_number":
                    value = cls._convert_serial_num(value)

                dev.extra["http_device_identity"][key] = value.strip()

    def get_syslog(self) -> list[dict]:
        """
        Get Syslog data (page: ``Syslog -> Full List``).
        """
        # Cache the page ID for subsequent queries in the same session
        if not self.syslog_page_id and not self._cache_syslog_page_id():
            self.log.warning(
                "Failed to get syslog: couldn't find ID of syslog "
                "page. This module may not have syslog data available."
            )
            return []

        url = f"rokform/SysListDetail?name=Full%20List&id={self.syslog_page_id}&comp=SysLog"
        page = self.get(url, use_cache=False)

        if not page or not page.text:
            return []

        return self.parse_syslog_page(page.text)

    def _cache_syslog_page_id(self) -> bool:
        """
        Get the page ID of the 'Full List' syslog page.
        """
        self.log.debug("Attempting to find syslog page ID")

        # This page has the URLs of the syslog pages with correct ID values
        syslog_home = self.get("rokform/SysDataDetail?name=SysLog")
        if not syslog_home or not syslog_home.text:
            return False

        # Extract the ID of the "Full List" syslog page
        match = self.SYSLOG_PAGE_RE.search(syslog_home.text)
        if not match:
            return False

        self.syslog_page_id = match.groups()[0]
        self.log.trace(f"Syslog page ID: {self.syslog_page_id}")

        return True

    @classmethod
    def parse_syslog_page(cls, text: str) -> list[dict]:
        """
        Parse Syslog data page.
        """
        data = cls._extract_list(text, start=0, width="100%", cellpadding=4)
        return [cls._clean_data(d) for d in data]

    @classmethod
    def process_syslog(cls, dev: DeviceData, syslog: list[dict]) -> None:
        """
        Add data from the parsed syslog pages to a
        :class:`~peat.data.models.DeviceData` object.
        """
        log.info(f"Processing syslog from {dev.ip}")

        for raw in syslog:
            # "Event String": "CloseNode() occurred"
            # "Event String": "CipStatus: Generated on device"
            action = utils.clean_replace(raw["Event String"], "", "/():").lower()
            action = action.replace(" ", "-").replace("--", "-").strip("-")
            event_kind = {"event"}

            # We **should** know the start_time, but not always
            # The timestamps are relative, so the start time is necessary
            # e.g. "28 days, 15h:42m:55.588s"
            t_delta = cls._parse_uptime(raw["Time"])
            if not t_delta:
                log.debug(f"Failed to parse event time: {raw['Time']}")
                event_kind.add("pipeline_error")

            created_ts = None
            if t_delta and dev.start_time:
                created_ts = dev.start_time + t_delta

            extra = {
                "file": raw["File"],  # "File": "CommPortBase.cpp"
                "line": int(raw["Line Number"]),  # "Line Number": "2308"
                "param_1": raw["Param1"],  # "Param1": "0x2"
                "param_2": raw["Param2"],  # "Param2": "0x19001e"
                "task_name": raw["Task Name"],  # "Task Name": "EncapTCP024"
                "event_code": raw["Event Code"],  # "Event Code": "0xd"
            }

            event = Event(
                action=action,
                category={"process"},
                created=created_ts,
                dataset="syslog",
                kind=event_kind,
                module=dev._module.__name__ if dev._module else "ControlLogix",
                original=str(raw),
                sequence=int(raw["Event Number"]),
                type={"info"},
                message=raw["Event String"],
                extra=extra,
            )

            dev.event.append(event)

    def get_serverlog(self, username: str = "Administrator", password: str = "") -> list[dict]:
        """
        Get ``serverlog`` data from a EWEB module.

        .. note::
           This page requires authentication. The default credentials are
           attempted but could differ on other devices. They are configurable
           via the "web" option in the PEAT configuration file.
        """
        page = self.get(self.SERVERLOG, use_cache=False, auth=HTTPDigestAuth(username, password))

        if not page or not page.text:
            return []

        return self.parse_serverlog_page(page.text)

    @classmethod
    def parse_serverlog_page(cls, text: str) -> list[dict]:
        """
        Parse ``serverlog`` data page from a EWEB module.
        """
        data = cls._extract_list(text, start=0, width="100%", cellpadding=4)
        return [cls._clean_data(d) for d in data]

    @classmethod
    def process_serverlog(cls, dev: DeviceData, serverlog: list[dict]) -> None:
        """
        Add data parsed EWEB ``serverlog`` page to a
        :class:`~peat.data.models.DeviceData` object.

        This log contains a history of web page requests to the EWEB module
        and the source IP of those requests.

        - Possible values for ``event.category``: network, web
        - Possible values for ``event.kind``: event, pipeline_error
        - Possible values for ``event.type``: access, allowed, denied, error, user
        """
        log.info(f"Processing serverlog from {dev.ip} (this may take a while)")

        for raw_event in serverlog:
            dev.related.ip.add(raw_event["IP Address"])

            event_category = {"network", "web"}
            event_kind = {"event"}
            event_type = {"access"}

            http_code = int(raw_event["HTTP Code"])  # "HTTP Code": "200"
            outcome = "unknown"

            if http_code < 300:
                outcome = "success"
                if "username" in raw_event["URL"]:
                    event_type.add("allowed")
            elif http_code >= 400:
                outcome = "failure"
                event_type.add("error")
                if "username" in raw_event["URL"]:
                    event_type.add("denied")

            extra = {
                # TODO: add network/host/http fields to event data model
                "url": raw_event["URL"],  # "URL": "/index.html",
                "http_code": http_code,  # "HTTP Code": "200",
                "ip": raw_event["IP Address"],  # "IP Address": "192.168.0.20"
                "access": raw_event["Access"],  # "Access: "public"
            }

            if "username=" in raw_event["URL"]:
                try:
                    # "URL": "/serverlog.asp?username=Administrator&realm=1756-EWEB"
                    user = parse_qs(urlparse(raw_event["URL"]).query)["username"][0]
                    extra["username"] = user
                    event_type.add("user")
                    dev.related.user.add(user)
                except Exception as ex:
                    log.warning(f"Failed to process username for URL '{raw_event['URL']}': {ex}")
                    event_kind.add("pipeline_error")

            event = Event(
                category=event_category,
                # "Timestamp": "MAY 04 17:11:01 2021",
                created=utils.parse_date(raw_event["Timestamp"]),
                dataset="serverlog",
                kind=event_kind,
                module=dev._module.__name__ if dev._module else "ControlLogix",
                original=str(raw_event),
                outcome=outcome,
                type=event_type,
                extra=extra,
            )

            # TODO: de-duplication of events before export
            dev.event.append(event)

    def get_diagnetwork(self) -> dict:
        """
        Retrieve and parse network interface settings page (``diagnetwork``).
        """
        page = self.get(self.DIAGNETWORK, use_cache=False)

        if not page or not page.text:
            return {}

        return self.parse_diagnetwork(page.text)

    @classmethod
    def parse_diagnetwork(cls, text: str) -> dict:
        """
        Parse and extract data from ``diagnetwork.asp`` HTML page data.
        """
        data = cls._extract_tabular(text, cellspacing=0, cellpadding=4)
        return cls._clean_data(data)

    @classmethod
    def process_diagnetwork(cls, dev: DeviceData, info: dict) -> None:
        """
        Add data from the parsed ``diagnetwork`` page to a
        :class:`~peat.data.models.DeviceData` object.
        """
        # NOTE: Interface.annotate() will add hostname and gateway to related.*
        iface = Interface(
            enabled=True,
            type="ethernet",
            mac=clean_mac(info.get("Ethernet Address (MAC)", "")),
        )

        if info.get("Host Name"):
            iface.hostname = info["Host Name"]

        if info.get("IP Address"):
            iface.ip = info["IP Address"]

        if info.get("Subnet Mask"):
            iface.subnet_mask = info["Subnet Mask"]

        if info.get("Default Gateway"):
            iface.gateway = info["Default Gateway"]

        dev.store("interface", iface)

    def get_modules(self) -> list[dict]:
        """
        Get information about all the modules on the chassis.
        """
        mod_list = self.get_module_list()
        modules = []

        for mod in mod_list:
            mod_data = self.retrieve_module(mod["slot"])
            if not mod_data:
                self.log.debug(f"No data for slot {mod['slot']}")
                continue

            # check if product name and revision match for funsies
            if mod["revision"] != mod_data["Module Revision"]:
                self.log.warning(
                    f"Revision '{mod['revision']}' from module "
                    f"table doesn't match the module details "
                    f"revision '{mod_data['Module Revision']}'"
                )

            if mod["module"] != mod_data["Product Name"]:
                self.log.warning(
                    f"Module name '{mod['module']}' from module "
                    f"table doesn't match the module details "
                    f"name '{mod_data['Product Name']}'"
                )

            modules.append({"slot": mod["slot"], **mod_data})

        return modules

    def get_module_list(self) -> list[dict]:
        """
        Get list of modules on the chassis.
        """
        page = self.get(self.CHASSIS_WHO, use_cache=False)

        if not page or not page.text:
            return []

        return self.parse_module_list(page.text)

    @classmethod
    def parse_module_list(cls, text: str) -> list[dict]:
        """
        Parse and extract list of modules from HTML text.
        """
        rows = cls._extract_rows(text, start=1, width="100%", align="left", cellpadding=0)
        data = []

        for row in rows:
            if len(row) != 5:
                log.trace(f"Skipping row with {len(row)} elements")
                continue

            data.append(
                cls._clean_data(
                    {
                        "module": row[3].a["title"].split("information about ")[-1],
                        "slot": row[3].a["href"].split("slot=")[-1],
                        "revision": row[4].string,
                    }
                )
            )

        return data

    def retrieve_module(self, slot: int) -> dict:
        """
        Information about a specific module in the chassis.
        """
        page = self.get(f"rokform/chassisDetail?slot={slot}", use_cache=False)

        if not page or not page.text:
            return {}
        if "No Information Available" in page.text:
            self.log.info(f"No data available for slot {slot}")
            return {}

        return self.parse_module_page(page.text)

    @classmethod
    def parse_module_page(cls, text: str) -> dict:
        """
        Parse and extract information about a PLC rack module from HTML text.
        """
        data = cls._extract_tabular(text, width=500, cellpadding=4)
        return cls._clean_data(data)

    @classmethod
    def process_modules(cls, dev: DeviceData, raw_modules: list[dict]) -> None:
        """
        Add data from the parsed modules to a
        :class:`~peat.data.models.DeviceData` object.
        """
        cleaned_mods = []

        for raw_mod in raw_modules:
            if not raw_mod:
                continue

            cleaned_mod = {}
            for key, value in raw_mod.items():
                key = key.strip().replace(" ", "_").lower()
                if key == "serial_number":
                    value = cls._convert_serial_num(value)
                cleaned_mod[key] = value.strip()

            cleaned_mods.append(cleaned_mod)

        for mod_dict in cleaned_mods:
            mod = DeviceData()

            if mod_dict.get("slot"):
                mod.slot = mod_dict.pop("slot")

            if mod_dict.get("serial_number"):
                mod.serial_number = mod_dict.pop("serial_number")

            if mod_dict.get("product_name"):
                mod.description.product = mod_dict.pop("product_name")

            if mod_dict.get("vendor"):
                vendor_id = int(mod_dict.pop("vendor"))
                if vendor_id in VENDOR_NAMES:
                    mod.description.vendor.name = VENDOR_NAMES[vendor_id]
                    if vendor_id == 1:
                        mod.description.vendor.id = "Rockwell"
                else:
                    log.warning(f"Unknown vendor ID: {vendor_id}")
                    mod.extra["vendor_id"] = vendor_id

            mod.extra.update(mod_dict)

            if mod.extra.get("module_status"):
                mod.status = mod.extra["module_status"]

            dev.store("module", mod, lookup="slot")

    def get_all(self, dev: DeviceData) -> bool:
        """
        Retrieves and processes data using all available methods.
        """
        # TODO: make this a class attribute, type annotate as typing.Final
        # Function pointers to methods to retrieve and process the data
        pull_process_methods = [
            ("home", self.get_home, self.process_home),
            ("network", self.get_network, self.process_network),
            ("device-identity", self.get_device_identity, self.process_device_identity),
            ("diagnetwork", self.get_diagnetwork, self.process_diagnetwork),
            ("modules", self.get_modules, self.process_modules),
            ("memory", self.get_memory, self.process_memory),
            ("syslog", self.get_syslog, self.process_syslog),
            ("serverlog", self.get_serverlog, self.process_serverlog),
        ]

        self.log.info(
            f"Pulling data from {self.ip}:{self.port} via HTTP "
            f"using {len(pull_process_methods)} methods "
            f"(timeout: {self.timeout} seconds)"
        )
        was_successful = True

        for name, get_func, process_func in pull_process_methods:
            self.log.debug(f"Running method for '{name}' data")
            err_msg = (
                f"Failed to process '{name}' data, "
                f"the ControlLogix module likely doesn't "
                f"support this method"
            )

            try:
                # Retrieve the data via HTTP and parse it into a dict/list
                if name == "serverlog":
                    # Minor hack to allow configurable creds for web login
                    pulled_info = get_func(
                        username=dev.options["web"]["user"],
                        password=dev.options["web"]["pass"],
                    )
                else:
                    pulled_info = get_func()

                if pulled_info:
                    if name == "serverlog":
                        dev.related.user.add(dev.options["web"]["user"])
                    dev.write_file(
                        data=pulled_info,
                        filename=f"{name}.json",  # Example: "syslog.json"
                        out_dir=dev.get_sub_dir("http_json_results"),
                    )
                    # Process the extracted data into the DeviceData object
                    process_func(dev, pulled_info)
                else:
                    self.log.warning(f"No data from '{name}' method")
            except Exception:
                self.log.warning(err_msg)
                self.log.trace(f"'{name}' method traceback\n{traceback.format_exc()}")
                was_successful = False
                continue

        return was_successful


__all__ = ["ClxHTTP"]
