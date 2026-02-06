from collections.abc import Callable
from datetime import timedelta
from pathlib import PurePath

from bs4 import BeautifulSoup

from peat import DeviceData, config, consts, log, utils
from peat.data import Interface, Register, Service, SSHKey, User
from peat.protocols import HTTP, clean_mac


class TotusHTTP(HTTP):
    """
    HTTP interface for the Camlin Totus Dissolved Gas Analyzer (DGA).
    """

    DEFAULT_HEADERS = {
        "sec-ch-ua": '" Not A;Brand";v="99", "Chromium";v="90"',
        "X-Requested-With": "XMLHttpRequest",
        "sec-ch-ua-mobile": "?0",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/90.0.4430.212 Safari/537.36"
        ),
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.methods: dict[str, dict[str, str | Callable]] = {
            "hardware_info": {
                "page": "system/api/1/hardware-info",
                "process_method": self.process_hardware_info,
            },
            "timedate": {
                "page": "system/api/1/timedate",
                "process_method": self.process_timedate,
            },
            "ntp_config": {
                "page": "system/api/1/ntp/config",
                "process_method": self.process_ntp_config,
            },
            "ntp_status": {
                "page": "system/api/1/ntp/status",
                "process_method": self.process_ntp_status,
            },
            "network_configuration": {
                "page": "system/api/1/network/configuration",
                "process_method": self.process_network_configuration,
            },
            "users": {
                "page": "auth/api/v0/users",
                "process_method": self.process_users,
            },
            # NOTE: role processing MUST be called after user processing!
            "roles": {
                "page": "auth/api/v0/roles",
                "process_method": self.process_roles,
            },
            "system_info": {
                "page": "totus/api/1.0/system/info",
                "process_method": self.process_system_info,
            },
            "serial_ports": {
                "page": "totus/api/1.0/system/serial-ports",
                "process_method": self.process_serial_ports,
            },
            "ssh_keys": {
                "page": "system/api/1/ssh-keys/root",
                "process_method": self.process_ssh_keys,
            },
            "openvpn": {
                "page": "system/api/1/openvpn",
                "process_method": self.process_openvpn,
            },
            "wifihotspot": {
                "page": "system/api/1/wifihotspot",
                "process_method": self.process_wifihotspot,
            },
            "modbus_interfaces": {
                "page": "totus/api/1.0/modbus/interfaces",
                "process_method": self.process_modbus_interfaces,
            },
            "dnp3_channels": {
                "page": "totus/api/1.0/dnp3/channels",
                "process_method": self.process_dnp3_channels,
            },
            "modbus_map": {
                "page": "totus/api/1.0/modbus/register-map",
                "parse_method": self.parse_modbus_map,
                "process_method": self.process_modbus_map,
            },
            "dnp3_map": {
                "page": "totus/api/1.0/dnp3/register-map",
                "parse_method": self.parse_dnp3_map,
                "process_method": self.process_dnp3_map,
            },
        }

    @property
    def logged_in(self) -> bool:
        return bool(self.connected and self.session.headers.get("X-XSRF-TOKEN"))

    def login(self, username: str, password: str) -> bool:
        if self.logged_in:
            self.log.debug("Skipping login since we're already logged in")
            return True

        if config.DEBUG:
            self.log.trace(f"Logging in with username '{username}' and password '{password}'")
        else:
            self.log.debug(f"Logging in with username '{username}'")

        # Get login XSRF (Cross-site request forgery) token
        # The token is required for all future requests to DGA
        try:
            # NOTE: This request will return 401 unauthorized, which doesn't
            #   matter since we just need a valid XSRF token.
            profile_response = self.get(page="auth/api/v0/profile", allow_errors=True)

            if profile_response is None or not profile_response.cookies:
                self.log.error("Login failed: bad response")
                return False

            token = profile_response.cookies["XSRF-TOKEN"]

            # TODO: use self.url, ensures correct protocol (http/https)
            login_response = self.post(
                f"http://{self.ip}:{self.port}/auth/login",
                data={"_csrf": token, "username": username, "password": password},
            )

            if not login_response or login_response.status_code != 200:
                self.log.error("Login failed: no response or non-200 status code")
                return False

            # Setting token for nginx to accept authentication/cookies
            self.session.headers["X-XSRF-TOKEN"] = token
            return True
        except Exception as ex:
            self.log.error(f"Login failed: {ex}")
            return False

    def get_and_process_all(self, dev: DeviceData) -> bool:
        """
        Get all data and process any successful retrievals into device data model.

        Returns:
            If at least one method was successful
        """
        at_least_one_success = False
        failed_methods = []

        for label, method in self.methods.items():
            self.log.info(f"Getting '{label}' data from {method['page']}")

            try:
                response = self.get(page=method["page"])

                if not response or not response.text:
                    self.log.warning(
                        f"Failed to get {label} from {method['page']}: no data or error response"
                    )
                    failed_methods.append(label)
                    continue

                # methods that work on text data
                if method.get("parse_method"):
                    self.log.debug(f"Parsing raw {label} data...")
                    parsed_data = method["parse_method"](response.text)

                    if not parsed_data:
                        self.log.warning(f"Failed to parse {label} data")
                        failed_methods.append(label)
                        continue

                # methods that work on JSON data
                else:
                    parsed_data = response.json()
                    # Only add some data to host.extra
                    if label not in ["ssh_keys", "users", "roles"]:
                        dev.extra[label] = parsed_data

                if config.DEVICE_DIR:
                    dev.write_file(
                        data=parsed_data,
                        filename=f"{label}.json",
                        out_dir=dev.get_sub_dir("http_json_data"),
                    )

                # call the process function to put data into device data model
                self.log.debug(f"Processing parsed {label} data into the data model...")
                method["process_method"](dev, parsed_data)

                at_least_one_success = True
            except Exception as ex:
                self.log.exception(f"'{label}' method failed with unhandled exception: {ex}")
                failed_methods.append(label)

        self.log.info(
            f"Finished getting and processing data from {dev.ip} using {len(self.methods)} methods"
        )

        if failed_methods:
            failed_str = "\n\t".join(failed_methods)
            self.log.warning(
                f"{len(failed_methods)} methods failed out of "
                f"{len(self.methods)} total methods for {dev.ip}"
                f"\n** Failed methods **\n{failed_str}"
            )

        return at_least_one_success

    @staticmethod
    def process_hardware_info(dev: DeviceData, hw_info: dict) -> None:
        dev.serial_number = hw_info["serialNumber"]
        dev.firmware.version = hw_info["softwareVersion"]
        dev.hostname = hw_info["hostname"]

        # TODO: ephemeral data from hw_info: freemem, dataFree, dataUsed
        dev.uptime = int(hw_info["uptime"])

        # Hardware information
        dev.architecture = hw_info["arch"]
        dev.hardware.memory_total = int(hw_info["totalmem"])
        dev.hardware.id = str(hw_info["hardwareID"])
        dev.hardware.storage_available = int(hw_info["dataSize"])

        # Operating system
        dev.os.name = hw_info["platform"]
        # TODO: auto-populate os.version from os.kernel in data model
        dev.os.kernel = hw_info["release"]
        dev.os.version = hw_info["release"].partition("-")[0]

    @staticmethod
    def process_timedate(dev: DeviceData, time_info: dict) -> None:
        dev.geo.timezone = time_info["timezone"]

        if dev.uptime:
            # Calculate start_time from device's timestamp - uptime
            curr_time = utils.parse_date(time_info["time"])
            if curr_time:
                dev.start_time = curr_time - timedelta(seconds=dev.uptime.total_seconds())

    @staticmethod
    def process_ntp_config(dev: DeviceData, ntp_config: dict) -> None:
        """
        Add GPS/NTP remotes to set of "related" hosts and IPs.
        """
        for time_source in ntp_config:
            if utils.is_ip(time_source):
                dev.related.ip.add(time_source)
            else:
                dev.related.hosts.add(time_source)

    @staticmethod
    def process_ntp_status(dev: DeviceData, ntp_status: dict) -> None:
        """
        Add GPS/NTP peers to set of "related" hosts and IPs.
        """
        for peer in ntp_status.get("status", {}).get("peers", []):
            if peer.get("remote"):
                if utils.is_ip(peer["remote"]):
                    dev.related.ip.add(peer["remote"])
                else:
                    dev.related.hosts.add(peer["remote"])

    @staticmethod
    def __process_if_dict(dev: DeviceData, iface: Interface, if_dict: dict) -> None:
        """
        Process fields that are in both "devices" and "connections.status".
        """
        if if_dict.get("type"):
            iface.type = if_dict["type"].lower()

        if not iface.ip and if_dict.get("ipAddress"):
            iface.ip = if_dict["ipAddress"]

        if if_dict.get("macAddress"):
            mac = clean_mac(if_dict["macAddress"])
            dev.related.mac.add(mac)

            if not iface.mac:
                iface.mac = mac

            # Add the IP to the interface PEAT is talking to
            if iface.mac == dev.mac:
                if not iface.ip:
                    iface.ip = dev.ip
                if not iface.hostname:
                    iface.hostname = dev.hostname

        # this can be zero, hence the "None" checks
        if iface.speed is None and if_dict.get("speed") is not None:
            iface.speed = int(if_dict["speed"])

        if not iface.subnet_mask and if_dict.get("netmask"):
            iface.subnet_mask = if_dict["netmask"]

        if not iface.gateway and if_dict.get("defaultGateway"):
            iface.gateway = if_dict["defaultGateway"]

        if not iface.id and if_dict.get("id"):
            iface.id = if_dict["id"]

        if if_dict.get("deviceState"):
            iface.extra["device_state"] = if_dict["deviceState"]

            if if_dict["deviceState"] != "unmanaged":
                iface.enabled = True
            else:
                iface.enabled = False

            if if_dict["deviceState"] == "connected":
                iface.connected = True
            else:
                iface.connected = False

        if "carrier" in if_dict:
            # "carrier" field indicates if there's a carrier signal on Ethernet
            # interfaces (e.g. a cable is connected to a switch).
            iface.connected = bool(if_dict["carrier"])

        # modem interface data
        if if_dict.get("type", "").lower() == "modem":
            if if_dict.get("modemState"):
                if if_dict["modemState"] == "enabled":
                    iface.enabled = True
                elif if_dict.get("modemState") == "connected":
                    iface.enabled = True
                    iface.connected = True
                elif iface.connected is None:
                    iface.connected = False

            if if_dict.get("fwVersion"):
                iface.version = str(if_dict.get("fwVersion", ""))

            if not iface.description.vendor.name:
                iface.description.vendor.name = if_dict.get("manufacturer", "")

            if not iface.description.model:
                iface.description.model = str(if_dict.get("model", ""))

            if if_dict.get("modemState") == "connected":
                iface.connected = True
            else:
                iface.connected = False

            iface.extra.update(
                {
                    "modem_state": str(if_dict.get("modemState", "")),
                    "access_tech": str(if_dict.get("accessTech", "")),
                    "signal": str(if_dict.get("signal", "")),
                    "primary_port": str(if_dict.get("primaryPort", "")),
                    "device": str(if_dict.get("device", "")),
                    "equipment_id": str(if_dict.get("equipmentId", "")),
                    "registration_state": str(if_dict.get("registrationState", "")),
                    "network": str(if_dict.get("network", "")),
                }
            )

    @staticmethod
    def process_network_configuration(dev: DeviceData, net_config: dict[str, list[dict]]) -> None:
        for raw_if in net_config["devices"]:
            iface = Interface(name=raw_if.get("name", ""))

            # Annotate fields on the Interface object
            TotusHTTP.__process_if_dict(dev, iface, raw_if)

            # Store into data model
            dev.store("interface", iface, lookup=["name", "mac", "ip"])

        for conn in net_config["connections"]:
            settings = conn.get("settings", {})
            status = conn.get("status", {})

            if settings.get("username"):
                dev.related.user.add(settings["username"])

            if_name = settings.get("interfaceName")
            if if_name:
                iface = dev.retrieve("interface", {"name": if_name})  # type: Interface

                if not iface:
                    iface = Interface(name=if_name)
                    dev.store("interface", iface, lookup="name")

                # Annotate fields on the Interface object
                TotusHTTP.__process_if_dict(dev, iface, status)
                TotusHTTP.__process_if_dict(dev, iface, settings)

                if conn.get("id"):
                    iface.extra["connection_id"] = conn["id"]

                if settings.get("name"):
                    iface.description.description = settings["name"]

                for s_key in ["autoconnect", "apn", "username"]:
                    if s_key in settings:
                        iface.extra[s_key] = settings[s_key]

            # Save any IPs to related.ip
            for ip_path in [
                "settings.ipAddress",
                "settings.defaultGateway",
                "settings.primaryDns",
                "status.ipAddress",
                "status.defaultGateway",
                "status.primaryDns",
            ]:
                ip = utils.deep_get(conn, ip_path, "")
                if ip and utils.is_ip(ip):
                    dev.related.ip.add(ip)

            # Save any MACs to related.mac
            for mac_path in ["settings.macAddress", "status.macAddress"]:
                mac = clean_mac(utils.deep_get(conn, mac_path, ""))
                if mac:
                    dev.related.mac.add(mac)

    @staticmethod
    def process_users(dev: DeviceData, users: dict[str, list[dict[str, str | int]]]) -> None:
        for user_dict in users["items"]:
            dev.related.user.add(user_dict.get("sub", ""))
            dev.related.user.add(user_dict.get("name", ""))

            user = User(
                name=user_dict.get("sub", ""),
                full_name=user_dict.get("name", ""),
            )

            if user_dict.get("id") is not None:
                user.id = str(user_dict["id"])

            if user_dict.get("role"):
                dev.related.roles.add(user_dict["role"])
                user.roles.add(user_dict["role"])

            if user_dict.get("state"):
                user.extra["state"] = user_dict["state"]

            if user_dict.get("iss"):
                user.extra["iss"] = user_dict["iss"]
                if "://" in user_dict["iss"]:
                    dev.related.urls.add(user_dict["iss"])

            dev.store("users", user, lookup="name")

    @staticmethod
    def process_roles(dev: DeviceData, roles: dict[str, list[dict]]) -> None:
        """
        Permissions allocated to roles.

        NOTE: This MUST be called after process_users()!
        """
        for role in roles["items"]:
            if not role.get("name"):
                log.warning(f"Skipping role with no name for {dev.get_comm_id()}: {role}")
                continue

            dev.related.roles.add(role["name"])

            # lookup user, if role name in user roles, then add permissions
            # this MUST be called after process_users!
            if role.get("permissions"):
                for user in dev.users:
                    if role["name"] in user.roles:
                        user.permissions.update(role["permissions"])

    @staticmethod
    def process_system_info(dev: DeviceData, system_info: dict) -> None:
        if not dev.firmware.version and system_info.get("softwareVersion"):
            dev.firmware.version = str(system_info["softwareVersion"])

        if not dev.hostname and system_info.get("hostname"):
            dev.hostname = str(system_info["hostname"])

    @staticmethod
    def process_serial_ports(dev: DeviceData, serial_ports: dict) -> None:
        """
        Serial ports on device.
        """
        for ser_dev in serial_ports:
            iface = Interface(name=ser_dev["name"], type="serial", serial_port=ser_dev["device"])

            if ser_dev.get("flow_control") and "none" in ser_dev["flow_control"]:
                iface.flow_control = "none"

            dev.store("interface", iface, lookup=["name", "serial_port"])

    @staticmethod
    def process_ssh_keys(dev: DeviceData, ssh_keys: dict) -> None:
        """
        Extract usernames, IPs, and/or hostnames from SSH public keys.
        """
        for key_dict in ssh_keys:
            if not key_dict:
                continue

            if not key_dict.get("publicKey"):
                log.warning(
                    f"Skipping invalid ssh key for {dev.get_comm_id()}: "
                    f"no 'publicKey' field\nRaw key: {key_dict}"
                )
                continue

            # Possible values for publicKey:
            #   "ssh-ed25519@22:1.2.3.4 0x6c91e1...f8157"
            #   "ssh-rsa AAAAbbbb...cccc user@hostname\n"
            #   "ssh-rsa AAAAbbbb...cccc rsa-key-<timestamp>"
            #   "/root/.ssh/keyname.pub"
            #   "keyname.pub"

            key_obj = SSHKey(
                id=key_dict.get("keyId", "").strip(),
                original=key_dict["publicKey"].strip(),
                type="public",
            )

            key_parts = key_obj.original.split(" ")

            if not key_parts or len(key_parts) == 1:
                if len(key_parts) == 1 and "." in key_parts[0]:
                    key_obj.file.path = PurePath(key_parts[0])
                    dev.related.files.add(key_parts[0])
                else:
                    log.warning(
                        f"TotusHTTP: failed to parse SSH key from {dev.ip} (key='{key_parts}')"
                    )
                    continue

            # "ssh-ed25519@22:1.2.3.4 <key>"
            if "@" in key_parts[0]:
                p2 = key_parts[0].partition("@")[2]
                if ":" in p2:
                    p2 = p2.partition(":")[2]

                if utils.is_ip(p2):
                    dev.related.ip.add(p2)
                else:
                    dev.related.hosts.add(p2)
                key_obj.host = p2

            # "<key> root@testb"
            if len(key_parts) >= 3:
                if "@" in key_parts[2]:
                    user = key_parts[2].partition("@")[0].strip()
                    dev.related.user.add(user)
                    key_obj.user = user

                    host = key_parts[2].partition("@")[2].strip()
                    if utils.is_ip(host):
                        dev.related.ip.add(host)
                    else:
                        dev.related.hosts.add(host)
                    key_obj.host = host
                elif utils.is_ip(key_parts[2]):
                    dev.related.ip.add(key_parts[2])
                    key_obj.host = key_parts[2]

            dev.store("ssh_keys", key_obj, lookup="id")

    @staticmethod
    def process_openvpn(dev: DeviceData, openvpn: dict) -> None:
        """
        Extract hostnames and/or IPs from OpenVPN configs.
        """
        for ov_profile in openvpn.get("profiles", []):
            # Add any IPs found in "address" to remote.ip
            if ov_profile.get("address"):
                for chunk in ov_profile["address"].strip().split(","):
                    if utils.is_ip(chunk):
                        dev.related.ip.add(chunk)

            # Add remote hosts to related.ip and/or related.hosts
            for remote in ov_profile.get("remotes", []):
                if not remote.get("host"):
                    continue

                if utils.is_ip(remote["host"]):
                    dev.related.ip.add(remote["host"])
                else:
                    dev.related.hosts.add(remote["host"])

    @staticmethod
    def process_wifihotspot(dev: DeviceData, wifihotspot: dict) -> None:
        # TODO: what interface is this internally? (in output of "ip addr" command)
        iface = Interface(name="wifihotspot", enabled=False, type="wifi")

        if wifihotspot.get("status") != "off":
            iface.enabled = True

        iface.description.description = (
            f"Wi-Fi Hotspot with an SSID of {wifihotspot.get('ssid', '')}"
        )

        iface.extra.update(wifihotspot)
        if iface.extra.get("password"):
            del iface.extra["password"]

        dev.store("interface", iface, lookup="name")

    @staticmethod
    def process_modbus_interfaces(dev: DeviceData, modbus_interfaces: dict) -> None:
        """
        Modbus configuration.
        """
        for mb_if in modbus_interfaces:
            svc = Service(protocol="modbus", enabled=True)

            if mb_if.get("port"):
                svc.port = int(mb_if["port"])
            if mb_if.get("slaveAddress") is not None:
                svc.protocol_id = str(mb_if["slaveAddress"])
            if mb_if.get("name"):
                svc.extra["name"] = str(mb_if["name"])
            if mb_if.get("id") is not None:
                svc.extra["id"] = mb_if["id"]

            interface_lookup = None
            if mb_if.get("device") == "tcp":
                svc.protocol = "modbus_tcp"
                svc.transport = "tcp"
                interface_lookup = {"ip": dev.ip}

            if svc.port:
                dev.related.ports.add(svc.port)
            if svc.protocol:
                dev.related.protocols.add(svc.protocol)

            dev.store("service", svc, interface_lookup=interface_lookup)

    @staticmethod
    def process_dnp3_channels(dev: DeviceData, dnp3_channels: dict) -> None:
        """
        DNP3 configuration.
        """
        for dnp3_ch in dnp3_channels:
            svc = Service(
                protocol="dnp3",
                port=int(dnp3_ch["config"]["port"]),
                enabled=True,
                protocol_id=str(dnp3_ch.get("localAddress", "")),
                extra={
                    "id": str(dnp3_ch.get("id", "")),
                    "name": str(dnp3_ch.get("name", "")),
                },
            )

            if dnp3_ch.get("channel", "").lower() == "tcp":
                svc.transport = "tcp"
            elif dnp3_ch.get("channel") is not None:
                svc.extra["channel"] = dnp3_ch["channel"]
            if dnp3_ch.get("bufferSize") is not None:
                svc.extra["buffer_size"] = int(dnp3_ch["bufferSize"])
            if dnp3_ch.get("remoteAddress") is not None:
                svc.extra["remote_address"] = int(dnp3_ch["remoteAddress"])
            if dnp3_ch.get("keepaliveTimeout") is not None:
                svc.extra["keepalive_timeout"] = int(dnp3_ch["keepaliveTimeout"])

            if svc.port:
                dev.related.ports.add(svc.port)
            if svc.protocol:
                dev.related.protocols.add(svc.protocol)

            dev.store("service", svc, interface_lookup={"ip": dev.ip})

    @staticmethod
    def parse_modbus_map(modbus_map_html: str) -> list[dict]:
        """
        Parse raw HTML page with the Modbus register map.
        """
        mb_soup = BeautifulSoup(modbus_map_html, features=consts.BS4_PARSER)
        mb_tables = list(mb_soup.body.find_all("table"))
        ht_body = mb_tables[0]

        # In some cases it has "tbody", in others it doesn't.
        # Might be a difference between software versions.
        if mb_tables[0].find("tbody"):
            ht_body = mb_tables[0].find("tbody")

        mb_headers = [
            str(th.string).strip().lower().replace(" ", "_") if th.string else ""
            for th in ht_body.find("tr").find_all("th")
        ]
        mb_data = []

        for m_tbl in mb_tables:
            m_tbl_body = m_tbl
            if m_tbl.find("tbody"):
                m_tbl_body = m_tbl.find("tbody")
            for tbl_entry in m_tbl_body.find_all("tr")[1:]:
                mb_data.append(
                    {
                        h: str(td.string) if td.string else None
                        for h, td in zip(mb_headers, tbl_entry.find_all("td"), strict=False)
                    }
                )

        return mb_data

    @staticmethod
    def process_modbus_map(dev: DeviceData, mb_data: list[dict]) -> None:
        for entry in mb_data:
            # TODO: handle number_of_registers > 1
            reg = Register(
                protocol="modbus",
                address=entry["address"],
                data_type=entry.get("format", "").lower(),
                tag=entry.get("topic", ""),
            )

            if "read only" in entry.get("access", "").lower():
                reg.read_write = "read"
            if entry.get("notes"):
                reg.description = entry["notes"]
            if entry.get("register") is not None:
                reg.extra["register"] = int(entry["register"])
            if entry.get("number_of_registers") is not None:
                reg.extra["number_of_registers"] = int(entry["number_of_registers"])
            if entry.get("scaling") is not None:
                reg.extra["scaling"] = float(entry["scaling"])
            if entry.get("offset") is not None:
                reg.extra["offset"] = entry["offset"]

            dev.store(
                "registers",
                reg,
                lookup={"protocol": reg.protocol, "address": reg.address},
            )

    @staticmethod
    def parse_dnp3_map(dnp3_map_html: str) -> dict[str, list[dict]]:
        """
        Parse raw HTML page with the DNP3 register map.
        """
        dnp3_soup = BeautifulSoup(dnp3_map_html, features=consts.BS4_PARSER)

        # Analogue Inputs, Digital Inputs
        dnp3_sections = {
            str(table_header.string): table
            for table_header, table in zip(
                list(dnp3_soup.body.find_all("h2")),
                list(dnp3_soup.body.find_all("table")),
                strict=False,
            )
        }
        dnp3_data = {}

        for section_name, section_table in dnp3_sections.items():
            t_type = section_name.split(" ")[0].lower().replace("s", "")
            t_type = t_type.replace("analogue", "analog")
            # TODO: add to dev.io?
            # direction = section_name.split(" ")[1].lower().replace("s", "")
            parsed_section = []
            section_headers = [
                str(th.string).strip().lower().replace(" ", "_") if th.string else ""
                for th in section_table.find("thead").find("tr").find_all("th")
            ]
            tbl_body = section_table
            if section_table.find("tbody"):
                tbl_body = section_table.find("tbody")
            for tbl_entry in tbl_body.find_all("tr")[1:]:
                parsed_section.append(
                    {
                        h: str(td.string) if td.string else None
                        for h, td in zip(section_headers, tbl_entry.find_all("td"), strict=False)
                    }
                )
            dnp3_data[section_name] = parsed_section

        return dnp3_data

    @staticmethod
    def process_dnp3_map(dev: DeviceData, dnp3_data: dict[str, list[dict]]) -> None:
        # "analogue inputs", "digital inputs"
        for section_name, section_data in dnp3_data.items():
            section_type = section_name.split(" ")[0].lower().replace("s", "")
            section_type = section_type.replace("analogue", "analog")

            for entry in section_data:
                reg = Register(
                    protocol="dnp3",
                    address=entry.get("index", ""),
                    tag=entry.get("topic", ""),
                    measurement_type=section_type,
                )
                if entry.get("description"):
                    reg.description = entry["description"]
                if entry.get("type") is not None:
                    reg.data_type = entry["type"].lower()
                if entry.get("class") is not None:
                    reg.extra["class"] = entry["class"]
                if entry.get("scale") is not None:
                    reg.extra["scale"] = float(entry["scale"])
                if entry.get("offset") is not None:
                    reg.extra["offset"] = entry["offset"]
                dev.store(
                    "registers",
                    reg,
                    lookup={
                        "protocol": reg.protocol,
                        "address": reg.address,
                        "measurement_type": reg.measurement_type,
                    },
                )


__all__ = ["TotusHTTP"]
