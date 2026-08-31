"""
SEL-362X Family of Security Gateways.

This module is designed to support both the SEL-3622 and the SEL-3620, though
was originally developed for the former.

Authors:
    - Francisco Santana
    - Nehal Ameen
"""

from copy import deepcopy as clone
from time import sleep
from types import FunctionType
from typing import Any, Optional, Callable
from datetime import datetime

from pydantic import BaseModel

from peat import DeviceData, DeviceModule, IPMethod, Service, Interface, User

from ..relay_parse import parse_fid
from . import sel362x_pull as p
from .sel362x_http import HTTP362X

from hashlib import md5, sha1, sha256, sha512, _Hash
from pathlib import Path


def do_hash(hcons: Callable[..., _Hash], data: str) -> str:
    """Get a HASH object from `hcons`, then make a digest of `data`"""
    hobj = hcons(usedforescurity=False)
    hobj.update(data.encode())
    return hobj.hexdigest()


def webcfg_summarize(dev: DeviceData, data: dict[str, Any]):
    """Summarize the contents of the full web config."""
    web_cert: str | None = None

    roles: dict[str, set[str]] = {}
    # Fetch local groups to use as roles
    # Convert from group-to-user surjective to user-to-group surjective
    if "local_groups" in data:
        lg = data["local_groups"]
        for g in lg:
            for name in lg[g]:
                if name not in roles:
                    roles[name] = set()
                roles[name].add(g)

    # Convert the list of users to an appropriate data model
    if "users" in data:
        for username in data["users"]:
            ud = data["users"][username]

            # "admin" perms for admin rights
            perms = set()
            if ud["admin"]:
                perms.add("admin")
            # "enabled" perms for enabled, "disabled" perms otherwise
            if ud["enabled"]:
                perms.add("enabled")
            else:
                perms.add("disabled")

            udata = User(
                email=ud["email"],
                full_name=f"{ud['first_name']} {ud['last_name']}",
                name=username,
                permissions=perms,
                roles=roles[username],
            )

            dev.users.append(udata)
            dev.related.user.add(username)
            if ud["email"] != "N/A":
                dev.related.emails.add(ud["email"])

    if "network" in data:
        ips = {}
        for alias in data["network"]["addresses"]:
            addr: str = data["network"]["addresses"][alias]["address"]
            addr = addr.split("/")[0]

            dev.related.ip.add(addr)

            iface = data["network"]["addresses"][alias]["interface"]
            if iface not in ips:
                ips[iface] = addr

        if "hostname" in data["network"]["global"]:
            dev.related.hosts.add(data["network"]["global"]["hostname"])

        if "gateway" in data["network"]["global"]:
            dev.related.ip.add(data["network"]["global"]["gateway"])

        for iface in data["network"]["interfaces"]:
            idata = data["network"]["interfaces"][iface]
            id = Interface(
                alias=iface,
                enabled=idata["status"] == "Enabled",
                type="ethernet",
                physical=True,
            )
            if iface in ips:
                id.ip = ips[iface]
            dev.interface.append(id)

    if "web_server" in data:
        port = data["web_server"]["port"]
        for listener in data["web_server"]["listeners"]:
            listener = data["web_server"]["listeners"][listener]

            ip: str = listener["ip"]
            ip = ip.split("/")[0]

            dev.service.append(
                Service(
                    port=port,
                    protocol="https",
                    transport="tcp",
                    listen_address=ip,
                )
            )

            dev.related.ip.add(ip)
            web_cert = data["web_server"]["cert"]

    if "static_routes" in data:
        sr = data["static_routes"]

        for id in sr:
            d = sr[id]
            if "gateway_address" in d:
                dev.related.ip.add(d["gateway_address"])

            dev.related.ip.add(d["network"].split("/")[0])

    if "version_information" in data:
        dev.firmware.version = data["version_information"]["version"]
        dev.firmware.extra["fid"] = data["version_information"]["fid"]
        dev.firmware.extra["serial_number"] = data["version_information"][
            "serial_number"
        ]

    if "ldap" in data:
        for server in data["ldap"]["servers"]:
            dev.related.hosts.add(server)

        for role in data["ldap"]["group_mappings"]:
            dev.related.roles.add(role)

    if "snmp" in data:
        servers = data["snmp"]["servers"]

        for server in servers:
            dev.related.ip.add(server["address"])

    if "syslog_settings" in data:
        for dst in data["syslog_settings"]["destinations"]:
            dev.related.ip.add(dst["ip"])

    if "certificates" in data and web_cert:
        cert: dict[str, str] | None = None
        if web_cert not in data["certificates"] and web_cert == "Default":
            cert = data["certificates"]["Default_Web_Cert"]
        elif web_cert in data["certificates"]:
            cert = data["certificates"][web_cert]

        if cert:
            dev.x509.alternative_names = cert["subject_alt_names"].split(",")

            if cert["file"] and (dev.get_out_dir() / cert["file"]).exists():
                certdata = (dev.get_out_dir() / cert["file"]).read_text()
                dev.x509.hash.md5 = do_hash(md5, certdata)
                dev.x509.hash.sha1 = do_hash(sha1, certdata)
                dev.x509.hash.sha256 = do_hash(sha256, certdata)
                dev.x509.hash.sha512 = do_hash(sha512, certdata)

                dev.x509.original = certdata

            dev.x509.issuer.common_name = cert["issuer_common_name"]
            dev.x509.issuer.country = cert["issuer_country"]
            dev.x509.issuer.state_or_province = cert["issuer_state"]
            dev.x509.issuer.locality = cert["issuer_locality"]
            dev.x509.issuer.organization = cert["issuer_org_name"]
            dev.x509.issuer.organizational_unit = cert["issuer_org_unit_name"]
            dev.x509.issuer.distinguished_name = cert["issuer_subject"]

            dev.x509.not_before = datetime.fromisoformat(cert["valid_start"])
            dev.x509.not_after = datetime.fromisoformat(cert["valid_end"])

            dev.x509.subject.common_name = cert["common_name"]
            dev.x509.subject.country = cert["country"]
            dev.x509.subject.state_or_province = cert["state"]
            dev.x509.subject.locality = cert["locality"]
            dev.x509.subject.organization = cert["org_name"]
            dev.x509.subject.organizational_unit = cert["org_unit_name"]
            dev.x509.subject.distinguished_name = cert["subject"]

            dev.x509.version_number = cert["version"]
            dev.x509.serial_number = cert["serial_number"]

        if "serial_ports" in data:
            for port in data["serial_ports"]:
                pdata = data["serial_ports"][port]
                dev.interface.append(
                    Interface(
                        alias=port,
                        enabled=pdata["state"] == "Enabled",
                        type="serial",
                        physical=True,
                        baudrate=int(pdata["baud_rate"]),
                        data_bits=int(pdata["data_bits"]),
                        parity=pdata["parity"],
                        stop_bits=pdata["stop_bits"],
                        flow_control=pdata["hw_flow_control"],
                    )
                )

        if "radius" in data:
            if data["radius"]["primary_server"]:
                dev.related.ip.add(data["radius"]["primary_server"])
            if data["radius"]["secondary_server"]:
                dev.related.ip.add(data["radius"]["secondary_server"])

        if "diagnostics" in data:
            d = data["diagnostics"]

            if "free_memory" in d:
                mem = d["free_memory"]

                dev.hardware.memory_available = mem["physical"]["free"]
                dev.hardware.memory_total = mem["physical"]["total"]
            if "process_list" in d:
                for p in d["process_list"]:
                    dev.related.process = p["command"]


class AdvancedRange(BaseModel):
    """An inclusive range type for versioning."""

    low: Optional[int] = None
    high: Optional[int] = None

    def __contains__(self, value: int) -> bool:
        result = True

        if self.low is not None:
            result = value >= self.low
        if self.high is not None and result:
            result = self.high >= value

        return result

    def __str__(self) -> str:
        if self.low is not None and self.high is not None:
            return f"{self.low} - {self.high}"
        elif self.low is not None:
            return f">= {self.low}"
        elif self.high is not None:
            return f"<= {self.high}"
        else:
            return "any"


AR = AdvancedRange


def irange(low: int | None = None, high: int | None = None) -> AdvancedRange:
    return AdvancedRange(low=low, high=high)


class Method:
    """Handles methods and compatibility"""

    handler: FunctionType
    attempts: int
    for_device: list[str]
    for_firmware: AdvancedRange | int

    def __init__(
        self,
        handler: FunctionType,
        attempts: int = 3,
        for_device: list[str] = [],
        for_firmware: AdvancedRange | int = AdvancedRange(),
    ):
        self.handler = handler
        self.attempts = attempts
        self.for_device = [d.lower() for d in for_device]
        self.for_firmware = for_firmware

    def dev_compat(self, dev: str) -> bool:
        """Check for device compatibility"""
        return len(self.for_device) == 0 or dev.lower() in self.for_device

    def firmware_compat(self, fw: int) -> bool:
        """Check for firmware compatibility"""
        return (
            fw in self.for_firmware
            if isinstance(self.for_firmware, AdvancedRange)
            else fw == self.for_firmware
        )

    def is_compat(self, dev: DeviceData) -> bool:
        """Check for compatibility"""
        return self.dev_compat(dev._cache["DEVICE"]) and self.firmware_compat(
            dev._cache["VERSION"]
        )

    def handle(self, dev: DeviceData, session: HTTP362X) -> dict[str, Any] | None:
        """Handle this method. Performs a compatibility check before executing the encapsulated method."""
        if not self.is_compat(dev):
            return None

        ex: Exception | None = None
        for a in range(self.attempts):
            try:
                return self.handler(dev, session)
            except Exception as e:
                ex = e

        raise (
            ex
            if isinstance(ex, Exception)
            else Exception(f"Failed to run method {self.handler.__name__}")
        )


class SEL362X(DeviceModule):
    """
    SEL-3620 Security Gateway.
    SEL-3622 Ethernet Security Gateway.

    It is possible (and planned) to replace the 3620 module with this one.
    To avoid ambiguity, this module will not alias the 3620.
    """

    device_type = "Gateway"
    vendor_id = "SEL"
    vendor_name = "Schweitzer Engineering Laboratories"
    brand = "SEL"
    module_aliases = ["sel-3622", "sel-362x", "3622", "362x"]
    default_options = {"web": {"user": "admin", "pass": "Admin123!", "users": []}}

    @classmethod
    def get_session(cls, dev: DeviceData) -> HTTP362X | None:
        """
        Get the session associated with the device
        """
        if "web_session" in dev._cache:
            session = dev._cache["web_session"]
            assert isinstance(session, HTTP362X)
            if session.is_logged_in():
                return session

        port = dev.options["https"]["port"]
        timeout = dev.options["https"]["timeout"]

        cls.log.debug(f"Verifying on port {port} with timeout {timeout}")

        session = HTTP362X(dev.ip, port, timeout)

        user = None
        passwd = None

        if dev._cache.get("verified_web_user") and dev._cache.get("verified_web_pass"):
            user = dev._cache["verified_web_user"]
            passwd = dev._cache["verified_web_pass"]
        else:
            if dev.options["web"]["user"]:
                user = dev.options["web"]["user"]
                passwd = dev.options["web"]["pass"]
            else:
                user = cls.default_options["web"]["user"]
                passwd = cls.default_options["web"]["pass"]

        login_timeout = dev.options.get("login_timeout")
        login_timeout = int(login_timeout) if login_timeout else 10

        cls.log.debug(
            f"Attempting log-in as {user} with a timeout of {login_timeout} seconds"
        )
        if not session.login(str(user), str(passwd), login_timeout):
            cls.log.error("Failed to log in to the device!")
            return None
        else:
            dev._cache["web_session"] = session
            dev._cache["global_token"] = session.get_global_token_value()
            return session

    @classmethod
    def _verify_http(cls, dev: DeviceData) -> bool:
        """
        Validate that the device is an SEL-362X via its HTTPS web interface
        """
        cls.log.info(f"SEL/362X: Verifying {dev.ip} via HTTPS")

        session = cls.get_session(dev)
        if not session:
            cls.log.error("Failed to log in to the device!")
            return False

        if session.validate_fid():
            cls.log.info("Success! This device is a supported SEL security gateway!")
        else:
            cls.log.error("Failure!")
            return False

        return True

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        """
        Pull data from the SEL 362X
        """
        cls.log.info(f"SEL/362X: Pulling information")

        session = cls.get_session(dev)
        port = dev.options["https"]["port"]
        if not session:
            cls.log.error("Failed to initialize session")
            return False

        fid = session.get_fid()
        if fid is None:
            cls.log.error("Failed to get the device's FID")
            raise Exception("Could not get the device's FID")

        fid = parse_fid(fid)

        dev._cache["DEVICE"] = fid["model"]
        dev._cache["VERSION"] = int(fid["revision"][1:])

        methods = [  # List pull methods here ((dev: DeviceData, session) -> dict[str, Any])
            # Prepare for pull later
            Method(p.initialize_file_management_pull, 1, for_firmware=AR(high=200)),
            # System
            Method(p.pull_usage_policy, 3),
            Method(p.pull_web_server_config, 3),
            # pull_file_management [moved to the end]
            Method(p.pull_physical_sensors, 3),
            # User
            Method(p.pull_users, 3),
            Method(p.pull_ldap_settings, 3),
            Method(p.pull_radius_settings, 3),
            Method(p.pull_local_groups, 3),
            # Network
            Method(p.pull_network_settings, 3),
            Method(p.pull_static_routes, 3),
            Method(p.pull_syslog_settings, 3),
            Method(p.pull_firewall_rules, 3),
            Method(p.pull_nat_config, 3, [], AR(low=212)),
            Method(p.pull_hosts, 3),
            Method(p.pull_snmp_settings, 3),
            # Serial Ports
            Method(p.pull_serial_port_settings, 3),
            Method(p.pull_serial_port_profiles, 3),
            Method(p.pull_port_mappings, 3),
            # Security
            Method(p.pull_certificates, 3),
            Method(p.pull_ipsec_connections, 3),
            Method(p.pull_clients, 3),
            Method(p.pull_host_keys, 3),
            Method(p.pull_passwd_mgmt, 3),
            # Reports
            Method(p.pull_syslog_report, 3),
            Method(p.pull_diagnostics, 3),
            # File Management is last to allow for enough time to see an update to the configuration
            Method(p.pull_file_management, 1, for_firmware=AR(high=200)),
        ]
        pulled_config = {}
        used_methods = {}

        tried_methods = 0

        for method in methods:
            tried_methods += 1
            cls.log.info(
                f'({tried_methods}/{len(methods)}) Attempting method "{method.handler.__name__}" for {dev.ip}:{port}'
            )

            try:
                # Call the method (`.handle()` checks for compatibility)
                result = method.handle(dev, session)
                if result is None:  # None indicates incompatibility
                    cls.log.info(
                        f'({tried_methods}/{len(methods)}) Method "{method.handler.__name__}" was not compatible'
                    )
                    used_methods[method.handler.__name__] = "NOT COMPAT"
                    continue

                for k in result:  # Check root keys for duplicates
                    if k in pulled_config:
                        cls.log.warning(
                            f"Key {k} is already present from a previous pull; overwriting..."
                        )

                # Report OK and update pulled config
                used_methods[method.handler.__name__] = "OK"
                pulled_config.update(result)
                cls.log.info(
                    f'({tried_methods}/{len(methods)}) Successfully used method "{method.handler.__name__}" on {dev.ip}:{port}'
                )

                sleep(1)
            except Exception as e:
                # Report error and mark not OK
                cls.log.exception(f"Exception caught: {e}")
                used_methods[method.handler.__name__] = "NOT OK"

        try:
            # Pull the index page to add extra data
            p.pull_index(dev, session, pulled_config)
        except Exception as e:
            cls.log.warning(f"Failed to pull data from dashboard: {e}")

        # Write relevant files

        dev.write_file(pulled_config, "web_cfg.json")  # Full web configuration
        dev.related.files.add("web_cfg.json")

        microconf = clone(pulled_config)
        if "syslog_report" in microconf:
            del microconf["syslog_report"]

        dev.write_file(microconf, "short_web_cfg.json")
        dev.related.files.add("short_web_cfg.json")

        dev.write_file(used_methods, "attempted_methods.json")
        dev.related.files.add("attempted_methods.json")

        webcfg_summarize(dev, pulled_config)

        cls.update_dev(dev)

        return True


# This seems to list the methods to be used to perform validation
SEL362X.ip_methods = [
    IPMethod(
        name="Perform a Web fingerprint (SEL-362x)",
        description=str(SEL362X._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=SEL362X._verify_http,
        default_port=443,
        protocol="https",
        reliability=8,
        transport="tcp",
    )
]
