"""
The Siemens SIPROTEC 4 Relay.

Services

- WebMonitor (TCP 80 and TCP 443)
- IEC61850 (TCP 102)
- SNMP (UDP 161)
- Unknown service (UDP 43690)
- DIGSI (UDP 50000)
- WebMonitor comms (UDP 56797)

There is a web interface located at port 80 that uses Java applets for
some features (use Internet Explorer and Java version 6).

Authors

- Christopher Goes
- Michelle Cabahug
"""

import binascii
import functools
import os.path
from datetime import datetime
from pprint import pformat
from typing import Literal

from peat import DeviceData, DeviceModule, IPMethod
from peat.protocols import HTTP, SNMP, snmp_walk

from .mlfb import decode_mlfb

# Directory containing SNMP MIBs as 'compiled' PySNMP Python files
# TODO: the mibs path won't work in a pyinstaller exe since it's a directory
#  and importlib.resources doesn't like that. We need to figure
#  out a better way to store and use SNMP MIBs in general.
# SIPROTEC_MIBS_DIR: str = utils.get_resource(__package__, "mibs")
# SIPROTEC_MIBS_DIR = Path(Path(__file__).parent, 'mibs').resolve()
SIPROTEC_MIBS_DIR = os.path.abspath(os.path.join(__file__, "..", "mibs"))

# TODO: add parse method that takes MLFB and/or VER txt files


class Siprotec(DeviceModule):
    """
    Siemens SIPROTEC 4 Relay.
    """

    device_type = "Relay"
    vendor_id = "Siemens"
    vendor_name = "Siemens AG"
    brand = "Siprotec"
    model = "7SJ6x"

    @classmethod
    def _verify_snmp(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a Siprotec by querying SNMP for OID
        ``1.3.6.1.2.1.1.1.0`` (``sysDescr``) and comparing the
        output against the string ``SIPROTEC``.
        """
        # TODO: use dev.options["snmp"]["community"] if it's configured
        for community in dev.options["snmp"]["communities"]:
            # TODO: some siprotecs are returning "Fusion 7.0"
            # 'Fusion 7.0 SNMP for Fusion TCP/IP'
            to_find = ["SIPROTEC"]

            snmp = SNMP(
                dev.ip,
                dev.options["snmp"]["port"],
                dev.options["snmp"]["timeout"],
                community=community,
            )

            if snmp.verify("1.3.6.1.2.1.1.1.0", to_find=to_find):
                # !! TODO: hack to cache the community that worked !!
                dev._options["snmp"]["community"] = community
                return True

        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        successful = True

        # Pull HTTP data
        # TODO: better way of selecting protocol to use (encrypted/unencrypted)
        web_success = False
        cls.log.info(f"Pulling WebMonitor information from {dev.ip}...")
        for protocol in ["http", "https"]:
            if dev.service_status({"protocol": protocol}) == "verified":
                if cls._get_webmonitor_data(dev, protocol):
                    web_success = True
        if not web_success:
            successful = False
        cls.log.info(f"Finished pulling WebMonitor information from {dev.ip}")

        # Pull SNMP data
        try:
            snmp_module, system = cls._get_snmp_data(
                ip=dev.ip,
                timeout=dev.options["snmp"]["timeout"],
                community=dev.options["snmp"]["community"],
            )
            if system.get("system_uptime"):
                dev.uptime = system.pop("system_uptime")  # TODO: timedelta?
                # TODO: calculate dev.start_time

            # Add the overall system info straight into the device info
            dev.extra.update(system)

            # Add the information for each module to its corresponding dict
            # TODO: add device modules to dev.module
            # TODO: extract interface information
            modname = str(snmp_module["sysName"])
            module_name = f"module_{modname[: modname.find(' ')]}"  # module_<sysName>
            if module_name in dev.extra:
                # If module exists, add the info
                dev.extra[module_name].update(snmp_module)
            else:
                # If it doesn't, create it using the info
                dev.extra[module_name] = snmp_module
        except Exception as err:
            cls.log.error(f"Could not pull SNMP metadata: {err}")
            successful = False

        return successful

    @classmethod
    def _get_webmonitor_data(cls, dev: DeviceData, protocol: Literal["http", "https"]) -> bool:
        """
        Query Siprotec webmonitor service for particular files via HTTP or HTTPS.
        """
        cls.log.debug(f"Pulling WebMonitor data from {dev.ip} using {protocol}")

        parsers = {
            "mlfb": cls._parse_mlfb_txt,
            "ver": cls._parse_ver_txt,
        }
        data_was_pulled = False

        with HTTP(
            ip=dev.ip,
            port=dev.options[protocol]["port"],
            timeout=dev.options[protocol]["timeout"],
        ) as http:
            for f_type, parser in parsers.items():
                # Check cache to prevent pulling the same file
                # multiple times (e.g. HTTP then HTTPS)
                if not dev._cache.get(f"{f_type}_data_pulled"):
                    filename = f"{f_type}.txt"
                    response = http.get(filename, protocol)
                    # If the first file fails with this protocol,
                    # subsequent ones likely will as well
                    if response is None:
                        break

                    raw_data = response.text
                    if not raw_data:
                        cls.log.debug(f"Empty {filename} data from {dev.ip}")
                        break

                    if "DOCTYPE" in raw_data or "<html" in raw_data:
                        cls.log.debug(
                            f"Failed to pull WebMonitor data from {dev.ip}: bad {filename} data"
                        )
                        return False

                    dev.write_file(raw_data, f"raw-{f_type}.txt")

                    parsed = parser(raw_data)
                    dev.write_file(parsed, f"parsed-{f_type}.json")

                    if parsed.get("firmware_version"):
                        dev.firmware.version = parsed.pop("firmware_version")
                    if parsed.get("model"):
                        dev.description.model = parsed.pop("model")

                    dev.extra.update(parsed)
                    dev._cache[f"{f_type}_data_pulled"] = True
                    data_was_pulled = True

        cls.log.debug(f"Finished pulling WebMonitor data from {dev.ip} using {protocol}")

        return data_was_pulled

    @classmethod
    def _get_snmp_data(
        cls, ip: str, timeout: float, community: str = "public"
    ) -> tuple[dict, dict]:
        """
        Obtains device metadata via SNMP.

        Args:
            community: SNMP Community string to use

        Returns:
            Info for the module hosting SNMP and the overall system, respectfully
        """
        # TODO: figure out more meaningful OIDs
        # TODO: Fix Siprotec MIBs (They are throwing errors on load)
        cls.log.info(f"Pulling SNMP information from {ip}...")
        module_info = {}
        system_info = {}
        sip_goose_info = {}
        iec_62439_info = {}

        # SNMP OIDs to pull from device
        # Format: "info_returned": "fully-qualified_oid"
        #
        # Since these OIDs are non-mandatory, the requests to make
        # depend on communicationServices results
        #
        # OIDs for information specific to the module running the SNMP server
        # First key in tuple is OID, second is type)
        module_oids = {
            # Module and Module FW version
            # TODO: possible serial number here?
            "sysDescr": ("2.1.1.1.0", str),
            # Address (object identifier) under which the
            # device-specific SNMP variables can be reached
            "sysObjectID": ("2.1.1.2.0", str),
            "sysName": ("2.1.1.5.0", str),
            "mac_address": ("2.1.2.2.1.6.2", str),
            "netmask": ("2.1.4.20.1.3." + ip, str),
            "ifAdminStatus": ("2.1.2.2.1.7.2", int),
            "ifOperStatus": ("2.1.2.2.1.8.2", int),
        }

        # OIDs with snmp statistics
        snmp_oids = {
            "snmpInBadVersions": ("2.1.11.3.0", int),
            "snmpInBadCommunityNames": ("2.1.11.3.0", int),
            "snmpInBadCommunityUses": ("2.1.11.3.0", int),
        }

        # OIDs with system-wide information
        system_oids = {
            "system_uptime": ("2.1.1.3.0", int),
        }

        # First key in tuple is OID, second is instance, third is type
        iec_62439_oids = {
            "manufacturerName": ("manufacturerName", 0, str),
            "interfaceCount": ("interfaceCount", 0, int),
            "versionName": ("versionName", 1, str),
            "nodeName": ("nodeName", 1, str),
            "nodeType": ("nodeType", 1, str),
            # TODO: The following are commented out due to pysnmp errors (ValueConstraint)
            # 'macAddressA':                  ('macAddressA', 1, str), #hexstr
            # 'macAddressB':                  ('macAddressB', 1, str), #hexstr
            "adapterActiveA": ("adapterActiveA", 1, str),
            "adapterActiveB": ("adapterActiveB", 1, str),
            "hsrLREMode": ("hsrLREMode", 1, str),
            "switchingEndNode": ("switchingEndNode", 1, str),
            "evaluateSupervision": ("evaluateSupervision", 1, str),
        }

        # Create SNMP object to use for pulling data
        snmp = SNMP(ip=ip, timeout=timeout, community=community, mib_paths=[SIPROTEC_MIBS_DIR])

        cls.log.debug("Pulling SNMP device modules info...")
        fw_ver = 0
        for name, oid_pair in module_oids.items():
            response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
            if not response:
                continue
            data = oid_pair[1](response[0]["value_string"])

            if data != "":
                if name == "mac_address":
                    # Handle MAC address being represented as
                    # raw bytes and not text characters.
                    mac = binascii.b2a_hex(bytes(data, "utf-8")).decode().upper()
                    module_info["mac_address"] = ":".join(
                        a + b for a, b in zip(mac[::2], mac[1::2], strict=False)
                    )
                elif name == "sysDescr":
                    # TODO: some siprotecs are returning "Fusion 7.0"
                    try:
                        fw_ver = data[-11:].replace(".", "")
                        fw_ver = int(fw_ver[: fw_ver.find("_")])
                        module_info["module_firmware_version"] = data[-11:]
                    except Exception:
                        cls.log.debug(f"Bad SNMP sysDescr: {data}")
                elif name == "ifAdminStatus":
                    module_info[name] = "up" if data == 1 else "down"
                elif name == "ifOperStatus":
                    module_info[name] = "up" if data == 1 else "down"
                else:
                    module_info[name] = data

        # Pull snmp statistics
        snmp_info = {}
        cls.log.debug("Pulling SNMP statistics info...")
        for name, oid_pair in snmp_oids.items():
            response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
            if not response:
                continue
            data = oid_pair[1](response[0]["value_string"])
            snmp_info[name] = data
        module_info["snmp_stats"] = snmp_info

        # Pull information for the overall system
        cls.log.debug("Pulling SNMP overall system info...")
        for name, oid_pair in system_oids.items():
            response = snmp.get(f"1.3.6.1.{oid_pair[0]}")
            if not response:
                continue
            data = oid_pair[1](response[0]["value_string"])
            if data != "":
                system_info[name] = data

        # Pull info from SipEthernet MIB
        cls.log.debug("Pulling SNMP SipEthernet info...")
        sip_eth_info = snmp_walk(
            ip=ip,
            mib_name="SipEthernet",
            mib_src=SIPROTEC_MIBS_DIR,
            timeout=timeout,
            community=community,
        )
        module_info["sip_ethernet"] = sip_eth_info

        # Pull info from SipGoose MIB
        cls.log.debug("Pulling SNMP SipGoose info...")
        try:
            sip_goose_info = snmp_walk(
                ip=ip,
                mib_name="SipGoose",
                mib_src=SIPROTEC_MIBS_DIR,
                timeout=timeout,
                community=community,
            )
        except Exception as err:
            cls.log.exception(f"Failed to pull SNMP SipGoose info: {err}")
        module_info["sip_goose"] = sip_goose_info

        # Pull info from SipOptical MIB
        # TODO: Fix ValueConstraintError with 7SJ61
        # Bandaid fix = compare fw version
        if fw_ver > 41000:
            cls.log.debug("Pulling SNMP SipOptical info...")
            sip_optical_info = snmp_walk(
                ip=ip,
                mib_name="SipOptical",
                mib_src=SIPROTEC_MIBS_DIR,
                timeout=timeout,
                community=community,
            )
            module_info["sip_optical"] = sip_optical_info
        else:
            cls.log.debug("Module firmware version not high enough for SipOptical")

        # If FW > 4.10, pull IEC62439 info
        # TODO: Fix ValueConstraintError when pulling mac addresses
        # Currently targets specific oids because we're getting weird errors
        #   trying to grab mac addresses
        cls.log.debug("Pulling SNMP IEC62439 info...")
        if fw_ver > 41000:
            for name, oid_triplet in iec_62439_oids.items():
                response = snmp.get(("IEC62439", oid_triplet[0], oid_triplet[1]))
                if not response:
                    continue
                data = oid_triplet[2](response[0]["value_string"])
                if data != "":
                    iec_62439_info[name] = data
        else:
            cls.log.debug("Module firmware version not high enough for IEC62439")
        module_info["iec_62439"] = iec_62439_info

        cls.log.info(f"Finished pulling SNMP information from {ip}")
        cls.log.trace2(f"** SNMP system_info **\n{pformat(system_info)}\n")
        cls.log.trace2(f"** SNMP module_info **\n{pformat(module_info)}\n")
        return module_info, system_info

    @staticmethod
    def _parse_mlfb_txt(data: str) -> dict:
        """
        Parse the contents of MLFB.txt.

        Args:
            data: Raw contents to parse

        Returns:
            The components of the file as a dictionary
        """
        parts = [x for x in data.split("\n") if x != ""]

        parsed = {
            "model": parts[0][:6],
            "bf_number": parts[1].strip(),
            "firmware_version": parts[-1][-9:].strip(),
            **decode_mlfb(parts[0][6 : data.index("-")]),
        }

        return parsed

    @classmethod
    def _parse_ver_txt(cls, data: str) -> dict:
        parts = [x.rstrip() for x in data.split("\n") if x != ""]

        if len(parts) != 2:
            cls.log.warning(
                f"Parse may be incorrect, encountered an unexpected VER.txt structure: {parts}"
            )

        parsed = {
            "webmonitor_version": parts[0][1:],
            "webmonitor_build_date": parts[1],
        }

        # TODO: add timezone data and put in elastic-friendly format
        try:
            tstamp = datetime.strptime(parts[1], "%a, %d %b %Y %H:%M:%S %Z")
            parsed["webmonitor_build_timestamp"] = tstamp.isoformat()
        except Exception as err:
            cls.log.debug(f"Failed to parse WebMonitor timestamp '{parts[1]}': {err}")

        return parsed


Siprotec.ip_methods = [
    IPMethod(
        name="Siprotec WebMonitor HTTP",
        description=str(Siprotec._get_webmonitor_data.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Siprotec._get_webmonitor_data, protocol="http"),
        reliability=7,
        protocol="http",
        transport="tcp",
        default_port=80,
    ),
    IPMethod(
        name="Siprotec WebMonitor HTTP",
        description=str(Siprotec._get_webmonitor_data.__doc__).strip(),
        type="unicast_ip",
        identify_function=functools.partial(Siprotec._get_webmonitor_data, protocol="https"),
        reliability=7,
        protocol="https",
        transport="tcp",
        default_port=443,
    ),
    IPMethod(
        name="Siprotec SNMP sysDescr",
        description=str(Siprotec._verify_snmp.__doc__).strip(),
        type="unicast_ip",
        identify_function=Siprotec._verify_snmp,
        reliability=8,
        protocol="snmp",
        transport="udp",
        default_port=161,
    ),
    # TODO: Verify IEC61850 (GOOSE) on 102/TCP
    #   See if there are any tags that would fingerprint it
    # TODO: verify DIGSI on port 50000/UDP
]


__all__ = ["Siprotec"]
