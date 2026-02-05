"""
PEAT module for the Allen-Bradley ControlLogix device.

Listening services (EN2TR)

- FTP (TCP 21) (if enabled in config)
- HTTP (TCP 80)
- SNMP (UDP 161)
- ENIP (UDP 2222)
- CIP (UDP 44818 and TCP 44818)

Listening services (EWEB)

- FTP (TCP 21) (if enabled in config)
- HTTP (TCP 80)
- SNMP (UDP 161)
- ENIP (UDP 2222)
- CIP (UDP 44818 and TCP 44818)

Authors

- Christopher Goes
- Mark Woodard
"""

import json
from datetime import timedelta
from pathlib import Path

from peat import (
    DeviceData,
    DeviceModule,
    Interface,
    IPMethod,
    consts,
    datastore,
    exit_handler,
    utils,
)
from peat.protocols import FTP, SNMP, fingerprint
from peat.protocols.enip import ENIP

from . import ab_push
from .ab_parse import parse_logic
from .ab_scan import DevDescType, broadcast_scan, fingerprint_device
from .clx_cip import ClxCIP
from .clx_http import ClxHTTP


class ControlLogix(DeviceModule):
    """
    Allen-Bradley ControlLogix devices.

    Supported communication modules: EN2T/D, EWEB, EN2TR, EN2TR/C, L8 CPU
    """

    device_type = "PLC"
    vendor_id = "Rockwell"  # Allen-Bradley is a brand name, not a vendor
    vendor_name = "Rockwell Automation/Allen-Bradley"
    brand = "ControlLogix"
    model = "1756"
    default_options = {
        "rockwell": {"pull_methods": ["cip", "ftp", "http", "snmp"]},
        "web": {"user": "Administrator", "pass": ""},
        "ftp": {"user": "Administrator", "pass": ""},
    }
    annotate_fields = {
        "os.name": "VxWorks",
        "os.vendor.name": "Wind River Systems",
        "os.vendor.id": "WindRiver",
    }
    module_aliases = ["clx", "allen-bradley"]

    @classmethod
    def _verify_ftp(cls, dev: DeviceData) -> bool:
        """
        Verify via FTP for devices with EWEB communication modules.
        """
        port = dev.options["ftp"]["port"]
        timeout = dev.options["ftp"]["timeout"]

        cls.log.trace(f"Verifying {dev.ip}:{port} via FTP (timeout: {timeout})")

        try:
            with FTP(dev.ip, port, timeout) as ftp:
                welcome_string = ftp.ftp.getwelcome()
                ftp.process_vxworks_ftp_welcome(welcome_string, dev)

                username = dev.options["ftp"]["user"]
                password = dev.options["ftp"]["pass"]

                if not ftp.login(username, password):
                    cls.log.debug(
                        f"Failed to verify {dev.ip} via FTP: "
                        f"login failed (username: {username})"
                    )
                    return False

                dev.related.user.add(username)

                file_dir = ftp.dir()
                if not file_dir or not file_dir[0]:
                    cls.log.debug(
                        f"Failed to verify {dev.ip} via FTP: no files "
                        f"on device or file listing failed"
                    )
                    return False

                dev.extra["ftp_files"] = file_dir[0]
                dev.extra["ftp_file_metadata"] = file_dir[1]

                if (
                    "vxworks" not in welcome_string.lower()
                    and not any(x.lower().endswith(".eds") for x in file_dir[0])
                    and "ReadMe.txt" not in file_dir[0]
                ):
                    cls.log.debug(
                        f"Failed to verify {dev.ip} via FTP: vxworks not "
                        f"in welcome and no *.eds or ReadMe.txt file found"
                    )
                    return False
        except Exception as ex:
            cls.log.debug(f"Failed to verify {dev.ip} via FTP: {ex}")
            return False

        cls.log.debug(f"Verified {dev.ip}:{port} via FTP")
        return True

    @classmethod
    def _verify_snmp(cls, dev: DeviceData) -> bool:
        """
        Verify via SNMP for devices with EN2T/EN2TR communication modules by
        querying for SNMP :term:`OID` ``1.3.6.1.2.1.1.1.0`` (``sysDescr``) and
        checking the value.
        """
        # TODO: get _verify_snmp() working
        #   Need to fix scan_api's checking of UDP ports (this affects M340 as well)
        #   Add config option to force UDP scans?
        #   Also force UDP checks if intensive scanning is enabled?

        # TODO: cache result of SNMP queries during scan/verify
        # for use with other modules (M340, CLX, Siprotec, etc).

        # TODO: do this check for port verification function,
        # then skip verify if it's already been done.

        if dev._cache.get("snmp_verified"):
            return True

        port = dev.options["snmp"]["port"]
        timeout = dev.options["snmp"]["timeout"]

        cls.log.trace(f"Verifying {dev.ip}:{port} via SNMP (timeout: {timeout})")

        search_strings = ["Rockwell Automation", "1756-", "-EWEB", "-EN2T"]

        for community in dev.options["snmp"]["communities"]:
            snmp = SNMP(dev.ip, port, timeout, community=community)
            if snmp.verify("1.3.6.1.2.1.1.1.0", to_find=search_strings):
                dev._cache["snmp_community"] = community
                dev._cache["snmp_verified"] = True
                dev._cache["snmp_object"] = snmp
                return True

        return False

    @classmethod
    def _annotate_clx_values(cls, data: DeviceData, value: dict) -> None:
        if not value:
            cls.log.warning(f"No CIP values for {data.ip}, CIP may have timed out")
            return

        data.description.brand = value.get("brand", "Unknown brand")
        data.description.product = value["product_name"]
        data.description.vendor.name = value.get("vendor", cls.vendor_name)
        data.description.vendor.id = cls.vendor_id
        data.type = value["product_type"]

        # Non-ControlLogix devices (e.g. PanelView HMI) won't have the 'cpu_serial' field
        data.serial_number = str(
            value.get("serial_number", value.get("cpu_serial", "Unknown serial number"))
        )

        if value.get("cpu_serial"):
            data.extra["cpu_serial"] = value["cpu_serial"]

        # Version and Revision, e.g. version=30,revision=13, as in "1756-L74_30.013.dmk"
        data.firmware.version = str(value["firmware_version"])
        data.firmware.revision = str(value["firmware_revision"])

        data.extra["product_code"] = value["product_code"]
        data.extra["state"] = value["state"]
        data.extra["status"] = value["status"]

    @classmethod
    def update_dev(cls, dev: DeviceData) -> None:
        super().update_dev(dev)

        for module in dev.module:
            if module.type == "PLC" and not module.description.description:
                module.description.description = "CPU module"
            if module.type == "PLC" and "unknown" in module.description.brand.lower():
                module.description.brand = dev.description.brand
            if not dev.slot and module.ip == dev.ip:
                dev.slot = module.slot

    @classmethod
    def _process_fingerprint(cls, dev: DeviceData, result: dict) -> None:
        # Save raw pulls to disk
        dev.write_file(result, "raw-cip-device-descriptions.json")

        # Note: see misc/rockwell/ for examples of this data as pulled from a device
        # Copy module data if the device has multiple modules
        # and assume module 0 is the CPU module.
        if result.get("modules"):
            cls._annotate_clx_values(dev, result["modules"][0])
            for slot_id, mod_values in result["modules"].items():
                mod = DeviceData()
                cls._annotate_clx_values(mod, mod_values)
                mod.slot = str(slot_id)
                dev.store("module", mod, lookup="slot")
                if not dev.slot and mod.ip == dev.ip:
                    dev.slot = mod.slot
        else:
            cls._annotate_clx_values(dev, result)

        dev._cache["cip_fingerprinted"] = True

    @classmethod
    def _verify_cip_unicast(cls, dev: DeviceData) -> bool:
        """Verify via a unicast :term:`CIP` ListIdentity packet."""
        port = dev.options["cip"]["port"]
        timeout = dev.options["cip"]["timeout"]

        cls.log.trace(f"Verifying CIP for {dev.ip}:{port} (timeout: {timeout})")

        payload = bytes(ENIP(commandCode="ListIdentity"))
        try:
            result = fingerprint(
                ip=dev.ip,
                port=port,
                timeout=timeout,
                payload=payload,
                finger_func=fingerprint_device,
            )
            if result:
                cls._process_fingerprint(dev, result)
                return True
        except ConnectionResetError as ex:
            cls.log.debug(f"Failed to identify {dev.ip} via CIP: {ex}")

        return False

    @classmethod
    def _verify_cip_broadcast(cls, target: str) -> list[DevDescType]:
        """
        Send a :term:`CIP` broadcast packet to broadcast IP and
        wait for responses from devices.
        """
        port = datastore.device_options["cip"]["port"]
        timeout = datastore.device_options["cip"]["timeout"]
        results = broadcast_scan(ip=target, port=port, timeout=timeout)
        for result in results:
            dev = datastore.get(result["ip"])
            cls._process_fingerprint(dev, result)
        return results

    @classmethod
    def _verify_http(cls, dev: DeviceData) -> bool:
        """Verify via HTTP for devices with EN2T/EN2TR communication modules."""
        port = dev.options["http"]["port"]
        timeout = dev.options["http"]["timeout"]
        cls.log.trace(f"Verifying HTTP for {dev.ip}:{port} (timeout: {timeout})")

        with ClxHTTP(dev.ip, port, timeout) as http:
            # index.html is probably cached from other module verifications
            # This reduces the number of requests for a scan, except for the
            # case where only the ControlLogix module is enabled for a scan.
            index_page = http.get("index.html")
            if not index_page or not index_page.text:
                return False
            if "Rockwell Automation" not in index_page.text:
                return False
            home_info = http.get_home()
            if not home_info:
                cls.log.warning(
                    f"Failed to get home.asp from {dev.ip} via HTTP. "
                    f"The device is a Rockwell, but not a communication "
                    f"module PEAT knows how to talk to via HTTP."
                )
                return False
            http.process_home(dev, home_info)
            dev._cache["clx_http_home_processed"] = True
        return True

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        # Sanity checks in case users messed up config (since there isn't config validation yet)
        if not dev.options["rockwell"]["pull_methods"]:
            cls.log.error(
                f"The 'rockwell.pull_methods' option is empty or null for {dev.ip}"
            )
            return False

        for method in dev.options["rockwell"]["pull_methods"]:
            if method not in cls.default_options["rockwell"]["pull_methods"]:
                cls.log.error(
                    f"Invalid 'rockwell.pull_methods' method '{method}' for {dev.ip}, it must "
                    f"be one of {cls.default_options['rockwell']['pull_methods']}"
                )
                return False

        pull_successful = False
        logic_not_successful = False

        # NOTE: do CIP first, it seems to fail sometimes if done after a HTTP pull
        #
        # The CIP fingerprint collects quite a bit of information. While it is
        # usually performed during a scan, it may not have been done if the scan
        # step was skipped, e.g. if calling pull() directly.
        if "cip" not in dev.options["rockwell"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'cip' for pull from {dev.ip}: "
                f"'cip' not listed in 'rockwell.pull_methods' option"
            )
        elif dev.service_status({"protocol": "cip"}) == "closed":
            cls.log.warning(f"Failed to pull CIP on {dev.ip}: CIP port is closed")
        elif not dev._cache.get("cip_fingerprinted") and not cls._verify_cip_unicast(
            dev
        ):
            cls.log.warning(
                f"Failed to pull CIP on {dev.ip}: CIP unicast "
                f"list-identity verification method failed"
            )
        else:
            raw_logic = cls.pull_logic(dev)

            if not raw_logic:
                logic_not_successful = True
            else:
                pull_successful = True

            cls.parse_logic(dev, raw_logic)
            cls.update_dev(dev)

        # Check if the SNMP port is closed. If it's not, then run the
        # normal verification check, and if it's successful, use SNMP
        if "snmp" not in dev.options["rockwell"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'snmp' for pull from {dev.ip}: "
                f"'snmp' not listed in 'rockwell.pull_methods' option"
            )
        elif dev.service_status({"protocol": "snmp"}) == "closed":
            cls.log.warning(f"Failed to pull SNMP on {dev.ip}: SNMP port is closed")
        elif (
            not dev._is_verified or not dev._cache.get("snmp_verified")
        ) and not cls._verify_snmp(dev):
            cls.log.warning(
                f"Failed to pull SNMP on {dev.ip}: SNMP verification method failed"
            )
        else:
            dev._is_verified = True
            cls.update_dev(dev)
            if cls.pull_snmp(dev):
                pull_successful = True

        # Check if the FTP port is closed. If it's not, then run the
        # normal verification check, and if it's successful, use FTP
        if "ftp" not in dev.options["rockwell"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'ftp' for pull from {dev.ip}: "
                f"'ftp' not listed in 'rockwell.pull_methods' option"
            )
        elif dev.service_status({"protocol": "ftp"}) == "closed":
            cls.log.warning(f"Failed to pull FTP on {dev.ip}: FTP port is closed")
        elif not dev._is_verified and not cls._verify_ftp(dev):
            cls.log.warning(
                f"Failed to pull FTP on {dev.ip}: FTP verification method failed"
            )
        else:
            dev._is_verified = True
            if cls.pull_ftp(dev):
                pull_successful = True

        # Check if the HTTP port is closed. If it's not, then run the
        # normal verification check, and if it's successful, use HTTP
        if "http" not in dev.options["rockwell"]["pull_methods"]:
            cls.log.warning(
                f"Skipping method 'http' for pull from {dev.ip}: "
                f"'http' not listed in 'rockwell.pull_methods' option"
            )
        elif dev.service_status({"protocol": "http"}) == "closed":
            cls.log.warning(f"Failed to pull HTTP on {dev.ip}: HTTP port is closed")
        elif not dev._is_verified and not cls._verify_http(dev):
            cls.log.warning(
                f"Failed to pull HTTP on {dev.ip}: HTTP verification method failed"
            )
        else:
            dev._is_verified = True
            if cls.pull_http(dev):
                pull_successful = True

        # Even if the HTTP pull was successful, failure to pull the logic
        # should result in a False result for the overall pull, since the
        # CIP port is open and was successfully fingerprinted.
        if logic_not_successful:
            pull_successful = False

        return pull_successful

    @classmethod
    def pull_ftp(cls, dev: DeviceData) -> bool:
        """
        Pull files from a EWEB communication module via FTP.

        Files pulled

        - ``*.eds``
        - ``ReadMe.txt``
        - Anything else on the device

        Returns:
            If the pull was successful
        """
        cls.log.info(f"Pulling FTP files from {dev.ip}")

        try:
            with FTP(
                ip=dev.ip,
                port=dev.options["ftp"]["port"],
                timeout=dev.options["ftp"]["timeout"],
            ) as ftp:
                welcome_string = ftp.ftp.getwelcome()
                if welcome_string and not dev.extra.get("ftp_welcome"):
                    ftp.process_vxworks_ftp_welcome(welcome_string, dev)

                if not ftp.login(
                    dev.options["ftp"]["user"], dev.options["ftp"]["pass"]
                ):
                    cls.log.error(f"Failed to pull from {dev.ip} via FTP: login failed")
                    return False

                # If file listing was queried during verify, then use the cached listing
                # Otherwise, query it like normal using "dir"
                if not dev.extra.get("ftp_files"):
                    file_dir = ftp.dir()
                    if not file_dir:
                        cls.log.error(
                            f"Failed to pull from {dev.ip} via FTP: "
                            f"no results from dir() command"
                        )
                        return False
                    dev.extra["ftp_files"] = file_dir[0]
                    dev.extra["ftp_metadata"] = file_dir[1]
                    dev.related.user.add(dev.options["ftp"]["user"])

                files = dev.extra["ftp_files"]  # type: list[str]

                cls.log.info(f"Downloading {len(files)} files via FTP from {dev.ip}")
                for filename in files:
                    cls.log.debug(f"Downloading '{filename}' via FTP from {dev.ip}")
                    ftp.download_binary(filename)

                # TODO: parse downloaded files

                cls.log.info(
                    f"Finished downloading {len(files)} files via FTP from {dev.ip}"
                )
                return True
        except Exception as ex:
            cls.log.error(f"Failed to pull from {dev.ip} via FTP: {ex}")
            return False

    @classmethod
    def pull_snmp(cls, dev: DeviceData) -> bool:
        """
        Pull data via SNMP from EWEB/EN2T communication modules.

        Returns:
            If the pull was successful
        """
        cls.log.info(f"Pulling SNMP from {dev.ip}")

        # TODO: move pulling of data for standardized MIBs to snmp.py?
        # TODO: move to separate function?
        pull_successful = True
        snmp = dev._cache.get("snmp_object")

        if not snmp:
            snmp = SNMP(
                ip=dev.ip,
                port=dev.options["snmp"]["port"],
                timeout=dev.options["snmp"]["timeout"],
                community=dev._cache.get(
                    "snmp_community", dev.options["snmp"]["community"]
                ),
            )
            dev._cache["snmp_object"] = snmp

        # System information (SNMPv2-MIB)
        sys_uptime = snmp.get(("SNMPv2-MIB", "sysUpTime", 0))
        if sys_uptime:
            # Timeticks: (2378054664) 275 days, 5:42:26.64
            # hundredths of a second (centiseconds)
            dev.uptime = timedelta(
                milliseconds=int(sys_uptime[0]["value_encoded"]) * 10
            )

        sys_contact = snmp.get(("SNMPv2-MIB", "sysContact", 0))
        if sys_contact:
            contact = str(sys_contact[0]["value_string"])
            if (
                "Wind River System" not in contact
            ):  # ignore a useless contact I saw on L7
                dev.related.user.add(contact)

        sys_name = snmp.get(("SNMPv2-MIB", "sysName", 0))
        if sys_name and not dev.name:
            dev.name = str(sys_name[0]["value_string"])

        sys_location = snmp.get(("SNMPv2-MIB", "sysLocation", 0))
        if sys_location:
            dev.geo.name = str(sys_location[0]["value_string"])

        # Interface information (IF-MIB)
        interface_count = snmp.get(("IF-MIB", "ifNumber", 0))
        if interface_count:
            interface_count = int(interface_count[0]["value_encoded"])
            # NOTE: interface indices start at 1 (not 0)
            for index in range(1, interface_count + 1):
                iface = Interface(
                    # Save interface index for correlating with IP routes
                    # No need to request index via SNMP if we have it from iteration
                    # Use Interface.id field to store this, since it's device-dependent
                    id=str(index)
                )

                if_name = snmp.get(("IF-MIB", "ifDescr", index))
                if if_name:
                    iface.name = str(if_name[0]["value_string"])

                if_type = snmp.get(("IF-MIB", "ifType", index))
                if if_type:
                    # NOTE: interface type gets resolved in SNMP.get()
                    iface.type = str(if_type[0]["value_string"])

                if_mtu = snmp.get(("IF-MIB", "ifMtu", index))
                if if_mtu:
                    iface.mtu = int(if_mtu[0]["value_encoded"])

                # current bandwidth in bits per second
                if_speed = snmp.get(("IF-MIB", "ifSpeed", index))
                if if_speed:
                    # Convert bits to megabits
                    iface.speed = int(int(if_speed[0]["value_encoded"]) / 1000000)

                phys_address = snmp.get(("IF-MIB", "ifPhysAddress", index))
                if phys_address:
                    iface.mac = phys_address[0]["value_string"]

                # Note about interface status:
                #   enabled => ifAdminStatus
                #   connected => ifOperStatus
                # up(1), down(2), testing(3)
                admin_status = snmp.get(("IF-MIB", "ifAdminStatus", index))
                if admin_status:
                    iface.enabled = bool(admin_status[0]["value_string"] == "up")

                oper_status = snmp.get(("IF-MIB", "ifOperStatus", index))
                if oper_status:
                    iface.connected = bool(oper_status[0]["value_string"] == "up")

                # calculate based on sysUpTime
                # "The value of sysUpTime at the time the interface entered
                # its current operational state.  If the current state was
                # entered prior to the last re-initialization of the local
                # network management subsystem, then this object contains a
                # zero value."
                # NOTE: this is also Timeticks,
                if_uptime = snmp.get(("IF-MIB", "ifLastChange", index))[0][
                    "value_encoded"
                ]  # int
                iface.uptime = timedelta(milliseconds=int(if_uptime) * 10)

                # INTEGER: false(2), true(1)
                # https://oidref.com/1.3.6.1.2.1.31.1.1.1.16
                # NOTE: this is only present on EN2T/EN2TR
                if_promisc = snmp.get(("IF-MIB", "ifPromiscuousMode", index))
                if if_promisc:
                    # prettyPrint in SNMP.get() converts integer to strings "false" or "true"
                    # We then convert those to a boolean using PEAT's utility function
                    iface.promiscuous_mode = consts.str_to_bool(
                        if_promisc[0]["value_string"]
                    )

                # why is ifConnectorPresent always false for all modules?
                # This object has the value 'true(1)' if the interface
                # sublayer has a physical connector and the value
                # 'false(2)' otherwise.
                # generally empty, but worth keeping i guess
                if_alias = snmp.get(("IF-MIB", "ifAlias", index))
                if if_alias:
                    iface.extra["alias"] = if_alias[0]["value_string"]  # string
                dev.store("interface", iface, lookup=["name", "mac", "id"])
        else:
            cls.log.error(f"Failed to get interface count for {dev.ip} via SNMP!")
            pull_successful = False

        # TODO: Routes (RFC1213-MIB)
        # TODO: associate routes with interface indices via ifIndex
        #   Also, use this to annotate subnet mask and gateway info
        # TODO: Services (RFC1213-MIB)

        if pull_successful:
            cls.log.info(f"Finished SNMP from {dev.ip}")
        else:
            cls.log.error(f"Failed to pull SNMP from {dev.ip}")

        return pull_successful

    @classmethod
    def pull_http(cls, dev: DeviceData) -> bool:
        """
        Pull device metadata, memory, syslog, and other data from a
        EN2T communication module via HTTP.

        .. note::
           Raw data pulled via each HTTP method is saved to a JSON file
           in the device results directory with a label of ``raw-<method>``,
           where ``<method>`` is the method name, e.g. ``raw-home``.

        Returns:
            If the pull was successful
        """
        cls.log.info(f"Pulling HTTP from {dev.ip}")

        with ClxHTTP(
            ip=dev.ip,
            port=dev.options["http"]["port"],
            timeout=dev.options["http"]["timeout"],
        ) as http:
            result = http.get_all(dev)

        if result:
            cls.log.info(f"Finished pulling HTTP from {dev.ip}")
        else:
            cls.log.warning(
                f"HTTP pull failed for {dev.ip} (some HTTP methods may "
                f"have failed, check logs for details)"
            )

        return result

    @classmethod
    def pull_logic(cls, dev: DeviceData) -> dict[str, dict[str, dict]]:
        """
        Pull raw process logic from the device via :term:`CIP`.

        By default, any slots (modules) that aren't "Adapter"
        or "I/O" type are queried for logic.

        Args:
            dev: device data to use for storage and caching

        Returns:
            Logic value dict
        """
        port = dev.options["cip"]["port"]
        timeout = dev.options["cip"]["timeout"]

        cls.log.info(
            f"Beginning logic pull from {dev.ip}:{port} via CIP "
            f"(timeout: {timeout} seconds)"
        )

        slots = dev.options.get("slots", [])  # type: list[int]
        if not slots:
            # Filter slots to only the ones that may have logic (CPUs)
            slots = [
                int(x.slot)
                for x in dev.module
                if not any(n in x.type for n in ["Adapter", "I/O"])
                # if x.type == "PLC"  # CPU
            ]

        logic = {}  # type: dict[str, dict[str, dict]]
        if "drivers" not in dev._cache:
            dev._cache["drivers"] = {}  # dict[int, ClxCIP]

        cls.log.info(
            f"Querying {dev.ip}:{port} via CIP for configuration, "
            f"program data, and memory map...."
        )
        for slot in slots:
            cls.log.info(f"Pulling logic from slot {slot} on {dev.ip}:{port}")

            if slot not in dev._cache["drivers"]:
                driver = ClxCIP(dev.ip, port, timeout, slot)
                dev._cache["drivers"][slot] = driver

                if not driver.open():
                    cls.log.warning(
                        f"ClxCIP failed to connect via CIP to slot "
                        f"{slot} on {dev.ip}:{port}"
                    )
                    continue

                dev._cache["drivers"][slot] = driver
                # Ensure remaining connections are closed properly when PEAT exits
                exit_handler.register(dev._cache["drivers"][slot].close, "CONNECTION")
            else:
                driver = dev._cache["drivers"][slot]

            try:
                slot_dict = driver.get_all_data()
                cls.log.info(f"Finished pulling logic from slot {slot}")
            except Exception as err:
                if "socket timeout" in str(err):
                    cls.log.warning(
                        f"Failed to pull logic via CIP from slot {slot} on "
                        f"{dev.ip}:{port}: timed out after {timeout} seconds"
                    )
                else:
                    cls.log.warning(
                        f"Failed to pull logic via CIP from slot {slot} on "
                        f"{dev.ip}:{port}: {err.__class__.__name__}"
                    )
                slot_dict = {}
            logic[str(slot)] = slot_dict

        dev.write_file(logic, "raw-logic.json")

        dev.logic.original = json.dumps(consts.convert(logic))
        dev.logic.formats["raw-values"] = logic
        dev.populate_fields()

        cls.log.info(f"Finished logic pull from {dev.ip}:{port} via CIP")
        return logic

    @classmethod
    def _push(
        cls,
        dev: DeviceData,
        to_push: str | bytes | Path,
        push_type: consts.PushType,
    ) -> bool:
        """
        Upload a new firmware image (``.lmk`` or ``.dmk`` file)
        to the device via :term:`CIP`.
        """
        if push_type != "firmware":
            cls.log.critical(f"Unsupported push type {push_type}, expected 'firmware'")
            return False

        if isinstance(to_push, Path):
            cls.log.info(f"Push: Loading firmware from file {to_push.name}")
            file = utils.check_file(to_push, ext=[".lmk", ".dmk"])

            if not file or not isinstance(file, Path):
                cls.log.error(f"Failed to push firmware to {dev.ip}: bad file")
                return False

            firmware = file.read_bytes()
        elif isinstance(to_push, bytes):
            firmware = to_push
        else:
            cls.log.error(f"Empty or unknown firmware blob: {to_push}")
            return False

        return ab_push.push_firmware(firmware, dev.ip, dev.options["cip"]["port"])

    @classmethod
    def parse_logic(cls, dev: DeviceData, logic_values: dict[str, dict]) -> str:
        """
        Parse logic pulled from the device via :term:`CIP`.
        """
        cls.log.info(f"Parsing logic from {dev.ip}...")
        parsed_slots = {}

        for slot, data in logic_values.items():
            # Attempt to retrieve the values for the slot
            if not data:
                cls.log.info(f"No logic was pulled from slot {slot} on {dev.ip}")
                continue

            # Try to get the a driver, if available
            driver = dev._cache.get("drivers", {}).get(int(slot))

            # Parse the data
            parsed_data = parse_logic(logic_dict=data, driver=driver)
            if not parsed_data:
                cls.log.warning(
                    f"Failed to parse logic pulled from slot {slot} on {dev.ip}"
                )
            parsed_slots[slot] = parsed_data

        dev.logic.file.local_path = dev.write_file(parsed_slots, "parsed-logic.json")

        # Example: "** Slot 0 **\nMemory Layout:\n[0xf0ffc4a4]  map0xd: 0x1\n"
        formatted_logic = "\n".join(
            f"** Slot {slot} **\n{line}\n" for slot, line in parsed_slots.items()
        )

        dev.write_file(formatted_logic, "formatted-logic.txt")
        dev.logic.parsed = formatted_logic

        cls.log.info(f"Finished parsing logic from {dev.ip}")
        return formatted_logic


# Notes
#   https://www.motioncontroltips.com/what-is-the-common-industrial-protocol-cip/
#   UDP is used for control data ("Implicit messages")
#   TCP is used for “as-needed” data ("Explicit messages")
ControlLogix.ip_methods = [
    IPMethod(
        name="ControlLogix FTP",
        description=str(ControlLogix._verify_ftp.__doc__).strip(),
        type="unicast_ip",
        identify_function=ControlLogix._verify_ftp,
        reliability=8,
        protocol="ftp",
        transport="tcp",
        default_port=21,
    ),
    IPMethod(
        name="ControlLogix HTTP page scraping",
        description=str(ControlLogix._verify_http.__doc__).strip(),
        type="unicast_ip",
        identify_function=ControlLogix._verify_http,
        reliability=8,
        protocol="http",
        transport="tcp",
        default_port=80,
    ),
    IPMethod(
        name="ControlLogix SNMP sysDescr",
        description=str(ControlLogix._verify_snmp.__doc__).strip(),
        type="unicast_ip",
        identify_function=ControlLogix._verify_snmp,
        reliability=6,
        protocol="snmp",
        transport="udp",
        default_port=161,
    ),
    IPMethod(
        name="ControlLogix CIP ListIdentity unicast",
        description=str(ControlLogix._verify_cip_unicast.__doc__).strip(),
        type="unicast_ip",
        identify_function=ControlLogix._verify_cip_unicast,
        reliability=9,
        protocol="cip",
        transport="udp",
        default_port=44818,
    ),
    IPMethod(
        name="ControlLogix CIP ListIdentity broadcast",
        description=str(ControlLogix._verify_cip_broadcast.__doc__).strip(),
        type="broadcast_ip",
        identify_function=ControlLogix._verify_cip_broadcast,
        reliability=9,
        protocol="cip",
        transport="udp",
        default_port=44818,
    ),
]


__all__ = ["ControlLogix"]
