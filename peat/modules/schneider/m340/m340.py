"""
The Schneider Electric Modicon M340 PLC.

The Schneider does NOT have separate "logic" and "config" files, just one
big blob that we call a "project file". Therefore, the semantics of "pull/parse
config/logic" are slightly skewed in this module.

Services

- FTP (TCP 21)
- DHCP client (UDP 68)
- TFTP (UDP 69)
- HTTP (TCP 80)
- HTTPS (TCP 443)
- SNMP (UDP 161)
- Modbus/TCP (TCP 502)
- Teredo (UDP 3544)

Reliable services for scanning: FTP, HTTP/S, SNMP, Modbus/TCP

Authors

- Christopher Goes
- Patrica Schulz
- Mark Woodard
"""

import binascii
import re
import socket
import traceback
from copy import copy
from datetime import datetime
from pathlib import Path, PureWindowsPath
from pprint import pformat
from xml.etree.ElementTree import SubElement

from peat import (
    IO,
    DeviceData,
    DeviceError,
    DeviceModule,
    Interface,
    IPMethod,
    Service,
    config,
    datastore,
    utils,
)
from peat.parsing.tc6 import TC6
from peat.protocols import FTP, SNMP

from . import m340_parse, m340_pull
from .umas_packets import (
    Modbus,
    UMASConnectionResponse,
    UMASResponse,
    connect_packet,
    poll_packet,
    pull_packet,
    send_umas_packet,
    start_pull_packet,
    stop_pull_packet,
)

# TODO
#  Separate the status-type info from the config-type info
#  Separate the parsing portions of pull_config methods
#  Implement more in-depth FTP functionality
#  - Recurse filesystem and list files, sizes, and modification times.
#       This is like what's done for the Sage and SEL relays
#  - Get VxWorks version?
#  - Parse some of the files pulled via FTP
#  - Generate hashes of files pulled via FTP


class M340(DeviceModule):
    """
    Schneider Modicon M340 PLC.
    """

    device_type = "PLC"
    vendor_id = "Schneider"
    vendor_name = "Schneider Electric"
    brand = "Modicon"
    model = "M340"
    filename_patterns = ["*.apx"]
    default_options = {
        "ftp": {"creds": [["loader", "fwdownload"]]},
        "m340": {"use_network_for_config": True, "generate_openplc_project": None},
    }
    annotate_fields = {
        "os.name": "VxWorks",
        "os.vendor.name": "Wind River Systems",
        "os.vendor.id": "WindRiver",
        "os.version": "7",  # TODO: big assumption, get ground truth
    }

    @classmethod
    def _verify_ftp(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a M340 via FTP by logging in with default FTP
        credentials and looking for files with particular names.
        """
        port = dev.options["ftp"]["port"]
        timeout = dev.options["ftp"]["timeout"]

        # If user configures a specific FTP user/pass, just use that
        if dev.options["ftp"].get("user") and dev.options["ftp"].get("pass"):
            creds = [[dev.options["ftp"]["user"], dev.options["ftp"]["pass"]]]
        elif dev.options["ftp"].get("creds"):
            creds = dev.options["ftp"]["creds"]
        else:
            creds = cls.default_options["ftp"]["creds"]

        cls.log.trace(f"Verifying {dev.ip}:{port} via FTP (timeout: {timeout})")

        search_strings = [
            "CPU 340",
            "BMX CPU",
            "BMX P34",
            "BMX NOE 0100",
            "PRA0100",
            "CPS 224",
            "CRP 312",
            "CPU 672",  # Other Modicon models
        ]

        try:
            for user, password in creds:
                with FTP(dev.ip, port, timeout) as ftp:
                    if not ftp.login(user, password):
                        continue
                    # TODO: cache DINF output for use with _pull()
                    #   so the command isn't repeated (reduce device load)
                    resp = str(ftp.cmd("DINF"))

                dev.related.user.add(user)

                if not resp:
                    cls.log.warning(
                        f"Login successful but no output from DINF "
                        f"FTP command on {dev.ip}"
                    )
                    return False

                if any(x.lower() in resp.lower() for x in search_strings):
                    cls.log.debug(f"Verified {dev.ip}:{port} via FTP")
                    return True

                cls.log.debug(
                    f"Failed to find any search strings in output "
                    f"from DINF command on {dev.ip}:{port}\n"
                    f"search strings: {search_strings}\n"
                    f"DINF output: '{resp}'"
                )
        except Exception as ex:
            # Exceptions shouldn't happen if a credential fails,
            # so exit early and don't try any more credentials
            cls.log.debug(f"Failed to verify {dev.ip} via FTP: {ex}")

        return False

    @classmethod
    def _verify_snmp(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a M340 by querying SNMP for OID
        ``1.3.6.1.2.1.1.1.0`` (``sysDescr``) and comparing it
        against specific strings.
        """
        port = dev.options["snmp"]["port"]
        timeout = dev.options["snmp"]["timeout"]

        cls.log.trace(f"Verifying {dev.ip}:{port} via SNMP (timeout: {timeout})")

        to_find = ["schneider", "telemecanique", "m340"]

        for community in dev.options["snmp"]["communities"]:
            snmp = SNMP(dev.ip, port, timeout, community=community)
            if snmp.verify("1.3.6.1.2.1.1.1.0", to_find=to_find):
                return True

        return False

    @classmethod
    def _verify_modbus(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a M340 via Modbus/TCP by sending a :term:`UMAS`
        identification packet to the device.
        """
        port = dev.options["modbus_tcp"]["port"]
        timeout = dev.options["modbus_tcp"]["timeout"]
        log = cls.log.bind(target=f"{dev.ip}:{port}")

        log.trace(f"Verifying {dev.ip}:{port} via Modbus/TCP (timeout: {timeout})")

        # TODO: less brittle check for modbus
        cpu_model = "BMX P34"
        is_m340 = False

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            try:
                sock.connect((dev.ip, port))

                # Method #1: Use Modbus/TCP Function Code 43 to ID the device
                # Source: github.com/digitalbond/Redpoint/blob/master/modicon-info.nse
                log.trace(f"Attempting first Modbus method for {dev.ip}:{port}")
                sock.send(binascii.unhexlify("000000000005002b0e0200"))
                response = Modbus(sock.recv(4096))

                if "Schneider" in str(response.data) and cpu_model in str(
                    response.data
                ):
                    is_m340 = True

                # Method #2: Request CPU and memory using the Unity code
                if not is_m340:
                    log.trace(f"Attempting second Modbus method for {dev.ip}:{port}")
                    sock.send(bytes(Modbus(data=binascii.unhexlify("0002"))))
                    response = UMASResponse(Modbus(sock.recv(4096)).data)
                    if cpu_model in response.payload:
                        is_m340 = True
            except Exception as err:
                log.trace(f"Modbus verification error for {dev.ip}: {err}")
                is_m340 = False

        log.debug(
            f"Modbus/TCP verification of device {dev.ip} "
            f"{'succeeded' if is_m340 else 'failed'}"
        )
        return is_m340

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        # NOTE: _pull will *always* pull the full project, there is no caching!!!
        project_blob = cls.pull_apx_file(dev.ip)
        pulled_config = cls._pull_config(dev, project_blob)

        if not pulled_config:
            return False

        blob_path = dev.write_file(pulled_config, "raw-pulled-config.json")

        # Parse the pulled blob to annotate our DeviceData object
        # TODO: don't provide file=blob_path once we have reliable metadata parsing
        cls._parse_blob(raw_data=project_blob, dev=dev, file=blob_path)
        return True

    @classmethod
    def _pull_config(cls, dev: DeviceData, project_blob: bytes) -> dict:
        """
        Pulls configuration information and device metadata from a M340.

        Args:
            dev: DeviceData instance to use and update with pulled data
            project_blob: Project file blob to parse

        Returns:
            The device configuration information
        """
        cls.log.debug(f"Pulling configuration from {dev.ip}...")
        timeout = dev.options.get("timeout", 1.0)

        # Extract the network configuration info to know what to pull
        # TODO: this is duplicating work also being done in _parse_blob()
        device_info = m340_parse.parse_config_to_dict(project_blob)

        # Extract SNMP community string, if configured
        snmp_community = "public"
        try:
            if "network_configurations" in device_info:
                for value in device_info["network_configurations"].values():
                    # Match the configured network address
                    # with the address we're pulling from
                    if (
                        value["ip_config"].get("IPNetwork") == dev.ip
                        and value.get("snmp_config", {})["get"] != "public"
                    ):
                        snmp_community = str(value["snmp_config"]["get"])
        except KeyError:
            cls.log.debug("Failed to parse out SNMP info from network_configurations")
        # TODO: update dev with snmp info

        # Pull configuration information from the network
        if dev.options["m340"]["use_network_for_config"]:
            # TODO: update dev in pull_network_config (pass the dev object?)
            net_config = m340_pull.pull_network_config(
                ip=dev.ip, timeout=timeout, snmp_community=snmp_community
            )
            device_info.update(net_config)
            # TODO: full parsing of modules and other information from data
            #   pulled via network protocols (SNMP, FTP, Modbus)
            dev.extra.update(net_config)

        if device_info.get("firmware_version"):
            dev.firmware.version = device_info.pop("firmware_version")

        cls.log.debug(f"Finished pulling configuration from {dev.ip}")
        return device_info

    @classmethod
    def pull_apx_file(cls, ip: str) -> bytes:
        """
        Pull the project file blob from a device.

        This is equivalent to the "Station.apx" file
        extracted from a .STA archive saved using Unity.

        Args:
            ip: IPv4 address of device to pull from

        Returns:
            The project file pulled from the device
        """
        dev = datastore.get(ip)
        timeout = dev.options["modbus_tcp"]["timeout"]
        port = dev.options["modbus_tcp"]["port"]
        log = cls.log.bind(target=f"{ip}:{port}")
        packet_tracker = []

        log.debug(f"Downloading project file from {ip}:{port} (timeout: {timeout})")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            try:
                sock.connect((ip, port))
            except OSError:
                raise DeviceError(
                    f"failed to download project file: could not connect to {ip}:{port}"
                ) from None

            # Establish a UMAS connection with the device
            try:
                # NOTE(cegoes): M340 will return a 0xFE on any subsequent concurrent
                #   connections to any modules on the same device rack, even if
                #   they're different modules.
                # NOTE(cegoes): connection ID 0 for everything seems to be best
                #   Multiple connection IDs at the same time will make it unhappy,
                #   but if we use the same ID, no problem ;)
                send_umas_packet(sock, poll_packet(0), UMASResponse, packet_tracker)
                connect_data = send_umas_packet(
                    sock, connect_packet(), UMASConnectionResponse, packet_tracker
                )
                cid = connect_data.newConnectionCode
                send_umas_packet(sock, poll_packet(cid), UMASResponse, packet_tracker)
                start_pull_data = send_umas_packet(
                    sock, start_pull_packet(cid), UMASResponse, packet_tracker
                )
                total_len = start_pull_data.dataLen
            except OSError as err:
                raise DeviceError(f"failed to pull project file from {ip}") from err

            recv_len = 0
            count = 1
            finished = False
            debug_data = []
            download_blob = bytearray(b"")

            # Pull the data
            while not finished:
                data = send_umas_packet(
                    sock, pull_packet(cid, count), UMASResponse, packet_tracker
                )

                if data.dataLen > 0:
                    if recv_len == total_len:
                        log.warning(
                            f"Abnormal response while pulling "
                            f"the project file: recv_len of "
                            f"{recv_len} == total_len"
                        )

                    if data.num == 0x01:
                        # If we've gotten this back, we're done
                        log.debug("Received EOF from device, finishing queries")
                        finished = True

                    recv_len += data.dataLen
                    download_blob.extend(bytearray(data.load))

                    if config.DEBUG:
                        debug_data.append(data.load)
                else:
                    finished = True

                count += 1

            count -= 1  # Don't include the final "close stream" packet in the count
            send_umas_packet(
                sock, stop_pull_packet(cid, count), UMASResponse, packet_tracker
            )

        # Dump of the raw UMAS bytes from the blob for debugging purposes
        if debug_data:
            debug_output = []

            for i, item in enumerate(debug_data):
                debug_output.append(f"\n\n\n******************\nPacket {i}\n\n")
                debug_output.append(binascii.hexlify(bytes(item)).decode())

            dev.write_file("".join(debug_output), "blob-packets.txt")

        # Dump of all packets sent
        if packet_tracker:
            # TODO: PCAP file generation
            # NOTE: we don't have the TCP header, so not sure if this will work
            # from scapy.utils import PcapWriter
            # pcap_path = (dev.get_out_dir() / "umas-packets.pcap").as_posix()
            #
            # log.debug(f"Writing packets to PCAP: {pcap_path}")
            # with PcapWriter(pcap_path) as writer:
            #     for pkt_dict in packet_tracker:
            #         writer.write_packet(pkt_dict[""])
            #         # writer.write(pkt_dict["packet_object"])
            # TODO: filter out the packet objects from dumped data
            dev.write_file(packet_tracker, "umas-metadata.json")

        byte_blob = bytes(download_blob)  # Convert "bytearray" to "bytes"
        dev.firmware.file.extension = "apx"
        dev.firmware.original = byte_blob

        cls.update_dev(dev)  # Note: this will write the .apx file to disk

        log.debug(f"Finished downloading project file from {ip}:{port}")
        return byte_blob

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData:
        file_data = file.read_bytes()

        dev = cls._parse_blob(file_data, dev=dev, file=file)
        dev.firmware.file.local_path = file
        dev.populate_fields()

        return dev

    @classmethod
    def _parse_blob(
        cls,
        raw_data: bytes,
        dev: DeviceData | None = None,
        file: Path | None = None,
    ) -> DeviceData:
        parsed_config = m340_parse.parse_config_to_dict(raw_data)
        metadata = parsed_config.get("project_file_metadata", {})  # type: dict

        # Determine a valid identifier for the device from the config
        if dev is None and parsed_config.get("module_names"):
            for value in parsed_config.values():
                if isinstance(value, dict) and value.get("ipv4_address"):
                    dev = datastore.get(value["ipv4_address"], "ip")
                    break
            if dev is None and metadata.get("project_name"):
                dev = datastore.get(metadata["project_name"], "id")

        # Last-resort fallback
        if dev is None and file is not None:
            cls.log.warning(
                "Unable to find a suitable Device ID in the "
                "project blob, using filename as device ID"
            )
            dev = datastore.get(file.stem, "id")

        # Store network information out of the configuration
        # TODO: use network_configurations
        for mod in parsed_config.values():
            if isinstance(mod, dict) and mod.get("ipv4_address"):
                iface = Interface(
                    ip=mod["ipv4_address"],
                    type="ethernet",
                    gateway=mod.get("configured_ipv4_gateway", ""),
                    subnet_mask=mod.get("configured_ipv4_netmask", ""),
                )
                dev.store("interface", iface, lookup="ip")

                def _proto_enabled(data):
                    """If status is "no configuration", service isn't enabled."""
                    if not data.get("service_status"):
                        return False
                    if data["service_status"].lower() == "no configuration":
                        return False
                    return True

                if mod.get("port_502"):
                    svc = Service(
                        protocol="modbus_tcp",
                        port=502,
                        transport="tcp",
                        enabled=_proto_enabled(mod["port_502"]),
                        extra=copy.deepcopy(mod["port_502"]),
                    )

                    if svc.port:
                        dev.related.ports.add(svc.port)
                    if svc.protocol:
                        dev.related.protocols.add(svc.protocol)

                    dev.store("service", svc)

                if mod.get("smtp_server"):
                    svc = Service(
                        protocol="smtp",
                        port=25,  # TODO: don't hardcode port for smtp
                        transport="tcp",
                        enabled=_proto_enabled(mod["smtp_server"]),
                        extra=copy.deepcopy(mod["smtp_server"]),
                    )

                    if svc.port:
                        dev.related.ports.add(svc.port)
                    if svc.protocol:
                        dev.related.protocols.add(svc.protocol)

                    dev.store("service", svc, lookup="protocol")

                if mod.get("web_server"):
                    svc = Service(
                        protocol="http",
                        port=80,  # TODO: don't hardcode port for web
                        transport="tcp",
                        enabled=_proto_enabled(mod["web_server"]),
                        extra=copy.deepcopy(mod["web_server"]),
                    )

                    if svc.port:
                        dev.related.ports.add(svc.port)
                    if svc.protocol:
                        dev.related.protocols.add(svc.protocol)

                    dev.store("service", svc, lookup="protocol")

        dev.populate_fields(network_only=True)

        # TODO: data model file handling needs improvement
        #   the file metadata extracted via parsing or from the device
        #   is being replaced by the metadata of the auto-created file

        # Store Logic metadata
        if metadata:
            if metadata.get("user_name"):
                dev.logic.author = metadata["user_name"].strip()

            if dev.logic.author:
                dev.related.user.add(dev.logic.author)

            if metadata.get("file_path"):
                extracted_path = PureWindowsPath(metadata["file_path"].strip())
                dev.logic.file.path = extracted_path
                dev.logic.file.owner = dev.logic.author

            if metadata.get("project_description"):
                # Cleanup the description and remove large chunks of spaces
                cleaned = metadata["project_description"].replace("\r\n", "\n")
                cleaned = re.sub(" {2,}", " ", cleaned).strip()
                dev.logic.description = cleaned

        if file is not None:
            dev.logic.file.local_path = file

        if dev.ip:
            dev.logic.file.device = dev.ip

        cls.update_dev(dev)

        # Parse out the Structured Text logic and save the TC6 tree as well
        logic_blocks = m340_parse.extract_logic_blocks(raw_data)
        if logic_blocks:
            # Create the TC6 object with the skeleton of the TC6 XML
            dev.logic.name = metadata.get("project_name", "").strip()
            if not dev.logic.name:
                dev.logic.name = dev.logic.file.name
            if not dev.logic.name:  # Fallback if neither value is known
                dev.logic.name = "PEAT-generated project"

            # TODO: is there a project modification timestamp embedded in APX?
            # TODO: this code could use some cleanup
            mtime = ""
            if dev.logic.file.mtime:
                mtime = dev.logic.file.mtime.strftime("%Y-%m-%dT%H:%M:%S")
            elif dev.firmware.file.mtime:
                mtime = dev.firmware.file.mtime.strftime("%Y-%m-%dT%H:%M:%S")
            elif file is not None:
                m_ts = datetime.fromtimestamp(file.stat().st_mtime)
                mtime = m_ts.strftime("%Y-%m-%dT%H:%M:%S")

            ctime = ""
            if dev.logic.file.created:
                ctime = dev.logic.file.created.strftime("%Y-%m-%dT%H:%M:%S")
            elif dev.firmware.file.created:
                ctime = dev.firmware.file.created.strftime("%Y-%m-%dT%H:%M:%S")
            elif file is not None:
                c_ts = datetime.fromtimestamp(file.stat().st_ctime)
                ctime = c_ts.strftime("%Y-%m-%dT%H:%M:%S")

            prod_ver = ""
            if metadata.get("unity_version"):
                prod_ver = f"Unity {metadata['unity_version'].strip()}"
            elif dev.firmware.version:
                prod_ver = f"Device firmware version {dev.firmware.version}"

            dev._cache["tc6"] = TC6(
                project_name=dev.logic.name,
                product_name=dev.description.product,
                product_version=prod_ver,
                modification_time=mtime,
                creation_time=ctime,
                company_name=dev.description.vendor.name,
                author=dev.logic.author,
                content_description=dev.logic.description,
            )
            try:
                # Build the TC6 XML tree and add to the TC6 object
                m340_parse.add_logic_to_tc6(
                    logic_blocks,
                    dev._cache["tc6"],
                    dev.options["sceptre_plc_compatible_st_logic"],
                )
            except Exception:
                cls.log.error(
                    "Exception while generating the TC6 XML. Perhaps "
                    "the variable region is wrong?"
                )
                cls.log.debug(f"** Traceback **\n{traceback.format_exc()}")
            else:
                # Don't store tc6 if there are no variables or logic
                if dev._cache["tc6"].logic_is_empty():
                    cls.log.warning("TC6 logic is empty, not saving...")
                else:
                    xml_string = dev._cache["tc6"].generate_xml_string(
                        dev.options["sceptre_plc_compatible_st_logic"]
                    )

                    if not xml_string:
                        cls.log.error(
                            "Failed to generate TC6 XML string for non-empty logic"
                        )
                    else:
                        dev.logic.formats["tc6"] = xml_string
                        st_logic = dev._cache["tc6"].generate_st(
                            xml_string, dev.options["sceptre_plc_compatible_st_logic"]
                        )
                        if st_logic:
                            dev.logic.original = st_logic
                            dev.logic.parsed = st_logic
                            dev.logic.formats["structured_text"] = st_logic
                        else:
                            cls.log.warning("No structured text was generated")
        else:
            cls.log.warning("Failed to process logic: no blocks were extracted")

        dev.populate_fields()

        # Modules
        io_points = {}
        for module_name in parsed_config["module_names"]:
            m_data = parsed_config[module_name]

            if m_data["slot"] < 0:
                cls.log.debug(
                    f"Skipping module {module_name} with negative "
                    f"slot number '{m_data['slot']}'"
                )
                continue

            module = DeviceData()
            module.slot = str(m_data["slot"])

            if m_data.get("model_name"):
                module.description.product = m_data["model_name"]
                if m_data["model_name"].startswith("BMX"):
                    module.description.brand = "BMX"
                    module.description.model = (
                        m_data["model_name"].split("BMX")[1].strip()
                    )
                module.description.vendor = dev.description.vendor

            if m_data.get("ipv4_address"):
                module.ip = m_data["ipv4_address"]

            if m_data.get("family"):
                # "Analog", "Discrete", "Communication", "Supply", "Micro Basic"
                module.type = m_data["family"]
                if module.type == "Micro Basic":
                    module.type = "CPU"
                if module.type in ["Analog", "Discrete"]:
                    module.type += " I/O"

            if m_data.get("io_groups"):
                for io_group in m_data["io_groups"]:
                    try:
                        i_key = io_group["key"]
                        if i_key in io_points:
                            io_points[i_key]["slots"].append(module.slot)
                        else:
                            io_points[i_key] = {"data": io_group}
                            io_points[i_key]["slots"] = [module.slot]
                    except Exception as ex:
                        cls.log.warning(
                            f"Skipping IO group due to exception: "
                            f"{ex}\n** Raw IO group **\n{io_group}"
                        )

            module.populate_fields()
            dev.store("module", module, lookup="slot")

        for point_key, point in io_points.items():
            direction = ""
            p_attr = point["data"].get("attribute")

            if p_attr:
                if p_attr.upper() == "IN":
                    direction = "input"
                elif p_attr.upper() == "OUT":
                    direction = "output"
                else:
                    cls.log.warning(f"Unknown io_groups attribute type: {p_attr}")

            # TODO: do something with additional fields, maybe a "extra" addition to IO model?
            #   "channel", "repeat", "size"
            io_point = IO(
                address=point["data"].get("address", ""),
                direction=direction,
                id=point_key,
                type=point["data"].get("type", ""),
                slot=point["slots"],
            )

            dev.store("io", io_point, lookup="id")

        # Add the raw parsed config to dev.extra
        dev.extra.update(parsed_config)

        cls.update_dev(dev)

        # Save raw results to files
        if config.DEVICE_DIR:
            if parsed_config:
                dev.write_file(parsed_config, "parsed-config.json")

            if dev.logic.formats.get("structured_text"):
                dev.write_file(dev.logic.formats["structured_text"], "logic.st")

            if dev.logic.formats.get("tc6"):
                dev.write_file(dev.logic.formats["tc6"], "tc6.xml")

            if dev.options["m340"]["generate_openplc_project"]:
                cls.generate_openplc_project(dev)

            if config.DEBUG:
                if logic_blocks:
                    text_dump = cls.parse_logic_to_text(logic_blocks)
                    if text_dump:
                        dev.write_file(text_dump, "text-dump.txt")
                else:
                    cls.log.warning("Failed logic text dump: no blocks were extracted")
                debug_dump = cls.dump_project(raw_data)
                if debug_dump:
                    dev.write_file(debug_dump, "debug-dump.txt")

        return dev

    @classmethod
    def parse_logic_to_text(cls, logic_blocks: dict) -> str:
        """
        Parse device project file blob into a printable string for debugging.
        """
        cls.log.info("Dumping process logic blocks as text...")

        text = ""
        for name, block in logic_blocks.items():
            name = str(name)
            if name in ["ST", "FBD", "LD", "program"] and block:
                text += f"----- {name} blocks -----\n\n"
                for i, b in enumerate(block):
                    text += f"{name} block {i}\n\n{b}\n\n"
            elif name == "vars":
                text += f"\n----- Variables ----- {name[:-5]}\n{pformat(block)}\n\n\n"

        cls.log.debug("Finished dumping process logic blocks as text")
        return text.strip()

    @classmethod
    def dump_project(cls, logic_blob: bytes) -> str:
        """
        Raw dump of blocks for debugging purposes.
        """
        cls.log.info("Dumping process logic chunks...")

        project_blocks = m340_parse.chunkify(logic_blob)

        text = ""
        for name, block in sorted(project_blocks.items()):
            try:
                text += f"Block {block['number']}\n"
                text += f"Tag: {block['tag']}\n"
                text += f"Offset: {name}\n"
                text += f"Header:\n{block['head']}\n"
                if block["tag"] == "2":
                    text += f"Data:\n{block['data']}\n"
            except KeyError as ex:
                cls.log.warning(
                    f"Failed to properly construct a debug dump of "
                    f"logic blob for block {name}, dumping raw block "
                    f"instead. Exception: {ex}"
                )
                text += f"*** BAD BLOCK ***\nOffset: {name}\n** Raw block **\n{block}"
            text += "\n\n\n"

        cls.log.debug("Finished dumping process logic chunks")
        return text.strip()

    @classmethod
    def generate_openplc_project(cls, dev: DeviceData) -> Path | None:
        """
        Generate a directory that can be opened with the OpenPLC editor.

        <project-name>_openplc_project/
            beremiz.xml
            plc.xml

        - https://github.com/thiagoralves/OpenPLC_Editor
        - https://www.openplcproject.com/plcopen-editor/
        """
        if not dev.options["m340"]["generate_openplc_project"]:
            cls.log.warning(
                "generate_openplc_project() called with no value "
                "set for 'generate_openplc_project'"
            )
            return None

        if not dev.logic.formats.get("tc6"):
            cls.log.error("Skipping OpenPLC generation: no TC6 logic")
            return None

        tc6 = dev._cache["tc6"]  # type: TC6
        body = tc6.main_pou.find("body")

        if tc6.element_empty(body):
            # TODO: make a copy of the tree before modifying?
            cls.log.warning(
                "No logic present in TC6, adding a empty 'ST' "
                "element to body so OpenPLC is happy."
            )

            logic_element = SubElement(body, "ST")
            content_element = SubElement(logic_element, "xhtml:p")
            content_element.text = "(* No logic was extracted by PEAT *)"

            tc6_xml = tc6.generate_xml_string(
                dev.options["sceptre_plc_compatible_st_logic"]
            )
        else:
            tc6_xml = dev.logic.formats["tc6"]

        if dev.options["m340"]["generate_openplc_project"] == "dev_out_dir":
            proj_name = dev.logic.name if dev.logic.name else dev.get_id()
            proj_path = dev.get_sub_dir(
                f"openplc_project_{proj_name.replace(' ', '-')}"
            )
        else:
            proj_path = Path(dev.options["m340"]["generate_openplc_project"]).resolve()

        beremiz_xml = """<?xml version="1.0" encoding="utf-8"?>
<BeremizRoot xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <TargetType/>
</BeremizRoot>
"""
        utils.write_file(
            beremiz_xml, proj_path / "beremiz.xml", overwrite_existing=True
        )
        utils.write_file(tc6_xml, proj_path / "plc.xml", overwrite_existing=True)

        cls.log.info(f"Generated OpenPLC project files in {proj_path.name}")
        return proj_path


M340.ip_methods = [
    IPMethod(
        name="M340 FTP",
        description=str(M340._verify_ftp.__doc__).strip(),
        type="unicast_ip",
        identify_function=M340._verify_ftp,
        reliability=6,
        protocol="ftp",
        transport="tcp",
        default_port=21,
    ),
    IPMethod(
        name="M340 SNMP sysDescr",
        description=str(M340._verify_snmp.__doc__).strip(),
        type="unicast_ip",
        identify_function=M340._verify_snmp,
        reliability=7,
        protocol="snmp",
        transport="udp",
        default_port=161,
    ),
    IPMethod(
        name="M340 Modbus/TCP",
        description=str(M340._verify_modbus.__doc__).strip(),
        type="unicast_ip",
        identify_function=M340._verify_modbus,
        reliability=8,
        protocol="modbus_tcp",
        transport="tcp",
        default_port=502,
    ),
]


__all__ = ["M340"]
