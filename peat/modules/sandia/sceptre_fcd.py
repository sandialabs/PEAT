"""
PEAT module for Sandia SCEPTRE virtual field devices.

Sandia SCEPTRE virtual field control devices (vFCDs), including the
SCEPTRE Virtual RTU and SCEPTRE Virtual Relay.

SCEPTRE virtual relays and RTUs are running a FTP server, which is used to
pull the device configuration XML file as well as the firmware binary image.
The XML file is then parsed and the extracted information saved.


Development, testing, and demonstration of this module is possible without a
running SCEPTRE instance by setting up a local FTP server using the Python Twisted
framework. To do so, run the following command in a terminal:

.. code-block:: bash

   pip3 install Twisted
   sudo -H $(which twistd) -n ftp --auth=anonymous -r examples/devices/sceptre/

Then, in another terminal, run peat:

.. code-block:: bash

   peat pull -d sceptre -i 127.0.0.1 --assume-online -v -c ./examples/peat-config-sceptre-testing.yaml

That config file sets the following options:

- ftp.port: 2121
- ftp.user: anonymous
- ftp.pass: anonymous
- sceptre.ftp_testing: true


Listening services

- FTP (TCP 21)

Data collected

- Full device configuration file
- Device firmware binary image
- Device type (e.g. "Relay" or "RTU")
- Device name (e.g. "relay-louie")
- Cycle time
- Logic

Authors

- Christopher Abate
- Christopher Goes
"""  # noqa: E501

from pathlib import Path, PurePosixPath
from random import randint
from xml.etree.ElementTree import Element, fromstring

from peat import (
    IO,
    DeviceData,
    DeviceModule,
    Interface,
    IPMethod,
    Register,
    Service,
    Tag,
    config,
    datastore,
)
from peat.protocols import FTP


class SCEPTRE(DeviceModule):
    """
    SCEPTRE Virtual RTUs and Virtual Relays.
    """

    device_type = "RTU"
    vendor_id = "Sandia"
    vendor_name = "Sandia National Laboratories"
    model = "SCEPTRE"
    brand = "SCEPTRE"
    filename_patterns = ["*.xml", "config.xml"]
    default_options = {
        "ftp": {
            "user": "sceptre",
            "pass": "sceptre",
        },
        "sceptre": {
            "ftp_testing": False,
            "bennu_filename": "bennu-field-deviced.firmware",
        },
    }

    annotate_fields = {
        "os.name": "Ubuntu",
        "os.vendor.name": "Canonical",
        "os.vendor.id": "Canonical",
    }

    @classmethod
    def _verify_ftp(cls, dev: DeviceData) -> bool:
        """
        Verify it's a SCEPTRE Bennu device by logging in with FTP and
        checking if any file named "bennu" is on the server.
        """
        port = dev.options["ftp"]["port"]
        timeout = dev.options["ftp"]["timeout"]
        ftp_testing = dev.options["sceptre"]["ftp_testing"]

        # Workaround hack for edge cases where fields get overwritten by other modules
        username = dev.options["ftp"].get("user")
        password = dev.options["ftp"].get("pass")
        if not username:
            username = cls.default_options["ftp"]["user"]
        if not password:
            password = cls.default_options["ftp"]["pass"]

        failed = ""
        file_list = []

        try:
            with FTP(dev.ip, port, timeout) as ftp:
                ftp.ftp.getwelcome()

                if not ftp.login(username, password):
                    failed = "login failed"
                elif ftp_testing:
                    dir_result = ftp.dir()
                    if not dir_result:
                        failed = "(FTP TESTING) file listing failed ('dir' command)"
                    elif "bennu" not in str(dir_result):
                        failed = "(FTP TESTING) bennu firmware not in file listing"
                    else:
                        file_list = dir_result[0]
                elif not ftp_testing and "bennu" not in str(ftp.nlst()):
                    nlst_result = ftp.nlst()
                    if not nlst_result:
                        failed = "file listing failed ('nlst' command)"
                    elif "bennu" not in str(nlst_result):
                        failed = "bennu firmware not in file listing"
                    else:
                        file_list = nlst_result
        except Exception as ex:
            failed = str(ex)

        if failed:
            cls.log.debug(f"Failed to verify FTP for {dev.ip}: {failed}")
            return False

        if file_list:
            dev._cache["file_list"] = file_list
            dev.related.files.update(file_list)
            for file in file_list:
                if file.startswith("bennu-field-deviced") or ".firmware" in file:
                    if not dev._runtime_options.get("sceptre"):
                        dev._runtime_options["sceptre"] = {}
                    dev._runtime_options["sceptre"]["bennu_filename"] = file
                    break

        if not dev.options["ftp"].get("user"):
            dev._options["ftp"]["user"] = username
        if not dev.options["ftp"].get("pass"):
            dev._options["ftp"]["pass"] = password

        dev.related.user.add(username)

        svc = Service(protocol="ftp", port=port, transport="tcp", status="verified")
        dev.store("service", svc, interface_lookup={"ip": dev.ip})

        return True

    @classmethod
    def _download_ftp(
        cls, dev: DeviceData, check_for: str, extension: str
    ) -> tuple[bytes | None, Path | None]:
        try:
            with FTP(
                ip=dev.ip,
                port=dev.options["ftp"]["port"],
                timeout=dev.options["ftp"]["timeout"],
            ) as ftp:
                username = dev.options["ftp"]["user"]
                password = dev.options["ftp"]["pass"]

                if not ftp.login(username, password):
                    return None, None

                dev.related.user.add(username)

                filename = ftp.find_file(check_for, extension, "/")
                if not filename:
                    return None, None

                data = ftp.download_binary(filename, save_to_file=False)
                downloaded_path = None
                if filename.startswith("/"):
                    filename = filename[1:]

                if config.DEVICE_DIR:
                    downloaded_path = dev.write_file(
                        data=data,
                        filename=filename,
                        out_dir=dev.get_sub_dir("ftp_files"),
                    )
                return data, downloaded_path
        except Exception as ex:
            cls.log.debug(f"Failed to get FTP file {check_for} from {dev.ip}: {ex}")

        return None, None

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        result = True
        if not cls.pull_firmware(dev):
            result = False

        if not cls.pull_config(dev):
            result = False

        return result

    @classmethod
    def pull_config(cls, dev: DeviceData) -> bool:
        """
        Retrieves the device configuration via FTP.

        The SCEPTRE vFCDs use a single XML file for their configuration,
        called 'config.xml' by default.
        """
        data, file_path = cls._download_ftp(dev, "config", ".xml")

        if data is None:
            cls.log.error(f"Failed to pull config from {dev.ip}")
            return False

        try:
            # If file output is disabled there won't be a file on disk
            if file_path:
                cls.parse_config(file_path, dev)
                dev.related.files.add(file_path.name)
            else:
                cls.parse_config(data, dev)
                dev.related.files.add("config.xml")
        except Exception as err:
            cls.log.exception(f"Failed to parse SCEPTRE config: {err}")
            return False

        return True

    @classmethod
    def pull_firmware(cls, dev: DeviceData) -> bytes:
        filename = dev.options["sceptre"]["bennu_filename"]
        data, file_path = cls._download_ftp(dev, filename, "")

        if data is None:
            cls.log.error(f"Failed to pull firmware from {dev.ip}")
            return b""

        dev.firmware.original = data

        # If file output is disabled there won't be a file on disk
        if file_path:
            dev.firmware.file.local_path = file_path
        else:
            dev.firmware.file.device = dev.get_id()
            dev.firmware.file.name = filename

        dev.firmware.file.directory = "/"
        dev.firmware.file.path = PurePosixPath("/", filename)
        dev.related.files.add(filename)

        dev.populate_fields()
        return data

    @classmethod
    def _upload_ftp(
        cls, dev: DeviceData, filename: str, content: str | bytes
    ) -> bool:
        try:
            with FTP(
                ip=dev.ip,
                port=dev.options["ftp"]["port"],
                timeout=dev.options["ftp"]["timeout"],
            ) as ftp:
                username = dev.options["ftp"]["user"]
                password = dev.options["ftp"]["pass"]

                if not ftp.login(username, password):
                    return False

                dev.related.user.add(username)

                if isinstance(content, str):
                    ftp.upload_text(filename, content)
                elif isinstance(content, bytes):
                    ftp.upload_binary(filename, content)
                else:
                    cls.log.error(
                        f"Cannot upload data with type '{type(content).__name__}'"
                    )
        except Exception as err:
            cls.log.debug(f"Failed to upload file {filename} to {dev.ip}: {err}")
            return False

        return True

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData:
        return cls.parse_config(file=file, dev=dev)

    @classmethod
    def parse_config(
        cls, file: Path | bytes | str, dev: DeviceData | None = None
    ) -> DeviceData:
        """
        Parse a SCEPTRE field device XML configuration file.

        .. note::
           Examples of configs can be found on the
           `bennu GitHub <https://github.com/sandialabs/sceptre-bennu/tree/main/data/configs>`__,
           in addition to the ones in the PEAT repo.
        """
        # Read the config data from the file
        if isinstance(file, Path):
            raw_config = file.read_text(encoding="utf-8")
        elif isinstance(file, bytes):
            raw_config = file.decode()
        else:
            raw_config = file

        # Get the root section and basic information
        root = fromstring(raw_config).find("field-device")
        name = _ele(root, "name")
        if not dev:
            if not name:
                name = f"UNKNOWN_{randint(0, 9999)}"
            dev = datastore.get(name, "name")

        if name and not dev.name:
            dev.name = name
        # Minor hack to determine device type by the name of the device,
        # which is a common practice in SCEPTRE topologies
        if dev.name:
            if "rtu" in dev.name.lower():
                dev.type = "RTU"
            elif "relay" in dev.name.lower():
                dev.type = "Relay"
            elif "fep" in dev.name.lower():
                dev.type = "FEP"

        cycle_time = _ele(root, "cycle-time")
        if cycle_time:
            dev.extra["cycle_time"] = int(cycle_time)

        # Parse I/O tags
        tags_element = root.find("tags")
        if tags_element is not None:
            for tag_element in list(tags_element):
                tag = Tag()
                for key in ["name", "io", "type"]:
                    if _ele(tag_element, key):
                        setattr(tag, key, _ele(tag_element, key))
                dev.store("tag", tag)
        else:
            cls.log.warning(f"No tags found in config for {dev.get_id()}")

        # Parse network communication modules (DNP3, Modbus/TCP, etc.)
        comms = root.find("comms")
        if comms is not None and len(comms):
            comm_mods = list(comms)
            # If client and server, then device is probably a FEP
            if (
                not dev.type
                and any("client" in e.tag for e in comm_mods)
                and any("server" in e.tag for e in comm_mods)
            ):
                dev.type = "FEP"
            for mod in comm_mods:
                extract_interface_info(mod, dev)  # Comm interface data
                # Parse protocol tags
                section_names = {
                    "analog-input",
                    "binary-input",
                    "binary-output",
                    "coil",
                    "discrete-input",
                    "input-register",
                }
                for child in list(mod):
                    if child.tag in section_names:
                        reg = Register(
                            protocol="_".join(mod.tag.split("-")[:-1]),
                            read_write="read_write",
                            measurement_type=child.tag.split("-")[0],
                            address=_ele(child, "address"),
                            tag=_ele(child, "tag"),
                        )
                        dev.store("registers", reg)
            # Sort registers for determinism
            # TODO: improve sort order, current version is wacky
            dev.registers.sort()
        else:
            cls.log.error(f"No 'comms' element found in config for {dev.get_id()}")

        # I/O modules (connected to the SCEPTRE simulation)
        # "input-module" and "output-module" are legacy from older version of bennu
        for module_name in ["input", "output", "input-module", "output-module"]:
            module_element = root.find(module_name)
            if module_element is None:
                continue

            for child in list(module_element):
                if child.tag in ["analog", "binary"]:
                    name = ""
                    desc = ""

                    # Legacy format
                    d_ele = child.find("device")
                    if d_ele is not None:
                        # Update existing tag descriptions with SCEPTRE I/O info
                        # Example: "Tank1 - level_setpoint - simulink"
                        d_info = [_ele(d_ele, k) for k in ["name", "field", "provider"]]
                        name = _ele(d_ele, "name")
                        desc = " - ".join(d for d in d_info if d)
                    # Current format
                    elif _ele(child, "name"):
                        name = _ele(child, "name")

                    io_id = _ele(child, "id")
                    if not io_id:
                        cls.log.warning(f"No 'id' for element: {child}")
                        continue

                    if desc:
                        # Add description to existing tag
                        tag = Tag(description=desc)
                        dev.store("tag", tag, lookup={"io": io_id})

                    io_obj = IO(
                        id=io_id,
                        name=name,
                        type=child.tag,
                        direction=module_name.split("-")[0],
                        description=desc,
                    )

                    dev.store("io", io_obj, lookup="id")

        # Sort tags for determinism
        if dev.tag:
            # TODO: improve sort order, current version is wacky
            dev.tag.sort()

        # Extract the device logic, if it exists
        logic = _ele(root, "logic")

        # Legacy name "logic-module", with subsection of "logic"
        if not logic:
            logic_module = root.find("logic-module")
            if logic_module is not None:
                logic = _ele(logic_module, "logic")

        if logic:
            if not dev.type:
                cls.log.debug("Logic is present, device is probably a Relay")
                dev.type = "Relay"
            parsed_logic = "\n".join(x.strip() for x in logic.splitlines() if x)
            dev.logic.original = logic
            dev.logic.parsed = parsed_logic
            if isinstance(file, Path):
                dev.logic.file.local_path = file
            else:
                dev.logic.file.device = dev.get_id()
                dev.logic.file.name = "config.xml"
            dev.populate_fields()
        elif not dev.type:
            cls.log.debug("No logic present, device is probably a RTU")
            dev.type = "RTU"

        cls.update_dev(dev)

        return dev


def extract_interface_info(com: Element, dev: DeviceData) -> None:
    # TODO: merge interface info for devices with client and server

    # modbus, modbus-tcp, bacnet, dnp3, sunspec-tcp
    protocol = "_".join(com.tag.split("-")[:-1])
    conn_type = com.tag.split("-")[-1]  # client, server

    iface = Interface(application=protocol, enabled=True)
    svc = Service(protocol=protocol, role=conn_type, enabled=True)

    if _ele(com, "address") is not None:
        svc.protocol_id = _ele(com, "address")
    if _ele(com, "event-logging"):
        svc.extra["event_logging"] = _ele(com, "event-logging")
    if _ele(com, "instance"):
        svc.extra["instance"] = _ele(com, "instance")
    if _ele(com, "scan-rate"):
        svc.extra["scan-rate"] = _ele(com, "scan-rate")

    # Get related IPs from command interface endpoint
    if _ele(com, "command-interface"):
        cmd_if = _parse_endpoint(_ele(com, "command-interface"))
        if cmd_if.get("ip"):
            dev.related.ip.add(cmd_if["ip"])
        if cmd_if.get("multicast_ip"):
            dev.related.ip.add(cmd_if["multicast_ip"])

    # TODO: build links to other devices via <x-connection> child tags
    #  <modbus-client>
    #    <modbus-connection>
    #      <endpoint>tcp://127.0.0.1:5502</endpoint>
    for child in list(com):
        if "connection" in child.tag:
            # for now, just add the IPs to related.ip
            # want to expand on this in the future with richer linkages
            if _ele(child, "endpoint"):
                conn_ep = _parse_endpoint(_ele(child, "endpoint"))
                if conn_ep.get("ip"):
                    dev.related.ip.add(conn_ep["ip"])
                if conn_ep.get("multicast_ip"):
                    dev.related.ip.add(conn_ep["multicast_ip"])

    endpoint = _ele(com, "endpoint")
    ip = _ele(com, "ip")
    if endpoint:
        parsed_endpoint = _parse_endpoint(endpoint)
        if parsed_endpoint.get("ip"):
            iface.ip = parsed_endpoint["ip"]
            dev.related.ip.add(parsed_endpoint["ip"])
        if parsed_endpoint.get("multicast_ip"):
            svc.extra["multicast_ip"] = parsed_endpoint["multicast_ip"]
            dev.related.ip.add(svc.extra["multicast_ip"])
        if parsed_endpoint.get("transport"):
            svc.transport = parsed_endpoint["transport"]
        if parsed_endpoint.get("port"):
            svc.port = parsed_endpoint["port"]
        if parsed_endpoint.get("serial_port"):
            iface.serial_port = parsed_endpoint["serial_port"]
        if parsed_endpoint.get("type"):
            iface.type = parsed_endpoint["type"]
        if not iface.serial_port:
            iface.type = "ethernet"
    # Legacy format
    elif ip:
        # <port>20000</port>
        # <ip>192.0.2.3</ip>
        iface.ip = ip
        iface.type = "ethernet"
        svc.transport = "tcp" if protocol != "bacnet" else "udp"
        port = _ele(com, "port")
        if port:
            svc.port = int(port)

    if svc.port:
        dev.related.ports.add(svc.port)
    if svc.protocol:
        dev.related.protocols.add(svc.protocol)

    dev.store("interface", iface, lookup=["ip", "serial_port", "application"])
    dev.store("service", svc, interface_lookup={"application": protocol})


def _parse_endpoint(endpoint: str) -> dict:
    if not endpoint:
        return {}
    data = {}  # type: dict[str, Union[str, int]]
    if ";" in endpoint:
        # <endpoint>udp://172.16.1.2;239.0.0.1:40000</endpoint>
        transport, ip, port = endpoint.split(":")
        data["ip"] = ip.split(";")[0].replace("//", "")
        data["transport"] = transport
        data["port"] = int(port)
        data["multicast_ip"] = ip.split(";")[1]
    elif "://" in endpoint:
        # <endpoint>tcp://172.16.1.2:5555</endpoint>
        # <endpoint>tcp://192.0.2.2:20000</endpoint>
        # <endpoint>udp://127.0.0.1:47808</endpoint>
        # <endpoint>tcp://127.0.0.1:20000</endpoint>
        transport, ip, port = endpoint.split(":")
        data["ip"] = ip.replace("//", "")
        data["transport"] = transport
        data["port"] = int(port)
    elif "/" in endpoint:  # Serial
        # <endpoint>/tmp/ttyS0</endpoint>
        # <endpoint>/dev/ttySerial1</endpoint>
        data["serial_port"] = endpoint
        data["type"] = "serial"
    elif ":" in endpoint:  # Not sure if I've seen, just a fallback
        data["ip"], port = endpoint.split(":")
        data["port"] = int(port)
    else:  # Legacy, I think
        # <endpoint>172.16.254.254</endpoint>
        data["ip"] = endpoint
    return data


def _ele(root: Element, to_find: str) -> str | None:
    found = root.find(to_find)
    if found is not None:
        return found.text.strip()
    return None


SCEPTRE.ip_methods = [
    IPMethod(
        name="SCEPTRE FTP",
        description=str(SCEPTRE._verify_ftp.__doc__).strip(),
        type="unicast_ip",
        identify_function=SCEPTRE._verify_ftp,
        reliability=9,
        protocol="ftp",
        transport="tcp",
        default_port=21,
    )
]


__all__ = ["SCEPTRE"]
