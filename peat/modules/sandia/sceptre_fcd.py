"""
PEAT module for Sandia SCEPTRE bennu virtual field devices.

`bennu <https://github.com/sandialabs/sceptre-bennu>`__ is the field device
emulator used by Sandia's SCEPTRE OT modeling and simulation platform
(deployed with `phenix <https://github.com/sandialabs/sceptre-phenix>`__).
A bennu field device (``bennu-field-deviced``) emulates an RTU, relay, PLC,
or front-end processor (FEP) that talks ICS protocols (DNP3, Modbus,
BACnet, IEC 60870-5-104) to the rest of the network and exchanges I/O with
the SCEPTRE power or process simulation (the "provider").

.. note::
   This module only handles bennu field devices and their XML configuration
   files. It does not support other parts of SCEPTRE, such as phenix,
   minimega, the simulation providers, pybennu, or the "SCEPTRE on a Platter"
   hardware.

On a phenix-deployed bennu VM, the SCEPTRE phenix app copies the device's
``config.xml`` and the ``bennu-field-deviced`` binary into the home directory
of the ``sceptre`` user, which ``vsftpd`` serves over FTP (login
``sceptre``/``sceptre``). ``bennu-watcherd`` installs any valid firmware
uploaded as ``bennu-field-deviced.firmware``. PEAT pulls the config and the
firmware binary over FTP and parses the config, and can push firmware.

Development and testing of this module can be done with the pre-built bennu
VM image from `sceptre-phenix-images
<https://github.com/sandialabs/sceptre-phenix-images>`__.
``scripts/run-bennu-vm.sh`` boots the image with QEMU,
loads a config into it, and forwards FTP to localhost port 2121. Then, in
another terminal, run peat:

.. code-block:: bash

   peat pull -d sceptre -i 127.0.0.1 --assume-online -v -c ./examples/peat-config-sceptre-testing.yaml

That config file sets the following options:

- ftp.port: 2121
- ftp.user: sceptre
- ftp.pass: sceptre


Firmware push

.. code-block:: bash

   peat push -d sceptre -i 192.0.2.10 -t firmware -- ./bennu-field-deviced

The firmware is uploaded as ``bennu-field-deviced.firmware``, and
``bennu-watcherd`` installs it and restarts the field device only if its
SHA-256 matches the original binary or one of the two "shell" variants
listed in ``/etc/sceptre/watcher.ini``. The watcher silently ignores any other
file, so PEAT refuses to push it. Config pushes aren't supported, since the
field device only reads ``/etc/sceptre/config.xml`` at startup, and that file
isn't reachable over FTP.

Listening services

- FTP (TCP 21)

Data collected

- Full device configuration file (``config.xml``)
- Device firmware binary image (``bennu-field-deviced``)
- Device type (e.g. "Relay", "RTU", or "FEP")
- Device name (e.g. "relay-louie")
- Cycle time
- Logic
- Tags (external and internal)
- Protocol data points (registers), with point options, linked to I/O
- Protocol servers and clients, including client connections to remote servers
- Network and serial interfaces, including the simulation I/O interface
- Simulation I/O points and the provider endpoints

Authors

- Christopher Abate
- Christopher Goes
"""  # noqa: E501

import hashlib
import ipaddress
from pathlib import Path, PurePosixPath
from random import randint
from typing import Final
from xml.etree.ElementTree import Element, fromstring

from peat import (
    IO,
    DeviceData,
    DeviceModule,
    Event,
    Interface,
    IPMethod,
    Register,
    Service,
    Tag,
    config,
    consts,
    datastore,
)
from peat.data.data_utils import match_all
from peat.file_signature import FileSignature
from peat.protocols import FTP

# Protocol data point elements: (measurement_type, read_write)
POINT_TYPES: Final[dict[str, tuple[str, str]]] = {
    "analog-input": ("analog", "read"),
    "analog-output": ("analog", "read_write"),
    "binary-input": ("binary", "read"),
    "binary-output": ("binary", "read_write"),
    "coil": ("binary", "read_write"),
    "discrete-input": ("binary", "read"),
    "holding-register": ("analog", "read_write"),
    "input-register": ("analog", "read"),
}

# Legacy SunSpec "register" elements have a child named after the data type
SUNSPEC_POINT: Final[str] = "register"

# Children of a comms module or connection that aren't simple settings
COMMS_STRUCTURAL: Final[frozenset[str]] = frozenset(
    {"endpoint", "ip", "port", "address", "command-interface", SUNSPEC_POINT, *POINT_TYPES}
)

# Initial value element of an internal tag: tag type.
# bennu treats "status" as binary and "value" as analog.
INTERNAL_TAG_TYPES: Final[dict[str, str]] = {
    "status": "binary",
    "value": "analog",
    "string": "string",
}

FIRMWARE_PREFIX: Final[str] = "bennu-field-deviced"

# bennu-watcherd installs valid firmware uploaded with this name
FIRMWARE_UPLOAD_NAME: Final[str] = f"{FIRMWARE_PREFIX}.firmware"


class SCEPTRE(DeviceModule):
    """
    SCEPTRE bennu field devices (virtual RTUs, relays, PLCs, and FEPs).
    """

    device_type = "RTU"
    vendor_id = "Sandia"
    vendor_name = "Sandia National Laboratories"
    model = "SCEPTRE"
    brand = "SCEPTRE"
    file_signatures = [
        FileSignature(
            default_filename="config.xml",
            xml_tags=("SCEPTRE",),
        ),
    ]
    default_options = {
        "ftp": {
            "user": "sceptre",
            "pass": "sceptre",
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
        Verify it's a SCEPTRE bennu field device by logging in with FTP and
        checking if any file named "bennu" is on the server.
        """
        port = dev.options["ftp"]["port"]
        timeout = dev.options["ftp"]["timeout"]

        # Workaround hack for edge cases where fields get overwritten by other modules
        username = dev.options["ftp"].get("user")
        password = dev.options["ftp"].get("pass")
        if not username:
            username = cls.default_options["ftp"]["user"]
        if not password:
            password = cls.default_options["ftp"]["pass"]

        failed = ""
        file_list = []
        welcome = None

        try:
            with FTP(dev.ip, port, timeout) as ftp:
                welcome = ftp.getwelcome()

                if not ftp.login(username, password):
                    failed = "login failed"
                elif not (file_list := ftp.nlst()):
                    failed = "file listing failed ('nlst' command)"

                if not failed and not any("bennu" in f for f in file_list):
                    failed = "bennu firmware not in file listing"
        except Exception as ex:
            failed = str(ex)

        if failed:
            cls.log.debug(f"Failed to verify FTP for {dev.ip}: {failed}")
            return False

        dev._cache["file_list"] = file_list
        dev.related.files.update(PurePosixPath(f).name for f in file_list)

        if not dev.options["ftp"].get("user"):
            dev._options["ftp"]["user"] = username
        if not dev.options["ftp"].get("pass"):
            dev._options["ftp"]["pass"] = password

        dev.related.user.add(username)
        if welcome:
            dev.extra["ftp_welcome"] = welcome

        svc = Service(protocol="ftp", port=port, transport="tcp", status="verified")
        dev.store("service", svc, interface_lookup={"ip": dev.ip})

        return True

    @classmethod
    def _download_ftp(
        cls,
        dev: DeviceData,
        candidates: list[str],
        fallback: str | None = None,
        extension: str = "",
        save: bool = True,
    ) -> tuple[bytes | None, Path | None, str]:
        """
        Download a file from the FTP server's root directory.

        Args:
            dev: device to download from
            candidates: exact filenames to look for, in order of preference
            fallback: if none of the candidates exist, the first file that
                contains this string and ends with ``extension`` is used
            extension: required file extension for the fallback match
            save: if the file should be written to the device's output directory

        Returns:
            The file data (or :obj:`None` if the download failed), the path of
            the file written to disk (if any), and the name of the file
            on the server.
        """
        try:
            with FTP(
                ip=dev.ip,
                port=dev.options["ftp"]["port"],
                timeout=dev.options["ftp"]["timeout"],
            ) as ftp:
                username = dev.options["ftp"]["user"]
                password = dev.options["ftp"]["pass"]

                if not ftp.login(username, password):
                    return None, None, ""

                dev.related.user.add(username)

                # NLST can return names with or without the directory prefix
                listing = {PurePosixPath(f).name: f for f in ftp.nlst_files("/")}
                remote_name = next((listing[c] for c in candidates if c in listing), None)
                if not remote_name and fallback:
                    remote_name = next(
                        (
                            path
                            for name, path in listing.items()
                            if fallback in name and name.endswith(extension)
                        ),
                        None,
                    )
                if not remote_name:
                    cls.log.debug(
                        f"No file matching {candidates} or '{fallback}' found on {dev.ip}"
                    )
                    return None, None, ""

                data = ftp.download_binary(remote_name, save_to_file=False)

                # Only use the base name locally, the name comes from the server
                filename = PurePosixPath(remote_name).name
                downloaded_path = None
                if save and config.DEVICE_DIR:
                    downloaded_path = dev.write_file(
                        data=data,
                        filename=filename,
                        out_dir=dev.get_sub_dir("ftp_files"),
                    )
                return data, downloaded_path, filename
        except Exception as ex:
            cls.log.debug(f"Failed to get FTP file {candidates} from {dev.ip}: {ex}")

        return None, None, ""

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

        bennu field devices use a single XML file for their configuration,
        called ``config.xml`` by default.
        """
        data, file_path, filename = cls._download_ftp(dev, ["config.xml"], "config", ".xml")

        if data is None:
            cls.log.error(f"Failed to pull config from {dev.ip}")
            return False

        try:
            # If file output is disabled there won't be a file on disk
            if file_path:
                cls.parse_config(file_path, dev)
            else:
                cls.parse_config(data, dev)
            dev.related.files.add(filename)
        except Exception as err:
            cls.log.exception(f"Failed to parse SCEPTRE config: {err}")
            return False

        return True

    @classmethod
    def pull_firmware(cls, dev: DeviceData) -> bytes:
        """
        Retrieves the ``bennu-field-deviced`` binary via FTP.

        Files are tried in this order:

        1. ``bennu-field-deviced.firmware``, the last firmware uploaded, if
           ``bennu-watcherd`` accepts it (see :func:`accepted_firmware_hashes`),
           meaning it's installed. A file the watcher rejects is still saved, but
           the original binary is the one running.
        2. ``bennu-field-deviced``, phenix's copy of the original binary
           (``/usr/bin/bennu-field-deviced``).
        3. The first file starting with ``bennu-field-deviced``.
        """
        uploaded, uploaded_path, uploaded_name = cls._download_ftp(dev, [FIRMWARE_UPLOAD_NAME])
        original, original_path, original_name = cls._download_ftp(dev, [FIRMWARE_PREFIX])

        if uploaded is not None and (
            original is None
            or hashlib.sha256(uploaded).hexdigest() in accepted_firmware_hashes(original)
        ):
            data, file_path, filename = uploaded, uploaded_path, uploaded_name
        elif original is not None:
            if uploaded is not None:
                cls.log.warning(
                    f"'{FIRMWARE_UPLOAD_NAME}' on {dev.ip} isn't firmware bennu-watcherd "
                    f"accepts, so the original binary '{FIRMWARE_PREFIX}' is running"
                )
            data, file_path, filename = original, original_path, original_name
        else:
            data, file_path, filename = cls._download_ftp(dev, [], FIRMWARE_PREFIX)

        # Both files are saved, since a rejected upload is useful evidence
        dev.related.files.update(name for name in (uploaded_name, original_name) if name)

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
    def _push(
        cls,
        dev: DeviceData,
        to_push: str | bytes | Path,
        push_type: consts.PushType,
    ) -> bool:
        """
        Push firmware to a bennu field device.

        The firmware is uploaded over FTP as ``bennu-field-deviced.firmware``.
        ``bennu-watcherd`` checks the SHA-256 of that file every 10 ms. When it
        differs from the last firmware the watcher installed and is one of the
        hashes in ``/etc/sceptre/watcher.ini``, the watcher stops the field device,
        copies the file to ``/usr/bin/bennu-field-deviced``, and restarts the
        field device. Any other file is ignored.

        PEAT can't read ``watcher.ini``, so it computes the accepted hashes from
        phenix's copy of the original binary on the FTP server (see
        :func:`accepted_firmware_hashes`). Firmware the watcher would ignore isn't
        uploaded. If the original binary can't be downloaded, the firmware is
        uploaded without the check. PEAT can't confirm the watcher installed the
        firmware, only that the upload worked.

        Config pushes aren't supported. The field device only reads
        ``/etc/sceptre/config.xml`` when it starts, and that file is outside
        of the FTP server's root directory.
        """
        if push_type != "firmware":
            cls.log.error(
                f"Push of '{push_type}' to {dev.ip} isn't supported: bennu field devices "
                f"only read their config at startup, from a file outside the FTP root"
            )
            return False

        try:
            firmware = to_push.read_bytes() if isinstance(to_push, Path) else to_push
        except OSError as err:
            cls.log.error(f"Firmware push to {dev.ip} failed: couldn't read {to_push}: {err}")
            return False
        if not isinstance(firmware, bytes) or not firmware:
            cls.log.error(
                f"Firmware push to {dev.ip} failed: firmware must be a non-empty file or bytes"
            )
            return False

        # Copy of the original binary, used to compute the hashes the watcher accepts
        original, _, _ = cls._download_ftp(dev, [FIRMWARE_PREFIX], save=False)
        if original is None:
            cls.log.warning(
                f"Couldn't download '{FIRMWARE_PREFIX}' from {dev.ip} to check if "
                f"bennu-watcherd will install the firmware"
            )
        elif hashlib.sha256(firmware).hexdigest() not in accepted_firmware_hashes(original):
            cls.log.error(
                f"Firmware push to {dev.ip} failed: the firmware doesn't match the original "
                f"'{FIRMWARE_PREFIX}' binary or its shell variants, so bennu-watcherd "
                f"wouldn't install it"
            )
            return False

        success = cls._upload_ftp(dev, FIRMWARE_UPLOAD_NAME, firmware)
        dev.store(
            "event",
            Event(
                action="file_push",
                outcome="success" if success else "failure",
                message=f"{'Pushed' if success else 'Failed to push'} firmware "
                f"'{FIRMWARE_UPLOAD_NAME}' ({len(firmware)} bytes)",
            ),
            append=True,
        )
        return success

    @classmethod
    def _upload_ftp(cls, dev: DeviceData, filename: str, content: str | bytes) -> bool:
        """
        Upload a file to the FTP server's root directory.

        Text is encoded as UTF-8. Everything is uploaded in binary mode, so
        the server can't change line endings. The upload is checked by
        comparing the file size on the server, if the server supports ``SIZE``.
        """
        if isinstance(content, str):
            content = content.encode("utf-8")
        if not isinstance(content, bytes):
            cls.log.error(f"Cannot upload data with type '{type(content).__name__}'")
            return False

        try:
            with FTP(
                ip=dev.ip,
                port=dev.options["ftp"]["port"],
                timeout=dev.options["ftp"]["timeout"],
            ) as ftp:
                username = dev.options["ftp"]["user"]
                password = dev.options["ftp"]["pass"]

                if not ftp.login(username, password):
                    cls.log.error(f"Failed to upload {filename} to {dev.ip}: login failed")
                    return False

                dev.related.user.add(username)
                ftp.upload_binary(filename, content)

                try:
                    remote_size = ftp.file_size(filename)
                except ValueError:  # Non-numeric SIZE reply
                    remote_size = None
                if remote_size is not None and remote_size != len(content):
                    cls.log.error(
                        f"Failed to upload {filename} to {dev.ip}: file on the server "
                        f"is {remote_size} bytes, expected {len(content)} bytes"
                    )
                    return False
        except Exception as err:
            cls.log.error(f"Failed to upload {filename} to {dev.ip}: {err}")
            return False

        dev.related.files.add(filename)
        cls.log.info(f"Uploaded {filename} ({len(content)} bytes) to {dev.ip}")
        return True

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData:
        return cls.parse_config(file=file, dev=dev)

    @classmethod
    def parse_config(cls, file: Path | bytes | str, dev: DeviceData | None = None) -> DeviceData:
        """
        Parse a SCEPTRE bennu field device XML configuration file.

        .. note::
           Examples of configs can be found on the
           `bennu GitHub <https://github.com/sandialabs/sceptre-bennu/tree/main/data/configs>`__,
           in addition to the ones in the PEAT repo.
        """
        # Read the config data from the file
        if isinstance(file, Path):
            raw_config = file.read_text(encoding="utf-8")
        elif isinstance(file, bytes):
            raw_config = file.decode("utf-8")
        else:
            raw_config = file

        # Get the root section and basic information
        root = fromstring(raw_config).find("field-device")
        if root is None:
            raise ValueError("No 'field-device' element in SCEPTRE config")

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

        # Cycle time of the field device's scan loop, in milliseconds
        cycle_time = _ele(root, "cycle-time")
        if cycle_time:
            try:
                dev.extra["cycle_time"] = int(cycle_time)
            except ValueError:
                cls.log.warning(f"Invalid cycle-time '{cycle_time}' in config for {dev.get_id()}")

        # Parse tags. External tags map to I/O points, internal tags are
        # variables used by the device logic.
        tag_to_io = {}  # type: dict[str, str]
        tags_element = root.find("tags")
        if tags_element is not None:
            for tag_element in tags_element.findall("external-tag"):
                tag = Tag()
                for key in ["name", "io", "type"]:
                    if _ele(tag_element, key):
                        setattr(tag, key, _ele(tag_element, key))
                if tag.name and tag.io:
                    tag_to_io[tag.name] = tag.io
                dev.store("tag", tag, lookup="name")

            for tag_element in tags_element.findall("internal-tag"):
                tag = Tag(name=_ele(tag_element, "name") or "")
                for key, tag_type in INTERNAL_TAG_TYPES.items():
                    initial = _ele(tag_element, key)
                    if initial is not None:
                        tag.type = tag_type
                        tag.description = f"Internal tag, initial value: {initial}"
                        break
                else:
                    tag.description = "Internal tag"
                dev.store("tag", tag, lookup="name")
        else:
            cls.log.warning(f"No tags found in config for {dev.get_id()}")

        # Parse network communication modules (DNP3, Modbus/TCP, etc.)
        comms = root.find("comms")
        if comms is not None and len(comms):
            comm_mods = list(comms)
            # If client and server, then device is probably a FEP
            if (
                not dev.type
                and any(e.tag.endswith("-client") for e in comm_mods)
                and any(e.tag.endswith("-server") for e in comm_mods)
            ):
                dev.type = "FEP"
            for mod in comm_mods:
                extract_interface_info(mod, dev)  # Comm interface data
                extract_registers(mod, dev, tag_to_io)  # Protocol data points
        else:
            cls.log.error(f"No 'comms' element found in config for {dev.get_id()}")

        # I/O modules (connected to the SCEPTRE simulation)
        # "input-module" and "output-module" are legacy from older version of bennu
        for module_name in ["input", "output", "input-module", "output-module"]:
            direction = module_name.split("-")[0]
            for module_element in root.findall(module_name):
                extract_io_endpoint(module_element, direction, dev)

                for child in list(module_element):
                    if child.tag not in ["analog", "binary"]:
                        continue

                    io_name = ""
                    desc = ""

                    # Legacy format
                    d_ele = child.find("device")
                    if d_ele is not None:
                        # Update existing tag descriptions with SCEPTRE I/O info
                        # Example: "Tank1 - level_setpoint - simulink"
                        d_info = [_ele(d_ele, k) for k in ["name", "field", "provider"]]
                        io_name = _ele(d_ele, "name") or ""
                        desc = " - ".join(d for d in d_info if d)
                    # Current format
                    elif _ele(child, "name"):
                        io_name = _ele(child, "name")

                    io_id = _ele(child, "id")
                    if not io_id:
                        cls.log.warning(f"No 'id' for element: {child}")
                        continue

                    # Add description to the existing tag for this I/O point
                    if desc and match_all(dev.tag, {"io": io_id}) is not None:
                        dev.store("tag", Tag(description=desc), lookup={"io": io_id})

                    io_obj = IO(
                        id=io_id,
                        name=io_name,
                        type=child.tag,
                        direction=direction,
                        description=desc,
                    )

                    dev.store("io", io_obj, lookup={"id": io_id, "direction": direction})

        # NOTE: the order of tags, registers, and I/O in the results is set
        # when the data is exported, using the "_sort_by_fields" of each model.

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
            parsed_logic = "\n".join(x.strip() for x in logic.splitlines() if x.strip())
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
    """
    Extract the interface and service for a comms module (e.g. ``dnp3-server``).

    Servers listen on an endpoint, which is a local interface on the device.
    Clients connect to one or more remote servers, which are recorded in the
    ``connections`` list in the service's ``extra`` field. Interfaces are
    keyed by IP or serial port, so a device with multiple servers on the
    same IP, or a client and a server, gets one interface with all the services.
    """
    # modbus, modbus-tcp, bacnet, dnp3, iec60870-5-104, sunspec-tcp
    protocol = "_".join(com.tag.split("-")[:-1])
    conn_type = com.tag.split("-")[-1]  # client, server

    svc = Service(protocol=protocol, role=conn_type, enabled=True)

    # DNP3 address of this device (outstation for servers, master for clients)
    if _ele(com, "address"):
        svc.protocol_id = _ele(com, "address")

    # Module settings, e.g. "event-logging", "scan-rate", "instance", "rpoll-rate"
    svc.extra.update(_settings(com))

    # Event log file the module writes, relative to the field device's working directory
    if _ele(com, "event-logging"):
        dev.related.files.add(_ele(com, "event-logging"))

    # bennu command interface (ZeroMQ) of a client module
    if _ele(com, "command-interface"):
        svc.extra["command_interface"] = _ele(com, "command-interface")
        _add_related(dev, _parse_endpoint(_ele(com, "command-interface")))

    # Connections from a client to remote servers
    #  <modbus-client>
    #    <modbus-connection>
    #      <endpoint>tcp://127.0.0.1:5502</endpoint>
    connections = []
    iface_lookup = None
    for child in [c for c in com if c.tag.endswith("-connection")]:
        conn_ep = _connection_endpoint(child)
        conn = {"endpoint": conn_ep} if conn_ep else {}
        conn.update(_settings(child))
        if _ele(child, "address"):
            conn["address"] = _ele(child, "address")

        parsed = _parse_endpoint(conn_ep)
        _add_related(dev, parsed)
        # A serial connection uses a serial port on this device
        if parsed.get("serial_port"):
            iface_lookup = _store_interface(dev, protocol, serial_port=parsed["serial_port"])
        if conn:
            connections.append(conn)

    if connections:
        svc.extra["connections"] = connections

    # Endpoint the server listens on
    endpoint = _ele(com, "endpoint")
    if not endpoint and _ele(com, "ip"):
        # Legacy format
        # <port>20000</port>
        # <ip>192.0.2.3</ip>
        transport = "udp" if protocol == "bacnet" else "tcp"
        endpoint = f"{transport}://{_join_host_port(_ele(com, 'ip'), _ele(com, 'port'))}"

    if endpoint:
        parsed = _parse_endpoint(endpoint)
        _add_related(dev, parsed)
        if parsed.get("transport"):
            svc.transport = parsed["transport"]
        if parsed.get("port"):
            svc.port = parsed["port"]
            svc.configured_port = parsed["port"]
        if parsed.get("multicast_ip"):
            svc.extra["multicast_ip"] = parsed["multicast_ip"]
        if parsed.get("ip"):
            svc.listen_address = parsed["ip"]
            iface_lookup = _store_interface(dev, protocol, ip=parsed["ip"])
        elif parsed.get("serial_port"):
            svc.listen_interface = parsed["serial_port"]
            iface_lookup = _store_interface(dev, protocol, serial_port=parsed["serial_port"])
        elif parsed.get("hostname"):
            svc.extra["hostname"] = parsed["hostname"]

    if svc.protocol:
        dev.related.protocols.add(svc.protocol)

    # Keep clients and servers of the same protocol, and servers listening
    # on different endpoints, as separate services
    svc_lookup = {"protocol": svc.protocol, "role": svc.role}
    for key in ["port", "listen_address", "listen_interface", "protocol_id"]:
        if getattr(svc, key):
            svc_lookup[key] = getattr(svc, key)
    dev.store("service", svc, lookup=svc_lookup, interface_lookup=iface_lookup)


def extract_registers(com: Element, dev: DeviceData, tag_to_io: dict[str, str]) -> None:
    """
    Extract the protocol data points ("registers") for a comms module.

    Servers list points directly under the module, clients list them under
    each ``<x-connection>`` to a server.
    """
    protocol = "_".join(com.tag.split("-")[:-1])

    sources = [(com, "")]  # type: list[tuple[Element, str]]
    for child in list(com):
        if child.tag.endswith("-connection"):
            sources.append((child, _connection_endpoint(child)))

    for parent, server_endpoint in sources:
        for point in list(parent):
            if point.tag not in POINT_TYPES and point.tag != SUNSPEC_POINT:
                continue

            reg = Register(
                protocol=protocol,
                address=_ele(point, "address") or "",
                extra=_settings(point, exclude={"address", "tag"}),
            )

            if point.tag in POINT_TYPES:
                reg.measurement_type, reg.read_write = POINT_TYPES[point.tag]
                reg.extra["point_type"] = point.tag
                reg.tag = _ele(point, "tag") or ""
            else:
                # Legacy SunSpec: <register><address>40072</address><uint16>A</uint16>
                for child in list(point):
                    if child.tag not in ["address", "scaling-factor"] and child.text:
                        reg.data_type = child.tag
                        reg.tag = child.text.strip()
                        reg.extra.pop(child.tag.replace("-", "_"), None)
                        break

            if reg.tag in tag_to_io:
                reg.io = tag_to_io[reg.tag]
            if server_endpoint:
                reg.extra["server_endpoint"] = server_endpoint

            # Points are only unique with their point type, role, and server, which
            # can't all be looked up. Duplicates are removed when the data is exported.
            dev.store("registers", reg, append=True)


def extract_io_endpoint(module: Element, direction: str, dev: DeviceData) -> None:
    """
    Record the endpoint of an I/O module, which connects to the simulation provider.

    Input modules subscribe to the provider's publish endpoint, e.g.
    ``udp://172.16.1.4;239.0.0.1:40000`` (local interface IP, multicast
    group, and port). Output modules send updates to the provider's server
    endpoint, e.g. ``tcp://172.16.1.2:5555``.
    """
    endpoint = _ele(module, "endpoint")
    if not endpoint:
        return

    endpoints = dev.extra.setdefault("io_endpoints", {}).setdefault(direction, [])
    if endpoint not in endpoints:
        endpoints.append(endpoint)

    parsed = _parse_endpoint(endpoint)
    _add_related(dev, parsed)

    # The IP before the ";" is the interface on the simulation network
    if direction == "input" and parsed.get("ip") and parsed.get("multicast_ip"):
        lookup = {"ip": parsed["ip"]}
        if match_all(dev.interface, lookup) is None:
            iface = Interface(
                ip=parsed["ip"],
                type="ethernet",
                enabled=True,
                extra={"purpose": "SCEPTRE simulation I/O"},
            )
            dev.store("interface", iface, lookup=lookup)


def accepted_firmware_hashes(original: bytes) -> set[str]:
    """
    SHA-256 hashes of the firmware that ``bennu-watcherd`` will install.

    These are the hashes the phenix SCEPTRE app writes to
    ``/etc/sceptre/watcher.ini`` (``sceptre_start.mako`` in
    `sceptre-phenix-apps <https://github.com/sandialabs/sceptre-phenix-apps>`__):
    the original ``bennu-field-deviced`` binary, and two variants with its
    ``SHELL_0`` marker changed to ``SHELL_1``.

    Args:
        original: The original ``bennu-field-deviced`` binary

    Returns:
        The accepted hashes, as lowercase hex strings
    """
    return {
        hashlib.sha256(original).hexdigest(),  # reghash
        hashlib.sha256(original.replace(b"_SHELL_0", b"_SHELL_1")).hexdigest(),  # shellhashA
        hashlib.sha256(original.replace(b"SHELL_0", b"SHELL_1")).hexdigest(),  # shellhashB
    }


def _store_interface(dev: DeviceData, protocol: str, ip: str = "", serial_port: str = "") -> dict:
    """
    Add a local interface if one with the same IP or serial port doesn't exist.

    Returns:
        The lookup to use for associating services with the interface
    """
    lookup = {"ip": ip} if ip else {"serial_port": serial_port}
    if match_all(dev.interface, lookup) is None:
        iface = Interface(
            application=protocol,
            enabled=True,
            type="ethernet" if ip else "serial",
            **lookup,
        )
        dev.store("interface", iface, lookup=lookup)
    return lookup


def _connection_endpoint(conn: Element) -> str:
    """Endpoint of a client connection, including the legacy ip/port format."""
    endpoint = _ele(conn, "endpoint")
    if not endpoint and _ele(conn, "ip"):
        endpoint = f"tcp://{_join_host_port(_ele(conn, 'ip'), _ele(conn, 'port'))}"
    return endpoint or ""


def _settings(element: Element, exclude: set[str] | frozenset[str] = COMMS_STRUCTURAL) -> dict:
    """
    Simple settings (elements with text and no children) of an element,
    with dashes in the names replaced by underscores.
    """
    settings = {}
    for child in list(element):
        if child.tag in exclude or len(child) or not child.text or not child.text.strip():
            continue
        settings[child.tag.replace("-", "_")] = child.text.strip()
    return settings


def _add_related(dev: DeviceData, parsed: dict) -> None:
    for key in ["ip", "multicast_ip"]:
        if parsed.get(key):
            dev.related.ip.add(parsed[key])
    if parsed.get("hostname"):
        dev.related.hosts.add(parsed["hostname"])
    if parsed.get("port"):
        dev.related.ports.add(parsed["port"])


def _parse_endpoint(endpoint: str | None) -> dict[str, str | int]:
    """
    Parse a bennu endpoint string.

    Examples:

    - ``tcp://192.0.2.2:20000``
    - ``udp://172.16.1.2;239.0.0.1:40000`` (local IP;multicast group:port)
    - ``udp://239.0.0.1:40000`` (multicast group:port)
    - ``tcp://*:5555`` (all interfaces)
    - ``tcp://[2001:db8::2]:20000`` (IPv6)
    - ``/dev/ttyS0`` (serial port)
    - ``192.0.2.2:20000``
    - ``172.16.254.254`` (legacy)
    """
    endpoint = endpoint.strip() if endpoint else ""
    if not endpoint:
        return {}

    if endpoint.startswith("/"):
        return {"serial_port": endpoint, "type": "serial"}

    data = {}  # type: dict[str, str | int]
    if "://" in endpoint:
        transport, _, endpoint = endpoint.partition("://")
        data["transport"] = transport.lower()
        if data["transport"] in ["ipc", "inproc"]:  # ZeroMQ local sockets
            return data

    local = ""
    if ";" in endpoint:
        local, _, endpoint = endpoint.partition(";")
        local = _normalize_ip(local.strip("[]"))

    host, port = _split_host_port(endpoint)
    if port.isdigit() and 0 < int(port) <= 65535:
        data["port"] = int(port)

    if host in ["", "*"]:
        return data

    ip = _normalize_ip(host)
    if not ip:
        data["hostname"] = host
    elif local or ipaddress.ip_address(ip).is_multicast:
        data["multicast_ip"] = ip
    else:
        data["ip"] = ip
    if local:
        data["ip"] = local

    return data


def _split_host_port(value: str) -> tuple[str, str]:
    """Split "host:port", "[ipv6]:port", or a bare host or IPv6 address."""
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        return host, rest.lstrip(":")
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, port
    return value, ""  # No port, or a bare IPv6 address


def _join_host_port(host: str, port: str | None) -> str:
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def _normalize_ip(value: str) -> str:
    """Return the IP address in canonical form, or an empty string if it isn't one."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _ele(root: Element, to_find: str) -> str | None:
    found = root.find(to_find)
    if found is not None:
        return found.text.strip() if found.text else ""
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
