"""
Methods for enumerating Allen-Bradley ControlLogix devices on a IP network.

Authors

- Casey Glatter
- Christopher Goes
- Patricia Schulz
"""

import copy
import socket
from pprint import pformat

from peat import config
from peat import log as peat_logger
from peat.modules.rockwell import clx_const
from peat.protocols.cip import AbCIP
from peat.protocols.common import scapy_human_field
from peat.protocols.enip.enip_packets import (
    ENIP,
    EncapData,
    ENIPListIdentityResponse,
    GetAttributesAllResponse,
)
from peat.protocols.ip import make_udp_socket, send_discovery_packet

DevDescType = dict[str, dict | int | str]

# TODO: use EnipDriver here


def broadcast_scan(ip: str, port: int = 44818, timeout: float = 5.0) -> list[DevDescType]:
    """
    Scan by sending a broadcast packet and waiting for responses from devices.

    Args:
        ip: IP to broadcast using
        port: Port to send broadcast to
        timeout: Time to wait for responses, in seconds

    Returns:
        List of basic device descriptions
    """
    log = peat_logger.bind(target=f"{ip}:{port}")
    log.info(
        f"Broadcast scanning for Allen-Bradley devices via CIP "
        f"on {ip}:{port} (timeout: {timeout:.2f} seconds)"
    )

    descriptions = []
    sock = make_udp_socket(timeout, broadcast=True)
    if sock is None:
        return []
    packet = bytes(ENIP(commandCode="ListIdentity"))

    if send_discovery_packet(sock, ip, port, packet):
        while True:
            try:
                dev_desc = fingerprint_device(sock)
                if dev_desc:
                    # Add the collected info to list of devices
                    descriptions.append(dev_desc)
            except TimeoutError:
                break
            except Exception as err:
                log.warning(
                    f"Failed to receive a response from an unknown device "
                    f"on scan to {ip}:{port} due to an error: {err}"
                )
    else:
        log.error(f"Failed to send discovery packet to {ip}:{port}")

    log.info(f"Finished CIP broadcast scan to {ip}:{port}, {len(descriptions)} results")
    sock.close()

    return descriptions


def fingerprint_device(sock: socket.socket) -> DevDescType | None:
    """
    Listen for response from a device, verify it is a Allen-Bradley,
    then determine basic metadata about it.
    """
    data, address = sock.recvfrom(4096)
    ip = str(address[0])
    port = int(address[1])
    log = peat_logger.bind(target=f"{ip}:{port}")
    log.info(f"Received a response from device {ip}:{port}")

    # Reconstruct the packet based on raw data from PLC
    resp_packet = ENIP(data)

    # "ListIdentity"
    if resp_packet.commandCode == 99:
        identity = ENIPListIdentityResponse(resp_packet.data)
        dev_desc = extract_info_response(identity)
        dev_desc["ip"] = ip
        dev_desc["port"] = port
        log.info(f"Found {dev_desc['vendor']} {dev_desc['product_name']} at {ip}:{port}")

        # Get information on all slots on the device (if it's not a MicroLogix)
        if dev_desc["product_code"] not in clx_const.MLX_PRODUCT_CODES:
            slots = enumerate_device_modules(ip, port)
            if slots:
                try:
                    cpu_slot = 0
                    if 0 not in slots:
                        log.warning("No data for slot 0, trying slot 1 for CPU...")
                        cpu = slots[1]
                        cpu_slot = 1
                    else:
                        cpu = slots[0]
                except KeyError:
                    log.error("No data for slot 0 or 1!")
                    log.debug(f"** SLOTS DUMP **\n{pformat(repr(slots))}")
                else:
                    if not cpu:
                        log.error(f"Empty CPU data from {ip}!")
                    else:
                        dt = cpu.get("product_type")
                        if dt and dt != "PLC":
                            log.warning(
                                f"CPU slot {cpu_slot} of {ip} has invalid product_type {dt}"
                            )
                        elif not dt:
                            log.warning(f"No product_type for CPU slot {cpu_slot} on {ip}")
                        dev_desc["cpu_serial"] = cpu["serial_number"]
                    dev_desc["modules"] = slots
            else:
                log.error(f"Failed to enumerate CPU modules for device {ip}")
                log.trace(f"** CURRENT DEV DESC **\n{dev_desc}")

        return dev_desc
    else:
        log.warning(f"Invalid command code '{resp_packet.commandCode}' received from {ip}:{port}")
        return None


def enumerate_device_modules(
    ip: str, port: int = 44818, chassis_size: int = 8, timeout: float = 5.0
) -> dict[int, dict[str, int | str]]:
    """
    Enumerate ControlLogix device modules.

    Args:
        ip: IPv4 address of device
        port: TCP port to use for enumeration
        chassis_size: Number of modules on the device
        timeout: Number of seconds to wait before timing out

    Returns:
        Metadata of any modules discovered during enumeration, keyed by slot number
    """
    log = peat_logger.bind(target=f"{ip}:{port}")
    log.info(
        f"Enumerating modules for ControlLogix device {ip}:{port} (timeout: {timeout:.2f} seconds)"
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)

        # Establish and register CIP session
        try:
            sock.connect((ip, port))
            sock.send(bytes(ENIP(commandCode="RegisterSession")))

            # The number here doesn't really matter as long as its > 28
            raw_session_data = sock.recv(28)  # Wait until we get 28 bytes
            session = ENIP(raw_session_data).sessionHandle
        except Exception as err:
            log.error(f"Failed to establish session with {ip}: {err}")
            if config.DEBUG:
                log.exception("")
            return {}

        log.debug(f"Session for {ip}: {hex(session)}")

        # Enumerate device modules
        log.info(f"Attempting to enumerate {chassis_size} modules on {ip}:{port}")
        slots = {}

        for slot in range(chassis_size):
            try:
                cip_ccm = AbCIP(
                    serviceCode="GET_ATTRIBUTE_ALL",
                    routeAddr=slot,
                )
                cip_packet = ENIP(
                    commandCode="SendRRData",
                    sessionHandle=session,
                    data=EncapData(data=bytes(cip_ccm)),
                )

                sock.send(bytes(cip_packet))

                # The number here doesn't really matter as long as its > 100
                raw_slot_data = sock.recv(100)  # Wait until we get 100 bytes
            except Exception as err:
                log.error(f"Error enumerating modules on {ip}: {err}")
                slots[slot] = {}
                break

            # Process the response
            encap_data = EncapData(ENIP(raw_slot_data).data)
            attributes = GetAttributesAllResponse(encap_data.data[4:])

            # Extract metadata from the processed response
            info = extract_info_response(attributes)

            # Save slot metadata if it's there (not a empty dict)
            if info:
                info["slot"] = slot
                slots[slot] = info
            else:
                log.debug(f"No data for slot {slot} on {ip}")

    return slots


def extract_info_response(
    info: ENIPListIdentityResponse | GetAttributesAllResponse,
) -> dict[str, int | str]:
    """
    Extract metadata from response to ``ListIdentity`` or ``GetAttributesAll``.
    """
    # Only extract slot metadata if it exists (for GetAttributesAllResponse)
    if not hasattr(info, "productName") or not info.productName:
        return {}

    # Remove null characters and strip whitespace from product name
    p_name = " ".join(info.productName.decode().split())
    p_name = p_name.replace("\u0000", "").strip()

    extracted = {
        "brand": "Unknown brand (refer to product_name)",
        "vendor": scapy_human_field(info, "vendor"),
        "product_name": p_name,
        "product_code": int(info.productCode),
        "product_type": scapy_human_field(info, "productType"),
        "serial_number": info.serialNumber,
        "firmware_version": info.MajorFirmwareVersion,
        "firmware_revision": info.MinorFirmwareVersion,
        "state": int(info.state),
        "status": int(scapy_human_field(info, "status")),
    }

    if extracted["product_type"].isdigit():
        extracted["product_type"] = "Unknown"

    # Try to guess what the brand is
    # for now, we hand-jam mappings from product code to brand
    # TODO: productCode + productType => lookup in EDS files
    if extracted["product_code"] in clx_const.CLX_PRODUCT_CODES:
        extracted["brand"] = "ControlLogix"
    elif extracted["product_code"] in clx_const.MLX_PRODUCT_CODES:
        extracted["brand"] = "MicroLogix"
    elif "PowerFlex" in extracted["product_name"]:
        extracted["brand"] = "PowerFlex"

    return extracted


def annotate_slots(existing_module: dict, new_module: dict) -> None:
    """
    Annotate the slots of a module with another module's info.
    """
    slots = existing_module["modules"]

    for slot_number, slot in slots.items():
        # If found, annotate with network information (IP, MAC, etc.)
        if new_module["serial_number"] == slot["serial_number"]:
            # Add the additional network information from fingerprint
            for key, value in new_module.items():
                # Only annotate with new information
                if key in ["modules"] or key in slot.keys():
                    continue

                # Copy the new data (deepcopy prevents reference issues)
                slots[slot_number][key] = copy.deepcopy(value)

            # We found the module, so stop the search
            break

    existing_module["modules"] = slots
