"""
Push firmware images to Allen-Bradley ControlLogix devices.

Authors

- Christopher Goes
- Mark Woodard
"""

import configparser
import io
import shutil
import socket
import tempfile
import zipfile
from pathlib import Path
from time import sleep

from peat import log, utils
from peat.protocols.cip import CCM, CIP, CIP_ERROR_CODES
from peat.protocols.enip import ENIP, EncapData, GetAttributesAllResponse

from .ab_scan import extract_info_response

# TODO: cleanup and properly integrate into PEAT API
# Use EnipDriver, pass in from ControlLogix?


def send_enip_pkt(sock: socket.socket, s_pkt: bytes) -> ENIP:
    sock.send(s_pkt)
    return ENIP(sock.recv(128))


# GetAttributeAll
def query_device(sock: socket.socket, session: int) -> tuple[int, dict | None]:
    ccm_fields = {
        "timeoutTicks": 0x9B07,
        "messageSize": 6,
        "service": "GET_ATTRIBUTE_ALL",
        "requestPathSize": 2,
        "requestPath": b"\x20\x01\x24\x01",
        "data": b"\x01\x00\x01\x00",
    }
    ccm_payload = bytes(CCM(**ccm_fields))

    cip_fields = {
        "timeout": 0x0014,
        "dataItemType_2": 0x00B2,
        "dataItemLength_2": len(ccm_payload) + 6,
        "service": "UNCONNECTED_SEND",
        "requestPathSize": 0x02,
        "requestPath": b"\x20\x06\x24\x01",
        "data": ccm_payload,
    }
    cip_payload = bytes(CIP(**cip_fields))

    s_pkt = bytes(ENIP(commandCode="SendRRData", sessionHandle=session, data=cip_payload))

    r_pkt = send_enip_pkt(sock, s_pkt)
    if r_pkt.status != 0:
        log.error("Failed to query device: ENIP error status")
        return r_pkt.status, None

    encap_data = EncapData(r_pkt.data)
    attributes = GetAttributesAllResponse(encap_data.data[4:])

    if attributes.status != 0:
        log.error("Failed to query device: CIP error status")
        return attributes.status, None

    return attributes.status, extract_info_response(attributes)


def generate_pre_data_packet(session: int, request_path: bytes, length: bytes) -> bytes:
    ccm_fields = {
        "timeoutTicks": 0x9B09,
        "messageSize": 0x16,
        "service": "RESERVED_0X51",
        "requestPathSize": 2,
        "requestPath": request_path,
        "data": length + b"\x00\x41\x03\x10\x07\x00\x01\x00\xe0\xcf\xc2\x00\x01\x00\x01\x00",
    }
    ccm_payload = bytes(CCM(**ccm_fields))

    cip_fields = {
        "timeout": 0x0050,
        "dataItemType_2": 0x00B2,
        "dataItemLength_2": len(ccm_payload) + 6,
        "service": "UNCONNECTED_SEND",
        "requestPathSize": 0x02,
        "requestPath": b"\x20\x06\x24\x01",
        "data": ccm_payload,
    }
    cip_payload = bytes(CIP(**cip_fields))

    return bytes(ENIP(commandCode="SendRRData", sessionHandle=session, data=cip_payload))


def generate_data_packet(session: int, request_path: bytes, payload: bytes) -> bytes:
    ccm_fields = {
        "timeoutTicks": 0x9B09,
        "messageSize": len(payload) + 6,
        "service": "RESERVED_0X4D",
        "requestPathSize": int(len(request_path) / 2),
        "requestPath": request_path,
        "data": payload + b"\x01\x00\x01\x00",
    }
    payload = bytes(CCM(**ccm_fields))

    cip_fields = {
        "timeout": 0x0050,
        "dataItemType_2": 0x00B2,
        "dataItemLength_2": len(payload) + 6,
        "service": "UNCONNECTED_SEND",
        "requestPathSize": 0x02,
        "requestPath": b"\x20\x06\x24\x01",
        "data": payload,
    }
    payload = bytes(CIP(**cip_fields))

    return bytes(ENIP(commandCode="SendRRData", sessionHandle=session, data=payload))


def send_file(sock: socket.socket, session: int, file_data: bytes, request_path: bytes) -> None:
    # TODO: Add test code
    length = (len(file_data)).to_bytes(4, byteorder="little")
    s_pkt = generate_pre_data_packet(session, request_path, length)
    send_enip_pkt(sock, s_pkt)

    for i in range(0, len(file_data), 256):
        pkt_num = i.to_bytes(4, byteorder="little")
        payload = pkt_num + file_data[i : i + 256]
        s_pkt = generate_data_packet(session, request_path, payload)
        send_enip_pkt(sock, s_pkt)


def reset(sock: socket.socket, session: int) -> None:
    cip_fields = {
        "timeout": 0x0014,
        "dataItemType_2": 0x00B2,
        "dataItemLength_2": 0x0016,
        "service": "UNCONNECTED_SEND",
        "requestPathSize": 0x02,
        "requestPath": b"\x20\x06\x24\x01",
        "data": b"\x07\x9b\x07\x00\x05\x02\x20\x01\x24\x01\x00\x00\x01\x00\x01\x00",
    }
    payload = bytes(CIP(**cip_fields))

    s_pkt = bytes(ENIP(commandCode="SendRRData", sessionHandle=session, data=payload))

    send_enip_pkt(sock, s_pkt)


def push_firmware(firmware: bytes, ip: str, port: int = 44818) -> bool:
    _log = log.bind(target=f"{ip}:{port}")
    _log.info(f"Pushing firmware to {ip}:{port} (size: {utils.fmt_size(len(firmware))})")

    # Extract the files out of the firmware blob
    try:
        sig1, bin1, sig2, bin2 = _open_firmware(firmware)
    except Exception as ex:
        _log.exception(f"Failed to extract firmware: {ex}")
        return False

    try:
        # Create TCP connection
        sock = socket.socket()
        sock.connect((ip, port))

        _log.debug("Register Session")
        session = send_enip_pkt(sock, bytes(ENIP(commandCode="RegisterSession"))).sessionHandle
        _log.debug(f"Session: {session}")
        sleep(2)

        # log.debug("Change to Program Mode")
        # TODO
        # s_pkt = generate_progmode_packet(session, payload)
        # r_pkt = send_enip_pkt(s, s_pkt)

        _log.debug("Query Device")
        status, device_info = query_device(sock, session)
        _log.debug(CIP_ERROR_CODES[status])
        _log.debug(device_info)

        _log.debug("Send Signature 1")
        send_file(sock, session, sig1, b"\x20\xa1\x24\x67")

        _log.debug("Send Binary 1")
        send_file(sock, session, bin1, b"\x20\xa1\x24\x03")
        sleep(10)

        _log.debug("Send Signature 2")
        send_file(sock, session, sig2, b"\x20\xa1\x24\x6a")

        _log.debug("Send Binary 2")
        send_file(sock, session, bin2, b"\x20\xa1\x24\x06")
        sleep(10)

        _log.debug("Reset Command")
        reset(sock, session)
        sleep(10)

        _log.debug("Pulling for Reboot and Query Device")
        while True:
            status, device_info = query_device(sock, session)
            _log.debug(CIP_ERROR_CODES[status])
            if status == 0x00:
                break
            sleep(10)
        _log.debug(f"Device info: {device_info}")

        # TODO: does session need to be unregistered after reboot?
    except OSError as ex:
        _log.error(f"Network error occurred while pushing firmware to {ip}:{port}: {ex}")
        return False

    _log.debug(f"Finished pushing firmware to device {ip}:{port}")
    return True


def _open_firmware(firmware: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    # Make a file-like object for zipfile to read
    file_obj = io.BytesIO(firmware)

    # Create a temporary directory for output of extracted files
    tmp_dir = Path(tempfile.mkdtemp())
    log.debug(f"Created temporary directory for firmware extraction: {tmp_dir}")

    # Parse the blob as a zipfile
    with zipfile.ZipFile(file_obj) as zip_ref:
        zip_ref.extractall(path=str(tmp_dir))
        zip_ref.close()

    # Get the names of the files we want
    config = configparser.ConfigParser()
    ini_files = tmp_dir.glob("PN-*.nvs")  # Get any extracted config files
    config.read(ini_files)  # Parses a list of file names

    # Read the binary files found
    sig1 = Path(tmp_dir, config["Update1"]["DataFileName"]).read_bytes()
    bin1 = Path(tmp_dir, config["Update2"]["DataFileName"]).read_bytes()
    sig2 = Path(tmp_dir, config["Update3"]["DataFileName"]).read_bytes()
    bin2 = Path(tmp_dir, config["Update4"]["DataFileName"]).read_bytes()

    # Cleanup
    log.debug(f"Removing temporary directory '{tmp_dir}'")
    shutil.rmtree(tmp_dir)
    return sig1, bin1, sig2, bin2
