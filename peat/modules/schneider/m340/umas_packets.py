"""
Scapy packets for the Schneider-proprietary UMAS protocol.

This protocol is used by the Schneider Modicon M340 PLC.

Authors

- Patrica Schulz
- Christopher Goes
"""

import binascii
import socket

from scapy.all import (
    ByteField,
    FieldLenField,
    LEShortField,
    MayEnd,
    Packet,
    ShortField,
    StrLenField,
    XByteField,
)

from peat import CommError, config, utils
from peat import log as peat_logger

# TODO: refactor the UMAS packets to properly implement the UMAS protocol
#   based on what we know now about it. hopefully improve reliability.


class Modbus(Packet):
    name = "Modbus/TCP"
    fields_desc = [
        ShortField("transactionID", 1),
        ShortField("protocolID", 0),
        FieldLenField(
            "length",
            None,
            length_of="data",
            adjust=lambda pkt, x: x + 2,  # noqa: ARG005
        ),
        XByteField("unitID", 0),
        ByteField("functionCode", 90),
        StrLenField("data", "", length_from=lambda pkt: pkt.length - 2),
    ]


class UMASQuery(Packet):
    name = "UMAS query"
    fields_desc = [
        XByteField("connectionCode", 0x6D),
        XByteField("commandCode", 0x00),
        ShortField("num", 0x01),
        LEShortField("data", 0x0000),
    ]


class UMASResponse(Packet):
    name = "UMAS response"
    fields_desc = [
        XByteField("connectionCode", 0x6D),
        # NOTE: MayEnd required for scapy 2.6
        # num and dataLen are optional?
        MayEnd(XByteField("commandCode", 0x00)),
        ShortField("num", 0x00),
        LEShortField("dataLen", 0x00),
    ]


class UMASPoll(Packet):
    name = "UMAS poll"
    fields_desc = [
        XByteField("connectionCode", 0x00),
        XByteField("commandCode", 0x00),
    ]


class UMASConnection(Packet):
    name = "UMAS connection"
    fields_desc = [
        XByteField("connectionCode", 0x00),
        XByteField("commandCode", 0x10),
        LEShortField("unknown1", 0xAF8C),
        LEShortField("unknown2", 0x0204),
        FieldLenField("length", None, length_of="name"),
        StrLenField("name", "", length_from=lambda pkt: pkt.length),
    ]


class UMASConnectionResponse(Packet):
    name = "UMAS connection response"
    fields_desc = [
        XByteField("connectionCode", 0x00),
        XByteField("commandCode", 0x10),
        XByteField("newConnectionCode", 0x10),
    ]


def start_pull_packet(cid: int) -> Modbus:
    p = {"connectionCode": cid, "commandCode": 0x33, "num": 1, "data": 0x03FB}
    mp = {"data": bytes(UMASQuery(**p))}
    return Modbus(**mp)


def pull_packet(cid: int, seq: int) -> Modbus:
    p = {"connectionCode": cid, "commandCode": 0x34, "num": 0x1, "data": seq}
    mp = {"data": bytes(UMASQuery(**p))}
    return Modbus(**mp)


def stop_pull_packet(cid: int, seq: int) -> Modbus:
    p = {"connectionCode": cid, "commandCode": 0x35, "num": 0x1, "data": seq}
    mp = {"data": bytes(UMASQuery(**p))}
    return Modbus(**mp)


def poll_packet(cid: int) -> Modbus:
    p = {"connectionCode": cid, "commandCode": 0x04}
    mp = {"data": bytes(UMASPoll(**p))}
    return Modbus(**mp)


def connect_packet() -> Modbus:
    # NOTE(cegoes): must call bytes() on a packet
    # layer before passing it to the next layer
    sch_connect = bytes(UMASConnection(name=b"PEAT - Unity Loader"))
    return Modbus(data=sch_connect)


def send_umas_packet(
    sock: socket.socket,
    packet: Packet | bytes,
    response_class: type[Packet],
    tracker: list | None = None,
) -> Packet:
    """
    Send a packet and receive the response from a UMAS device.

    Args:
        sock: The TCP socket to use
        packet: The packet to send
        response_class: The Packet subclass to process the response as
        tracker: tracks all packets sent, including raw payloads and metadata

    Returns:
        The data field of the response
    """
    payload = bytes(packet)

    # for logging
    ip, port = sock.getpeername()
    device = f"{ip}:{port}"
    log = peat_logger.bind(target=device)

    if config.DEBUG >= 3:
        log.trace3(
            f"Sending packet from local interface {sock.getsockname()} to "
            f"remote device {device}\nLength: {len(packet)}"
            f"\nContents: {binascii.hexlify(payload)}"
        )

    try:
        update_tracker("send", packet, payload, sock, tracker)
        bytes_sent = sock.send(payload)
        if config.DEBUG >= 2:
            log.trace2(f"{bytes_sent} bytes were sent to {device}")
        if bytes_sent != len(payload):
            log.error(f"Only {bytes_sent} bytes were sent out of {len(payload)} total bytes")
    except OSError as err:
        log.exception("Could not send UMAS packet")
        raise err

    # TODO: fix for scapy 2.6.1
    raw_response = sock.recv(4096)  # type: bytes
    modbus_layer = Modbus(raw_response)
    data = response_class(modbus_layer.data)  # type: Packet
    update_tracker("receive", data, raw_response, sock, tracker)

    if config.DEBUG >= 3:
        log.trace3(
            f"Raw data from remote device {device}"
            f"\nLength: {len(packet)}\nContents: "
            f"{binascii.hexlify(raw_response)}"
        )

    if data.commandCode != 0xFE:
        if data.commandCode == 253:  # 0xfd
            raise CommError(
                f"Response code 0xfd (253). Someone is currently connected to the "
                f"device in the Unity editor or a PEAT pull is happening at "
                f"the same time against this module or another communication "
                f"module on the same chassis! (device: {device})"
            )

        log.warning(f"Received an invalid command code: {hex(data.commandCode)}")
        if config.DEBUG:
            data.show2()

    return data


def update_tracker(
    direction: str,
    packet: Packet,
    payload: bytes,
    sock: socket.socket,
    tracker: list | None,
):
    # TODO: expand this technique globally to PEAT for traffic capturing/logging
    if tracker is not None:
        # TODO: store UMAS function code
        # TODO: store UMAS response status (for responses)
        # TODO: resolve UMAS function name (from .umas_codes.py)
        dataset = {
            "direction": direction,
            "local_ip": sock.getsockname()[0],
            "local_port": sock.getsockname()[1],
            "remote_ip": sock.getpeername()[0],
            "remote_port": sock.getpeername()[1],
            # "packet_object": packet,
            "packet_length": len(packet),
            "payload": binascii.hexlify(payload),
            "data": binascii.hexlify(packet.data) if hasattr(packet, "data") else b"",
            "load": binascii.hexlify(packet.load) if hasattr(packet, "load") else b"",
            "timestamp": utils.utc_now(),
        }
        tracker.append(dataset)
