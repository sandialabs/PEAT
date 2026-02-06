"""
Scapy packets for the ENIP protocol used by the Allen Bradley PLC.

Authors

- Casey Glatter
- Christopher Goes
- Patrica Schulz
- Mark Woodard
"""

# References:
#   https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-enip.c
#   https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-cip.c

import struct
from typing import Final

from scapy.all import bind_layers
from scapy.fields import (
    ByteField,
    FieldLenField,
    IPField,
    LEFieldLenField,
    LEIntEnumField,
    LEIntField,
    LELongField,
    LEShortEnumField,
    LEShortField,
    LongField,
    MayEnd,
    MultipleTypeField,
    PacketField,
    ShortField,
    StrFixedLenField,
    StrLenField,
    XByteField,
)
from scapy.packet import Packet

from .vendor_ids import VENDOR_NAMES

ENIP_COMMANDS: Final[dict[int, str]] = {
    0x0000: "NOP",  # 0
    0x0001: "Identify",  # 1
    0x0004: "ListServices",  # 4
    0x0063: "ListIdentity",  # 99
    0x0064: "ListInterfaces",  # 100
    0x0065: "RegisterSession",  # 101
    0x0066: "UnregisterSession",  # 102
    0x006F: "SendRRData",  # 111
    0x0070: "SendUnitData",  # 112
    0x0072: "IndicateStatus",  # 114
    0x0073: "Cancel",  # 115
    0x00C8: "StartDTLS",  # 200
}

# Command name => command code
# Inverted dict of ENIP_COMMANDS
ENIP_CMD_TO_CODE: Final[dict[str, int]] = {value: key for key, value in ENIP_COMMANDS.items()}

# https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-enip.c#L536
ENIP_TYPE_IDS: Final[dict[int, str]] = {
    0x0000: "Null Address Item",
    0x000C: "CIP Identity",
    0x0086: "CIP Security Information",
    0x0087: "EtherNet/IP Capability",
    0x0088: "EtherNet/IP Usage",
    0x00A1: "Connected Address Item",
    0x00B1: "Connected Data Item",
    0x00B2: "Unconnected Data Item",
    0x0100: "List Services Response",
    0x8000: "Socket Address Info O->T",
    0x8001: "Socket Address Info T->O",
    0x8002: "Sequenced Address Item",
    0x8003: "Unconnected Message over UDP",
}

# EtherNet/IP Encapsulation Error Codes
# The comments are standard CIP Encapsulation Error returned in the cip message header
ENIP_STATUS: Final[dict[int, str]] = {
    # "Success"
    0x0000: "Success",
    # "The sender issued an invalid or unsupported encapsulation command"
    0x0001: "Invalid Command",
    # "Insufficient memory"
    0x0002: "No Memory Resources",
    # "Poorly formed or incorrect data in the data portion"
    0x0003: "Incorrect Data",
    # "An originator used an invalid session handle when "
    # "sending an encapsulation message to the target"
    0x0064: "Invalid Session Handle",
    # "The target received a message of invalid length"
    0x0065: "Invalid Length",
    # "Unsupported Protocol Version"
    0x0069: "Unsupported Protocol Revision",
    # "Encapsulated CIP service not allowed on this port"
    0x006A: "Encapsulated CIP service not allowed on this port",
}

# TODO: full lookup table using Electronic Data Sheet (EDS) files
PRODUCT_TYPES: Final[dict[int, str]] = {
    0x00: "Generic Device (deprecated)",  # 0
    0x02: "AC Drive",  # 2
    0x03: "Motor Overload",  # 3
    0x04: "Limit Switch",  # 4
    0x05: "Inductive Proximity Switch",  # 5
    0x06: "Photoelectric Sensor",  # 6
    0x07: "General Purpose Discrete I/O",  # 7
    0x09: "Resolver",  # 9
    # Allen-Bradley specific?
    0x0A: "General Purpose Analog I/O",  # 10
    # Rockwell-specific?
    0x0B: "Software",  # 11
    0x0C: "Communications Adapter",  # 12
    # Formerly "Programmable Logic Controller", changed on 09/13/2022.
    # It's only defined as such in EDS files for the MicroLogix.
    # For all other devices, it's defined simply as "PLC",
    # so we use that now.
    0x0E: "PLC",  # 14
    0x10: "Position Controller",  # 16
    0x13: "DC Drive",  # 19
    0x15: "Contactor",  # 21
    0x16: "Motor Starter",  # 22
    0x17: "Soft Start",  # 23
    0x18: "Human-Machine Interface",  # 24
    0x1A: "Mass Flow Controller",  # 26
    0x1B: "Pneumatic Valve",  # 27
    0x1C: "Vacuum Pressure Gauge",  # 28
    0x1D: "Process Control Value",  # 29
    0x1E: "Residual Gas Analyzer",  # 30
    0x1F: "DC Power Generator",  # 31
    0x20: "RF Power Generator",  # 32
    0x21: "Turbomolecular Vacuum Pump",  # 33
    0x22: "Encoder",  # 34
    0x23: "Safety Discrete I/O Device",  # 35
    0x24: "Fluid Flow Controller",  # 36
    0x25: "CIP Motion Drive",  # 37
    0x26: "CompoNet Repeater",  # 38
    0x27: "Mass Flow Controller Enhanced",  # 39
    0x28: "CIP Modbus Device",  # 40
    0x29: "CIP Modbus Translator",  # 41
    0x2A: "Safety Analog I/O Device",  # 42
    0x2B: "Generic Device (keyable)",  # 43
    0x2C: "Managed Switch",  # 44
    0x2D: "CIP Motion Safety Drive Device",  # 45
    0x2E: "Safety Drive Device",  # 46
    0x2F: "CIP Motion Encoder",  # 47
    0x31: "CIP Motion I/O",  # 49
    0x3B: "ControlNet Physical Layer Component",  # 59
    0x96: "AC Drive",  # 150
    0xC8: "Embedded Component",  # 200
}


class LEShortLenField(FieldLenField):
    """
    A len field in a 2-byte integer.
    """

    def __init__(self, name, default, count_of=None, length_of=None):
        FieldLenField.__init__(
            self, name, default, fmt="<H", count_of=count_of, length_of=length_of
        )


class EncapData(Packet):
    name = "EncapData for ENIP"
    fields_desc = [
        LEIntField("handle", 0),  # Interface Handle, 0=CIP
        LEShortField("timeout", 2),  # seconds  (TODO: increase this? configurable?)
        LEShortField("itemCount", 2),
        LEShortField("addrItemType", 0),  # 0 = Null Address
        LEShortField("addrLengthData", 0),
        LEShortField("dataItemType", 178),  # 0xB2 (178) = Unconnected Data Item
        # NOTE: default value for lengthData must be None
        LEFieldLenField("lengthData", None, length_of="data"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.lengthData),
    ]


# TODO (cegoes, 01/10/2025): some responses are 8 bytes,
# while others are 18 bytes + productName (and len).
# This is really an identity response, and is a symptom
# of PEAT's fragmented and messy CIP/ENIP code.
#
# Bugfix (cegoes, 01/10/2025): Scapy 2.6.0 changed dissection behavior.
# Previously, if the bytes passed were too short to fully dissect, then
# the dissection would end between fields. Remaining fields would be kept
# with default values. The new behavior requires these points to be explictly
# defined, using MayEnd.
# Details: https://github.com/secdev/scapy/pull/4012
class GetAttributesAllResponse(Packet):
    name = "GetAttributesAll Response"
    fields_desc = [
        LEShortEnumField("vendor", 1, VENDOR_NAMES),
        MayEnd(LEShortEnumField("productType", 1, PRODUCT_TYPES)),
        LEShortField("productCode", 0),
        ByteField("MajorFirmwareVersion", 0),
        ByteField("MinorFirmwareVersion", 0),
        LEShortField("status", 0),
        LEIntField("serialNumber", 0),  # 4 bytes
        ByteField("productNameLength", 0),
        MayEnd(StrLenField("productName", b"", length_from=lambda pkt: pkt.productNameLength)),
        XByteField("state", 0),
    ]


# TODO (01/11/2022): reduce duplication between packet classes, use inheritance/layers
# LEShortField("itemCount", 1),
# LEShortEnumField("typeID", 1, ENIP_TYPE_IDS),
# LEShortField("length", 2),
# LEShortField("encapsulationVersion", 1),
# LEShortField("sinFamily", 2),

# ByteField  => 1 byte
# ShortField => 2 bytes
# IntField   => 4 bytes


class ENIPListIdentityResponse(Packet):
    name = "ENIP ListIdentity Response"
    fields_desc = [
        LEShortField("itemCount", 1),
        LEShortEnumField("typeID", 1, ENIP_TYPE_IDS),
        LEShortField("length", 2),
        LEShortField("encapsulationVersion", 1),
        LEShortField("sinFamily", 2),
        ShortField("sinPort", 44818),
        IPField("sinAddr", "0.0.0.0"),
        LELongField("sinZero", 0),
        # "VendCode" in EDS
        LEShortEnumField("vendor", 1, VENDOR_NAMES),
        # "ProdType" in EDS
        LEShortEnumField("productType", 1, PRODUCT_TYPES),
        # Number identifying product name and rating
        # TODO: find a lookup table for productCode
        # This can be resolved using EDS (Electronic Data Sheet) files
        # "ProdCode" in EDS
        LEShortField("productCode", 0),
        # 1st byte is Major firmware, second is minor
        # e.g. 30/13, as in "1756-L74_30.013.dmk"
        ByteField("MajorFirmwareVersion", 0),
        ByteField("MinorFirmwareVersion", 0),
        # TODO: find a lookup table for status
        # "The Status attribute provides information on the status of the device, e.g.,
        #  whether it is owned (controlled by another device) or configured
        #  (to something different than the out-of-the-box default),
        #  and whether any major or minor faults have occurred."
        LEShortField("status", 0),
        # ByteField("status1", 0),
        # ByteField("status2", 0),
        LEIntField("serialNumber", 0),  # 4 bytes
        ByteField("productNameLength", 0),
        # "ProdName" in EDS
        StrLenField("productName", b"", length_from=lambda pkt: pkt.productNameLength),
        # TODO: lookup table for "state"
        XByteField("state", 0),
    ]


# status1 + status2, status=14416 is actually 112 + 49 => "REMOTE RUN"
# KEYSWITCH = {
#     96: {16: "RUN", 17: "RUN", 48: "REMOTE RUN", 49: "REMOTE RUN"},
#     112: {32: "PROG", 33: "PROG", 48: "REMOTE PROG", 49: "REMOTE PROG"},
# }


class ENIPListInterfacesResponseItems(Packet):
    name = "ENIPListInterfacesResponseItems"
    fields_desc = [
        LEShortEnumField("typeID", 1, ENIP_TYPE_IDS),
        FieldLenField("itemLength", 0, length_of="itemData"),
        StrLenField("itemData", b"", length_from=lambda pkt: pkt.itemLength),
    ]


class ENIPListInterfacesResponse(Packet):
    name = "ENIPListInterfacesResponse"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="listItems"),
        PacketField("listItems", None, ENIPListInterfacesResponseItems),
    ]


class ENIPListServicesResponseItems(Packet):
    name = "ENIP ListServices Response Items"
    fields_desc = [
        LEShortEnumField("typeID", 1, ENIP_TYPE_IDS),
        LEShortField("length", 2),
        LEShortField("encapsulationVersion", 1),  # 2 bytes
        LEShortField("sinFamily", 2),  # 2 bytes
        # StrLenField("serviceName", b"", length_from=lambda pkt: pkt.length - 6),
        StrFixedLenField("serviceName", None, 64),  # TODO: why 16 * 4?
    ]


class ENIPListServicesResponse(Packet):
    name = "ENIP ListServices Response"
    fields_desc = [
        FieldLenField("itemCount", 0, count_of="listItems"),
        PacketField("listItems", None, ENIPListServicesResponseItems),
    ]


class ENIPRegisterSession(Packet):
    name = "ENIP RegisterSession"
    fields_desc = [
        LEShortField("protocolVersion", 1),
        LEShortField("optionsRegisterSession", 0),
    ]


# TODO: compare PCAPs of PEAT before and after refactor
# broadcast, unicast, tcp, udp


class _ENIPBuilder:
    # Automatically calculate dataLength from data's...length
    # This gets called when bytes(ENIP(...)) is called
    # payload has a value when called like: ENIP(...) / b"data"
    # payload is empty in this case: ENIP(..., data=b"data")
    def post_build(self, packet, payload):
        if not self.dataLength and payload:
            length = struct.pack("<H", len(payload))
            packet = packet[:2] + length + packet[4:]
        elif not self.dataLength and len(packet) > 24:
            length = struct.pack("<H", len(packet[24:]))
            packet = packet[:2] + length + packet[4:]
        return packet + payload


class ENIP(_ENIPBuilder, Packet):
    """
    EtherNet/IP packet encapsulation.

    If "data" isn't set, it will be automatically set based on commandCode.

    The header is 24 bytes fixed length.

    It can be used with TCP. Maybe UDP as well?
    """

    name = "EtherNet/IP Request"
    fields_desc = [
        # NOTE(cegoes, 6/3/23): "commandCode" must be used for field name.
        # Otherwise, it shadows (and is blocked by) Packet.command().
        LEShortEnumField("commandCode", 0, ENIP_COMMANDS),  # 2 bytes
        LEShortLenField("dataLength", 0, length_of="data"),  # 2 bytes
        LEIntField("sessionHandle", 0),  # 4 bytes
        # TODO: rename to enipStatus (to differentiate from status field in CIP layer)
        LEIntEnumField("status", 0, ENIP_STATUS),  # 4 bytes
        LongField("senderContext", 5),  # 8 bytes
        LEIntField("options", 0),  # 4 bytes
        MultipleTypeField(
            [
                (
                    PacketField("data", ENIPRegisterSession(), ENIPRegisterSession),
                    lambda pkt: pkt.commandCode == ENIP_CMD_TO_CODE["RegisterSession"],
                )
            ],
            StrLenField("data", b"", length_from=lambda pkt: pkt.dataLength),
        ),
    ]


# class ENIPResponse(_ENIPBuilder, Packet):
#     """
#     EtherNet/IP packet response dissection.

#     The data field will be dissected based on commandCode.
#     """

#     name = "EtherNet/IP Response"
#     fields_desc = [
#         # NOTE(cegoes, 6/3/23): "commandCode" must be used for field name.
#         # Otherwise, it shadows (and is blocked by) Packet.command().
#         LEShortEnumField("commandCode", 0, ENIP_COMMANDS),  # 2 bytes
#         LEShortLenField("dataLength", 0, length_of="data"),  # 2 bytes
#         LEIntField("sessionHandle", 0),  # 4 bytes
#         # LEIntEnumField("status", 0, ENIP_STATUS),  # 4 bytes
#         LEIntEnumField("enipStatus", 0, ENIP_STATUS),  # 4 bytes
#         LongField("senderContext", 5),  # 8 bytes
#         LEIntField("options", 0),  # 4 bytes
#         # StrLenField("data", b"", length_from=lambda pkt: pkt.dataLength),
#         MultipleTypeField(
#             [
#                 (
#                     PacketField("data", ENIPRegisterSession(), ENIPRegisterSession),
#                     lambda pkt: pkt.commandCode == ENIP_CMD_TO_CODE["RegisterSession"],
#                 ),
#                 (
#                     PacketField("data", None, ENIPListServicesResponse),
#                     lambda pkt: pkt.commandCode == ENIP_CMD_TO_CODE["ListServices"],
#                 ),
#                 (
#                     PacketField("data", None, ENIPListIdentityResponse),
#                     lambda pkt: pkt.commandCode == ENIP_CMD_TO_CODE["ListIdentity"],
#                 ),
#                 (
#                     PacketField("data", None, ENIPListInterfacesResponse),
#                     lambda pkt: pkt.commandCode == ENIP_CMD_TO_CODE["ListInterfaces"],
#                 ),
#             ],
#             StrLenField("data", b"", length_from=lambda pkt: pkt.dataLength),
#         ),
#     ]


# GetAttributesAllResponse is a subset of ENIPListIdentityResponse
bind_layers(ENIPListIdentityResponse, GetAttributesAllResponse)


# TODO: bind layers to ports for TCP and UDP? (bind_bottom_up?)
# TODO: def answers(self, other), compare session handle

__all__ = [
    "ENIP",
    "ENIPListIdentityResponse",
    "ENIPRegisterSession",
    "EncapData",
    "GetAttributesAllResponse",
]
