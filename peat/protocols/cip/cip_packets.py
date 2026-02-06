"""
Scapy packets for the Common Industrial Protocol (CIP) protocol,
used by Rockwell Allen Bradley PLCs and other devices.

CIP is encapsulated by the ENIP protocol.
In other words, CIP is a subset of ENIP.

Authors

- Casey Glatter
- Patrica Schulz
- Mark Woodard
"""

from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    IntField,
    LEFieldLenField,
    LEIntField,
    LEShortField,
    ShortField,
    StrField,
    StrLenField,
)
from scapy.packet import Packet

from .cip_const import *


class ByteLenField(FieldLenField):
    """
    Field representing the length of the payload of the packet in one byte.
    """

    def __init__(self, name, default, count_of=None, length_of=None):
        FieldLenField.__init__(
            self, name, default, fmt="B", count_of=count_of, length_of=length_of
        )


class AbCIP(Packet):
    name = "CIP"
    fields_desc = [
        ByteEnumField("cmServiceCode", 0x52, CIP_SERVICE_CODES),  # 0x52 = UNCONNECTED_SEND
        ByteField("cmReqPathSize", 2),
        IntField("cmReqPath", 0x20062401),  # for UNCONNECTED_SEND
        ShortField("timeout", 0x069A),
        # Embedded message request
        LEShortField("messageRequestSize", 0x0006),  # serviceCode, reqPathLen, reqPath
        ByteEnumField("serviceCode", 0x01, CIP_SERVICE_CODES),  # 1 = GetAttributesAll
        ByteField("lengthReqPath", 0x02),  # number of words, not bytes
        IntField("reqPath", 0x20012401),  # Identity
        # Route path (this addresses module on backplane?)
        ByteField("routePathSize", 1),
        ByteField("reserved", 0),
        ByteField("routeSegment", 1),  # 0 = Reserved, 1 = Backplane
        ByteField("routeAddr", 0),  # Slot number
    ]


# NOTE: CIP and CCM are used by ab_push.py, and embed ENIP layers as well.
# Don't modify or you might break ab_push.py
class CIP(Packet):
    """
    Common Industrial Protocol (CIP) packet.
    """

    name = "CIP Packet"  # TODO: CIP is taken by "AbCIP"
    fields_desc = [
        LEIntField("handle", 0),  # Interface Handle (0=CIP)
        LEShortField("timeout", 0),
        LEShortField("itemCount", 2),  # Item count: should be at list 2 (Address and Data)
        LEShortField("dataItemType_1", 0),  # Address Item Type ID
        LEShortField("dataItemLength_1", 0),  # Address Item Length
        LEShortField("dataItemType_2", 0),  # Address Item Type ID
        LEFieldLenField("dataItemLength_2", 0),  # Address Item Length
        # Everything above this is ENIP Command Specific Data
        ByteEnumField("service", 0, CIP_SERVICE_CODES),
        ByteLenField("requestPathSize", 0, length_of="requestPath"),
        StrLenField("requestPath", b"", length_from=lambda pkt: pkt.requestPathSize),
        StrField("data", ""),
    ]


class CCM(Packet):
    """
    CIP Connection Manager (CCM) packet.
    """

    name = "CCM"
    fields_desc = [
        LEShortField("timeoutTicks", 0),
        LEShortField("messageSize", 0),
        ByteEnumField("service", 0, CIP_SERVICE_CODES),
        ByteLenField("requestPathSize", 0, length_of="requestPath"),
        StrLenField("requestPath", b"", length_from=lambda pkt: pkt.requestPathSize),
        StrField("data", ""),
    ]


__all__ = ["CCM", "CIP", "AbCIP"]
