from collections.abc import Callable
from typing import Final

from scapy.fields import ByteField, IntField, LEIntField, ShortField
from scapy.packet import Packet

from peat.protocols.data_packing import (
    pack_dint,
    pack_int,
    pack_real,
    pack_sint,
    unpack_dint,
    unpack_int,
    unpack_real,
    unpack_sint,
)
from peat.protocols.enip.enip_packets import ENIP, EncapData

UNPACK_PCCC_DATA_FUNCTION: Final[dict[str, Callable]] = {
    "N": unpack_int,
    "B": unpack_int,
    "T": unpack_int,
    "C": unpack_int,
    "S": unpack_int,
    "F": unpack_real,
    "A": unpack_sint,
    "R": unpack_dint,
    "O": unpack_int,
    "I": unpack_int,
}

PACK_PCCC_DATA_FUNCTION: Final[dict[str, Callable]] = {
    "N": pack_int,
    "B": pack_int,
    "T": pack_int,
    "C": pack_int,
    "S": pack_int,
    "F": pack_real,
    "A": pack_sint,
    "R": pack_dint,
    "O": pack_int,
    "I": pack_int,
}


class PCCCoverCIP(Packet):
    name = "PCCCoverCIP"
    fields_desc = [
        ByteField("serviceCode", 0x4B),  # Execute PCCC
        ByteField("lengthReqPath", 0x02),
        IntField("reqPath", 0x20672401),  # 20,67(class,PCCC) 24,01(Instance 1)
        ByteField("lengthReqID", 0x07),
        ShortField("vendorID", 0x4D00),  # Allen Bradley vendor ID ???
        IntField("serialNum", 0x316AFB28),  # ML1100 serial num ???
        ByteField("pcccCmd", 0x0F),
        ByteField("sts", 0x00),  # 0x00 in req
        ShortField("tnsw", 0x4D18),  # Same value in req/res
        ByteField("pcccFnc", 0x17),  # Read physical bytes
        LEIntField("plcFwPhysAddr", 0x00008000),  # Starting address of firmware
        ByteField("readSize", 0xF8),
    ]


def generate_pccc_packet(pccc_cip_data: dict) -> ENIP:
    return ENIP(
        commandCode="SendRRData",
        data=bytes(EncapData(data=bytes(PCCCoverCIP(**pccc_cip_data)))),
    )


__all__ = [
    "PACK_PCCC_DATA_FUNCTION",
    "UNPACK_PCCC_DATA_FUNCTION",
    "PCCCoverCIP",
    "generate_pccc_packet",
]
