# NOTE(cegoes): Much of this was pulled from cip_const.py
# It could be necessary for CIP as well as ENIP

from typing import Final

from peat import CommError


class EnipCommError(CommError):
    pass


ENIP_ENCAP_PORT: Final[int] = 44818  # CIP
ENIP_SECURE_PORT: Final[int] = 2221  # ENIP Secure TLS/DTLS
ENIP_IO_PORT: Final[int] = 2222

ENIP_SEQ_MIN: Final[int] = 0
ENIP_SEQ_MAX: Final[int] = 65535

DATA_ITEM: Final[dict[str, bytes]] = {
    "Connected": b"\xb1\x00",
    "Unconnected": b"\xb2\x00",
}

ADDRESS_ITEM: Final[dict[str, bytes]] = {
    "Connection Based": b"\xa1\x00",
    "Null": b"\x00\x00",
    "UCMM": b"\x00\x00",
}

MR_SERVICE_SIZE: Final[int] = 2

PADDING_BYTE: Final[bytes] = b"\x00"
PRIORITY: Final[bytes] = b"\x0a"
TIMEOUT_TICKS: Final[bytes] = b"\xf9"
TIMEOUT_MULTIPLIER: Final[bytes] = b"\x00"  # b'\x01'
TRANSPORT_CLASS: Final[bytes] = b"\xa3"

HEADER_SIZE: Final[int] = 24
EXTENDED_SYMBOL: Final[bytes] = b"\x91"
BOOL_ONE: Final[int] = 0xFF
REQUEST_SERVICE: Final[int] = 0
REQUEST_PATH_SIZE: Final[int] = 1
REQUEST_PATH: Final[int] = 2
SUCCESS: Final[int] = 0
INSUFFICIENT_PACKETS: Final[int] = 6
OFFSET_MESSAGE_REQUEST: Final[int] = 40

CONNECTION_PARAMETER: Final[dict[str, int]] = {
    "PLC5": 0x4302,
    "SLC500": 0x4302,
    "CNET": 0x4320,
    "DHP": 0x4302,
    "Default": 0x43F4,  # 0x43f8,
}

CONNECTION_SIZE: Final[dict[str, bytes]] = {
    "Backplane": b"\x03",
    "Direct Network": b"\x02",
}  # CLX
