import struct
from typing import Final
from collections.abc import Callable

# NOTE(cegoes): keep an eye on str/bytes conversion here


# 'b' is signed character
def pack_sint(n: int) -> bytes:
    return struct.pack("b", n)


# 'B' is unsigned character
def pack_usint(n: int) -> bytes:
    return struct.pack("B", n)


# 'h' is short, '<' is little endian, size is 2
def pack_int(n: int) -> bytes:
    """Pack 16 bit into 2 bytes little endian."""
    return struct.pack("<h", n)


# 'H' is unsigned short, '<' is little endian, size is 2
def pack_uint(n: int) -> bytes:
    """Pack 16 bit into 2 bytes little endian."""
    return struct.pack("<H", n)


# 'i' is int, '<' is little endian, size is 4
def pack_dint(n: int) -> bytes:
    """Pack 32 bit into 4 bytes little endian."""
    return struct.pack("<i", n)


# 'f' is IEEE 754 binary32, float, '<' is little endian, size is 4
def pack_real(r: float) -> bytes:
    """Pack 4 bytes little endian to :class:`int`."""
    return struct.pack("<f", r)


def unpack_bool(st: bytes) -> int:
    if int(struct.unpack("B", st[0])[0]) == 255:
        return 1
    return 0


def unpack_sint(st: bytes) -> int:
    return int(struct.unpack("b", st)[0])


def unpack_usint(st: bytes) -> int:
    return int(struct.unpack("B", st)[0])


def unpack_int(st: bytes) -> int:
    """Unpack 2 bytes little endian to :class:`int`."""
    return int(struct.unpack("<h", st[0:2])[0])


def unpack_uint(st: bytes) -> int:
    """Unpack 2 bytes little endian to :class:`int`."""
    return int(struct.unpack("<H", st[0:2])[0])


def unpack_dint(st: bytes) -> int:
    """Unpack 4 bytes little endian to :class:`int`."""
    return int(struct.unpack("<i", st[0:4])[0])


def unpack_real(st: bytes) -> float:
    """Unpack 4 bytes little endian to :class:`float`."""
    return float(struct.unpack("<f", st[0:4])[0])


def unpack_lint(st: bytes) -> int:
    """Unpack 4 bytes little endian to :class:`int`."""
    return int(struct.unpack("<q", st[0:8])[0])


UNPACK_DATA_FUNCTION: Final[dict[str, Callable]] = {
    "BOOL": unpack_bool,
    "SINT": unpack_sint,  # Signed 8-bit integer
    "INT": unpack_int,  # Signed 16-bit integer
    "UINT": unpack_uint,  # Unsigned 16-bit integer
    "DINT": unpack_dint,  # Signed 32-bit integer
    "REAL": unpack_real,  # 32-bit floating point,
    "LINT": unpack_lint,
    "BYTE": unpack_sint,  # byte string 8-bits
    "WORD": unpack_uint,  # byte string 16-bits
    "DWORD": unpack_dint,  # byte string 32-bits
    "LWORD": unpack_lint,  # byte string 64-bits
}


DATA_FUNCTION_SIZE: Final[dict[str, int]] = {
    "BOOL": 1,
    "SINT": 1,  # Signed 8-bit integer
    "INT": 2,  # Signed 16-bit integer
    "UINT": 2,  # Unsigned 16-bit integer
    "DINT": 4,  # Signed 32-bit integer
    "REAL": 4,  # 32-bit floating point
    "LINT": 8,
    "BYTE": 1,  # byte string 8-bits
    "WORD": 2,  # byte string 16-bits
    "DWORD": 4,  # byte string 32-bits
    "LWORD": 8,  # byte string 64-bits
}
