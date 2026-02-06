"""
Woodward proprietary Servlink serial protocol

SVL TCP

- ERROR RESPONSE: 0xE10000
- BAD/EMPTY RESPONSE: 0x0100020001

Authors

- Peter Shurtz
"""

import socket
import struct

from peat import log
from peat.protocols import pretty_hex_bytes, serial_txn

# Sequence bytes indexed by serial address
svl_seq_bytes = {}

SVL_SER_DEFAULT_DAT_DLM = b"\xf0"

SVL_TCP_DEFAULT_PORT = 666
SVL_TCP_DEFAULT_DAT_DLM = b"\x50"
SVL_TCP_DEFAULT_BUF_SIZE = 4096

svl_socket_cxns = {}  # type: dict[str, dict]

# Data type specifiers for data command parameters
svl_data_types = {
    str: {"mask": b"\x00", "len": 0},
    bytes: {"mask": b"\x00", "len": 0},
    bool: {"mask": b"\x01", "len": 3},
    float: {"mask": b"\x02", "len": 6},
    int: {"mask": b"\x04", "len": 6},
}

# System command bytes for _svlser_seq_txn()
svl_sys_cmds = {
    "Protocol": {"cmd": b"\x50", "type": str, "len": 0},  # System\\Protocol
    "System": {"cmd": b"\x51", "type": str, "len": 0},  # System\\System
    "Control": {"cmd": b"\x52", "type": str, "len": 0},  # System\\Control
    "Application": {"cmd": b"\x54", "type": str, "len": 0},  # System\\Application
    "Configuration": {"cmd": b"\x55", "type": str, "len": 0},  # Configuration
    "Product": {"cmd": b"\x57", "type": str, "len": 0},  # System\\Product
}

# Data command bytes for _svlser_seq_txn()
svl_dat_cmds = {
    "write": {"cmd": b"\x25"},
    "read": {"cmd": b"\x28"},
}


def _svlser_sys_txn(address: str, sys_cmd_itm: dict) -> dict:
    raw_bytes = _svlser_seq_txn(address, sys_cmd_itm["cmd"])
    return _svlser_parse_rsp(raw_bytes)


def _svlser_dat_txn(
    address: str,
    dat_cmd_itm: dict,
    type_bytes: bytes | None = None,
    delim: bytes | None = None,
) -> dict:
    raw_bytes = _svlser_seq_txn(address, _svlser_dat_fmt(dat_cmd_itm, type_bytes, delim))
    return _svlser_parse_rsp(raw_bytes)


def _svlser_seq_txn(address: str, wr_bytes: bytes) -> bytearray | None:
    """
    Send a sequential Servlink serial message.
    Also track the Servlink sequence.

    Args:
        address: The serial address
        wr_bytes: The data to write (data payload)
        rfmt: The expected response format
        rlen: The expected response length

    Returns:
        The parsed response
    """
    seq_bytes = _svlser_seq_fmt(address, wr_bytes)
    txn_bytes = _svlser_raw_txn(address, seq_bytes, False)

    if address in svl_seq_bytes and svl_seq_bytes[address] == b"\x21":
        svl_seq_bytes[address] = b"\x20"
    else:
        svl_seq_bytes[address] = b"\x21"

    return txn_bytes  # rsp


def _svlser_raw_txn(address: str, wr_bytes: bytes, reset: bool = False) -> bytearray | None:
    """
    Send a raw Servlink serial message.
    Optionally reset the Servlink sequence.

    Args:
        address: The serial address
        wr_bytes: The data to write (data payload)
        reset: Whether to reset the Servlink sequence

    Returns:
        The raw serial response
    """
    if reset:
        svl_seq_bytes[address] = b"\x21"

    svl_bytes = b"\x00\x00\x00"  # 3-char dead time
    svl_bytes += _svlser_raw_fmt(wr_bytes)
    svl_bytes += b"\x00\x00\x00"  # 3-char dead time

    return serial_txn(svl_bytes, address)


def _svlser_seq_fmt(address: str, cmd_bytes: bytes) -> bytes:
    """
    Apply Servlink sequence byte.
    """
    if address not in svl_seq_bytes:
        log.warning(f"Servlink sequence for {address} not initialized. Initializing...")
        # TODO: should this be SVLTCP_INIT_MSG? using SVLSER_INIT_MSG for now
        _svlser_raw_txn(address, b"\x60\x0f\xff", True)

    return svl_seq_bytes[address] + cmd_bytes


def _svlser_raw_fmt(wr_bytes: bytes) -> bytes:
    """
    Apply Servlink format.
    """
    # Start with initial byte (slave address?)
    svl_bytes = b"\x01"
    # Add content bytes. Sometimes a 0x10 needs to be inserted before and a
    # 0x20 ORed with one or more of these bytes (but NOT the initial 0x01 or
    # the 0x03 delimiter). The CRC must be calculated from the unmodified
    # bytes, so either they must be preserved or the CRC must be calculated
    # first.
    svl_bytes += _svlser_ins_1020(wr_bytes)
    # Add delimiter (?)
    svl_bytes += b"\x03"
    # Calculate the CRC from the unmodified content bytes.
    crc_bytes = _svlser_crc(wr_bytes)
    # Add CRC. Sometimes a similar process to insert a 0x10 before and to OR a
    # 0x20 with one or more bytes must be performed separately on the CRC.
    svl_bytes += _svlser_ins_1020(crc_bytes)

    return svl_bytes


def _svlser_dat_fmt(
    dat_cmd_itm: dict, type_bytes: bytes | None = None, delim: bytes | None = None
) -> bytes:
    # Start with command byte
    svl_bytes = svl_dat_cmds["read"]["cmd"]
    # Add byte composed of mask and type. Oddly, Python does not support
    # bitwise operations on bytes, so convert to int"s and back.
    mask_int = int.from_bytes(dat_cmd_itm["mask"], byteorder="big")
    if type_bytes is None:
        if dat_cmd_itm["type"] in svl_data_types:
            type_bytes = svl_data_types[dat_cmd_itm["type"]]["mask"]
        else:
            type_bytes = b"\x00"
    type_int = int.from_bytes(type_bytes, byteorder="big")
    svl_bytes += (mask_int | type_int).to_bytes(1, byteorder="big")
    # Add delimiter
    if delim is None:
        svl_bytes += SVL_SER_DEFAULT_DAT_DLM
    else:
        svl_bytes += delim
    # Add data address
    svl_bytes += dat_cmd_itm["addr"]

    return svl_bytes


def _svlser_parse_rsp(rd_bytes: bytes | None) -> dict:
    """Parse the Servlink response to transform it to the specified type.
    Multiple data fields are not yet implemented.

    Args:
        rd_bytes: The data to parse (raw response bytes)
        rfmt: The expected response format
        rlen: The expected response length. Use 0 to ignore length.

    Returns:
        The parsed response in the specified format
    """
    ser_rsp = {"hdr": None, "rbytes": None, "crc": None}

    if rd_bytes is None:
        return ser_rsp

    # Remove formatting bytes and get CRC
    if len(rd_bytes) >= 7 and rd_bytes[-4] == 3 and (rd_bytes[-3] == 16 or rd_bytes[-2] == 16):
        # Sometimes the CRC has a 0x10 inserted before and a 0x20 ORed with one
        # of the bytes of the CRC.
        #   0 - echoes byte 0 of command
        #   1 - echoes byte 1 of command
        #  -4 - 0x03 delimiter
        #  -3 - 0x10 or CRC first byte
        #  -2 - 0x10 or CRC first byte ORed with 0x20
        #  -1 - CRC second byte or CRC second byte ORed with 0x20
        calc_bytes = rd_bytes[1:-4]
        rd_crc = _svlser_rmv_1020(rd_bytes[-3:])
        log.trace3(f"0x1020 crc: {pretty_hex_bytes(rd_crc)}")
    elif len(rd_bytes) >= 6:
        # Normal response.
        #   0 - echoes byte 0 of command
        #   1 - echoes byte 1 of command
        #  -3 - 0x03 delimiter
        #  -2 - CRC first byte
        #  -1 - CRC second byte
        calc_bytes = rd_bytes[1:-3]
        rd_crc = rd_bytes[-2:]
    else:
        # Not enough bytes left - no data?
        log.trace3(f"No data found for {pretty_hex_bytes(rd_bytes)}")
        return ser_rsp

    ser_rsp["hdr"] = rd_bytes[0:2]
    ser_rsp["crc"] = rd_crc

    # Sometimes the data has a 0x10 inserted before and a 0x20 ORed with one or
    # more bytes of the data. For example, instead of looking like:
    #       0x 01 21 00 00 01 03 D8 CB
    # it looks like:
    #       0x 01 21 00 00 10 21 03 D8 CB
    # where the real data is "00 00 01", not "00 00 10 21" (the CRC agrees with
    # this as well).
    #
    # Remove 0x1020"s.
    calc_bytes = _svlser_rmv_1020(calc_bytes)  # for checking the CRC
    data_bytes = calc_bytes[1:]  # for everything else
    ser_rsp["rbytes"] = data_bytes

    # Check CRC
    calc_crc = _svlser_crc(calc_bytes)
    if calc_crc != rd_crc:
        log.debug(
            f"Unexpected CRC, expected {pretty_hex_bytes(rd_crc)}, "
            f"got {pretty_hex_bytes(calc_crc)} ({pretty_hex_bytes(calc_bytes)})"
        )

    return ser_rsp


def _svlser_ins_1020(in_bytes: bytes) -> bytearray:
    """
    Various parts of commands need to have a 0x10 inserted before and a 0x20
    ORed with one or more specific byte(s). Do that here.
    Use int's for bitwise
    operations.
    It seems like this is done whenever the following bytes are encountered in
    certain locations (NOT the initial 0x10 or the 0x03 delimiter):
        0x01, 0x03, 0x0D, 0x10, 0x11, 0x13
    """
    # Trigger on 0x01 -> 1, 0x03 -> 3, 0x0D -> 13, 0x10 -> 16, 0x11 -> 17, 0x13 -> 19
    trigger_bytes = [1, 3, 13, 16, 17, 19]

    out_bytes = bytearray()
    for b in in_bytes:
        if b in trigger_bytes:
            out_bytes += b"\x10"
            out_bytes += (b | 32).to_bytes(1, byteorder="big")  # 0x20 -> 32
        else:
            out_bytes += b.to_bytes(1, byteorder="big")

    if in_bytes != out_bytes:
        pretty_in = pretty_hex_bytes(in_bytes)
        pretty_out = pretty_hex_bytes(out_bytes)
        log.trace3(f"0x1020 ins: {pretty_in} -> {pretty_out}")

    return out_bytes


def _svlser_rmv_1020(data_bytes: bytes) -> bytes:
    """
    Various parts of received data have a 0x10 inserted before and a 0x20
    ORed with one or more specific byte(s). Remove those here.
    Use int's forbitwise operations.
    Right now since we don't know the actual criteria for 0x1020's, we'll
    assume that any real 0x10's would have been escaped this way, so any 0x10's
    we see with following byte >= 0x20 indicate a 0x1020 to be removed.
    """
    len_pre = len(data_bytes)
    pretty_pre = pretty_hex_bytes(data_bytes)
    i = 0
    while i < (len(data_bytes) - 1):
        if data_bytes[i] == 16 and data_bytes[i + 1] >= 32:  # 0x10 -> 16, 0x20 -> 32
            # Remove the 0x10 byte at index i
            del data_bytes[i]
            # The 0x20-ORed byte should now be at index i, un-OR it
            data_bytes[i] -= 32  # 0x20 -> 32
        i += 1

    if len(data_bytes) < len_pre:
        pretty_post = pretty_hex_bytes(data_bytes)
        log.trace3(f"0x1020 rmv: {pretty_pre} -> {pretty_post}")

    return data_bytes


def _svlser_crc(data_bytes: bytes) -> bytes:
    """
    Calculate Servlink CRC (little-endian CRC-16-MODBUS of the bytes
    between 0x01 and 0x03).
    Use int's so we can use bitwise operations.

    Args:
        data_bytes: The data bytes from which to calculate the CRC

    Returns:
        The two-byte CRC of data_bytes
    """
    crc = 65535  # 0xFFFF" -> 65535
    for i in range(len(data_bytes)):
        crc ^= data_bytes[i]
        for _j in range(8):
            if (crc & 1) != 0:  # 0x0001" -> 1
                crc >>= 1
                crc ^= 40961  # 0xA001" -> 40961
            else:
                crc >>= 1
    # byteorder="big" is the endianness of the Python int->byte conversion,
    # NOT the endianness of the CRC calculation!
    return crc.to_bytes(2, byteorder="big")


def _svltcp_sys_txn(ip: str, sys_cmd_itm: dict) -> dict:
    raw_bytes = _svltcp_raw_txn(ip, sys_cmd_itm["cmd"])
    return _svltcp_parse_rsp(raw_bytes)


def _svltcp_dat_txn(
    ip: str,
    dat_cmd_itm: dict,
    type_bytes: bytes | None = None,
    delim: bytes | None = None,
) -> dict:
    raw_bytes = _svltcp_raw_txn(ip, _svltcp_dat_fmt(dat_cmd_itm, type_bytes, delim))
    return _svltcp_parse_rsp(raw_bytes)


def _svltcp_raw_txn(ip: str, wr_bytes: bytes) -> bytes | None:
    return svl_socket_txn(ip, _svltcp_raw_fmt(wr_bytes))


def _svltcp_init(ip: str, wr_bytes: bytes) -> bytes:
    if not svl_socket_connected(ip):
        svl_socket_connect(ip)

    svl_socket_cxns[ip]["init"] = svl_socket_txn(ip, wr_bytes)

    return svl_socket_cxns[ip]["init"]


def svl_socket_txn(ip: str, wr_bytes: bytes) -> bytes | None:
    if not svl_socket_connected(ip):
        svl_socket_connect(ip)

    sock = svl_socket_cxns[ip]["sock"]
    try:
        log.trace3(f"WR {ip}: {pretty_hex_bytes(wr_bytes)}")
        sock.send(wr_bytes)
    except Exception as err:
        log.error(f"Error writing to Servlink/TCP on {ip}: {err}")

    rd_bytes = None
    try:
        rd_bytes = sock.recv(svl_socket_cxns[ip]["buf_size"])
        log.trace3(f"RD {ip}: {pretty_hex_bytes(rd_bytes)}")
    except Exception as err:
        log.error(f"Error reading from Servlink/TCP on {ip}: {err}")

    return rd_bytes


def svl_socket_connected(ip: str) -> bool:
    return (
        ip in svl_socket_cxns
        and "sock" in svl_socket_cxns[ip]
        and svl_socket_cxns[ip]["sock"] is not None
    )


def svl_socket_initialized(ip: str) -> bool:
    return (
        ip in svl_socket_cxns
        and "init" in svl_socket_cxns[ip]
        and svl_socket_cxns[ip]["init"] is not None
    )


def svl_socket_connect(
    ip: str,
    port: int | None = None,
    timeout: float | None = None,
    delim: bytes | None = None,
    bufsize: int | None = None,
) -> socket.socket | None:
    # Check whether already connected
    if svl_socket_connected(ip):
        log.error(f"Already connected to Servlink/TCP on {ip}")
        return None

    # Defaults
    if port is None:
        port = SVL_TCP_DEFAULT_PORT

    if timeout is None:
        timeout = 5

    if delim is None:
        svl_socket_cxns[ip] = {"dat_dlm": SVL_TCP_DEFAULT_DAT_DLM}
    else:
        svl_socket_cxns[ip] = {"dat_dlm": delim}

    if bufsize is None:
        svl_socket_cxns[ip] = {"buf_size": SVL_TCP_DEFAULT_BUF_SIZE}
    else:
        svl_socket_cxns[ip] = {"buf_size": bufsize}

    # Connect
    try:
        svl_socket_cxns[ip]["sock"] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        svl_socket_cxns[ip]["sock"].settimeout(timeout)
        svl_socket_cxns[ip]["sock"].connect((ip, port))
        return svl_socket_cxns[ip]["sock"]
    except Exception as err:
        log.error(f"Error connecting to Servlink/TCP on {ip}: {err}")
        svl_socket_disconnect(ip)
        return None


def svl_socket_disconnect(ip: str) -> None:
    if ip in svl_socket_cxns:
        if "sock" in svl_socket_cxns[ip] and svl_socket_cxns[ip]["sock"] is not None:
            try:
                svl_socket_cxns[ip]["sock"].close()
            except Exception as err:
                # Log, but give up - nothing else to do here
                log.error(f"Error disconnecting from Servlink/TCP on {ip}: {err}")
        del svl_socket_cxns[ip]


def _svltcp_dat_fmt(
    dat_cmd_itm: dict, type_bytes: bytes | None = None, delim: bytes | None = None
) -> bytes:
    # Start with command byte
    svl_bytes = svl_dat_cmds["read"]["cmd"]

    # Add byte composed of mask and type. Oddly, Python does not support
    # bitwise operations on bytes, so convert to int's and back.
    mask_int = int.from_bytes(dat_cmd_itm["mask"], byteorder="big")
    if type_bytes is None:
        if dat_cmd_itm["type"] in svl_data_types:
            type_bytes = svl_data_types[dat_cmd_itm["type"]]["mask"]
        else:
            type_bytes = b"\x00"

    type_int = int.from_bytes(type_bytes, byteorder="big")
    svl_bytes += (mask_int | type_int).to_bytes(1, byteorder="big")

    # Add delimiter
    if delim is None:
        svl_bytes += SVL_TCP_DEFAULT_DAT_DLM
    else:
        svl_bytes += delim

    # Add data address
    svl_bytes += dat_cmd_itm["addr"]

    return svl_bytes


def _svltcp_raw_fmt(wr_bytes: bytes) -> bytes:
    # Start with initial byte (slave address?)
    svl_bytes = b"\x01"

    # Add two-byte count of content bytes.
    svl_bytes += len(wr_bytes).to_bytes(2, byteorder="big")

    # Add content bytes.
    svl_bytes += wr_bytes

    return svl_bytes


def _svltcp_parse_rsp(rd_bytes: bytes | None) -> dict:
    tcp_rsp = {"hdr": None, "len": None, "rbytes": None}

    if rd_bytes is None:
        return tcp_rsp

    if len(rd_bytes) > 0:
        tcp_rsp["hdr"] = rd_bytes[0]

    if len(rd_bytes) > 2:
        tcp_rsp["len"] = rd_bytes[1:3]

    if len(rd_bytes) > 3:
        tcp_rsp["rbytes"] = rd_bytes[3:]

    return tcp_rsp


def _svl_parse_data(data_bytes: bytes, rfmt: type) -> str | int | bool | float | bytes:
    rlen = svl_data_types[rfmt]["len"]

    # Parse the data
    try:
        if rfmt is str:
            # check for pre/post 0x00"s
            if data_bytes[0] == 0 and data_bytes[-1] == 0:
                return data_bytes[1:-1].decode("utf-8", "replace").strip()
            return data_bytes.decode("utf-8", "replace").strip()
        elif rfmt is int and len(data_bytes) == rlen:
            return int.from_bytes(data_bytes, "big")
        elif rfmt is bool and len(data_bytes) == rlen:
            return int.from_bytes(data_bytes, "big") != 0
        elif rfmt is float and len(data_bytes) == rlen and len(data_bytes) > 4:
            # floats are 4 bytes
            return struct.unpack(">f", data_bytes[(rlen - 4) :])[0]
        elif rfmt is not bytes:
            # Working as designed, but log to debug. Fall through for bytes.
            log.debug(f"Unexpected format, expected {rfmt} for {pretty_hex_bytes(data_bytes)}")
    except Exception as ex:
        log.error(f"Error parsing response for {pretty_hex_bytes(data_bytes)}: {ex}")

    # If we didn"t return some other type, just return the bytes
    return pretty_hex_bytes(data_bytes)


__all__ = [
    "_svl_parse_data",
    "_svlser_dat_txn",
    "_svlser_raw_txn",
    "_svlser_sys_txn",
    "_svltcp_dat_txn",
    "_svltcp_init",
    "_svltcp_raw_txn",
    "_svltcp_sys_txn",
    "svl_dat_cmds",
    "svl_data_types",
    "svl_socket_connect",
    "svl_socket_disconnect",
    "svl_socket_initialized",
    "svl_sys_cmds",
]
