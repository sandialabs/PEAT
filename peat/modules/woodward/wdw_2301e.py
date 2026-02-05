"""Woodward 2301e Speed Controller.

Services

- Servlink (Woodward proprietary protocol) on RS232 and RS422
- Modbus (optional) on RS232 and RS422

Authors

- Peter Shurtz
"""

import struct
from pathlib import Path
from typing import Any

from peat import DeviceData, DeviceModule, Interface, SerialMethod, datastore, log
from peat.protocols import open_serial_port, pretty_hex_bytes, serial_txn

from .wdw_2301e_svl import *

# TODO: remove '*' imports
from .wdw_svl import *
from .wdw_tc import *

# Track the Servlink sequence
svl_seq_odd = True

# "Magic" bytes for Servlink "hello" for _servlink_raw_txn()
SVL_HELLO_ACK = b"\x01\x60\x10\x21\x00\x80\x00\x80\x03\x33\x34"

# Data type specifiers for Servlink
# This is probably not 2301E-specific
# TODO: are these old?
svl_data_type = {
    bool: b"\x81",
    float: b"\x82",
    int: b"\x84",
    bytes: b"\xd4",
}


class WDW2301E(DeviceModule):
    """Woodward 2301e Speed Controller."""

    device_type = "Controller"
    vendor_id = "Woodward"
    vendor_name = "Woodward, Inc"
    brand = "WDW"
    model = "2301E"
    filename_patterns = [
        "*.wset"
    ]  # TODO: should wset and tc parsing belong here or 3500XT?
    # TODO: combine some common functions of 3500XT and 2301E?
    woodward_fallback_baudrates = [9600]

    @classmethod
    def _verify_serial(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a 2301E via the Woodward-proprietary Servlink
        protocol over a serial connection.
        """
        baudrates = dev.options["baudrates"]
        if not baudrates:
            baudrates = cls.woodward_fallback_baudrates
        timeout = dev.options["servlink_serial"]["timeout"]

        for baudrate in baudrates:
            if (
                open_serial_port(dev.serial_port, baudrate, timeout)
                and _servlink_hello_txn(dev.serial_port) == SVL_HELLO_ACK
                and "2301e"
                in str(
                    _servlink_sys_txn(svl_sys_cmds["Product"], dev.serial_port)
                ).lower()
            ):
                cls.log.debug(f"Verified {dev.serial_port} (baudrate: {baudrate})")
                iface = Interface(
                    connected=True,
                    type="rs_232",  # TODO: detect serial interface type
                    serial_port=dev.serial_port,
                    baudrate=baudrate,
                    parity="none",
                    stop_bits=1,
                    flow_control="none",
                )
                dev.store("interface", iface, lookup="serial_port")
                return True

        cls.log.warning(f"Failed to verify {dev.serial_port} (baudrates: {baudrates})")
        return False

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        serial_info = cls._get_serial_data(dev.serial_port)
        if not serial_info:
            return False

        dev.extra.update(serial_info)
        dev.write_file(serial_info, "pulled-config.json")
        return True

    @classmethod
    def _get_serial_data(cls, address: str) -> dict[str, str]:
        """Get the system information and configuration using Servlink serial.
        It is assumed that the serial connection has been opened and the
        Servlink sequence has been reset previously e.g. in identify_serial.

        Args:
            address: The serial address

        Returns:
            A dictionary containing the system information
        """
        cls.log.info(f"Pulling Serial information from {address}...")
        serial_info: dict[str, Any] = {"system": {}, "config": {}}

        # Get the system information
        for k in svl_sys_cmds.keys():
            cls.log.debug(f"Pulling System\\{k}")
            serial_info["system"][k] = _servlink_sys_txn(svl_sys_cmds[k], address)
            cls.log.trace2(f"{k} = \"{serial_info['system'][k]}\"")

        # Get the configuration
        # TODO: should this only be the keys that start with "CfgA\\"?
        for a in svl_dat_prms.keys():
            cls.log.debug(f"Pulling {a}")
            serial_info["config"][a] = _servlink_rw_txn(
                svl_dat_cmds["read"], svl_dat_prms[a], address
            )
            cls.log.trace2(f"{a} = \"{serial_info['config'][a]}\"")

        cls.log.info(f"Finished pulling Serial information from {address}")
        return serial_info

    @classmethod
    def _parse(
        cls, file: Path, dev: DeviceData | None = None
    ) -> DeviceData | None:
        to_parse = file.read_bytes()
        # TODO: detect 2301E wset file
        try:
            tc_file_text = to_parse.decode()  # NOTE(cegoes): this may be iso8859-1
            parsed_config = _parse_tc_file(tc_file_text)
        except Exception as ex:
            cls.log.exception(f"Critical parsing error: {ex}")
            return None
        # TODO: this is a temporary hack since we currently don't have examples of 2301E files

        if parsed_config:
            if not dev:
                dev = datastore.get(file.stem, "id")
            dev.extra.update(parsed_config)
            cls.update_dev(dev)
            dev.write_file(parsed_config, "parsed-config.json")
            return dev
        else:
            cls.log.warning("No project parsed")
            return None


WDW2301E.serial_methods = [
    SerialMethod(
        name="wdw2301e_servlink_serial",
        description=str(WDW2301E._verify_serial.__doc__).strip(),
        type="direct",
        identify_function=WDW2301E._verify_serial,
        reliability=3,
    )
]


# TODO: this is in separate file now?
# This is likely not 2301E-specific
def _parse_tc_file(project: str) -> dict:
    """Parse a *.tc device logic file.

    Args:
        project: The .tc file prepared by parse_project

    Returns:
        A dictionary containing the device logic
    """
    if not isinstance(project, str):
        log.error(f"Project type error: {type(project)!s}")
        return {}

    bad_lines = 0
    parsed_logic = {}
    lines = project.strip().split("\r\n")

    file_ver_line = lines.pop(0)
    fw_prefix_line = lines.pop(0)
    fw_date_line = lines.pop(0)
    header_line = lines.pop(0)
    if (
        "File Version" in file_ver_line
        and "-" in fw_prefix_line
        and "UTC" in fw_date_line
        and len(header_line.split("\t")) == 9
        and header_line.startswith("Mode")
    ):
        parsed_logic["file_version"] = file_ver_line
        parsed_logic["firmware_prefix"] = fw_prefix_line
        parsed_logic["firmware_date"] = fw_date_line
    else:
        log.warning("Unknown tc logic format")
        return {}

    parsed_logic["logic"] = {}
    for line in lines:
        fields = line.split("\t")
        if not len(fields) == 9:
            log.debug(f"Malformed line: '{line}'")
            bad_lines += 1
            continue

        # Build Mode, Category, Block Name, and Field Name organization,
        # then populate with Type, Current, Initial, Low, and High
        ref = parsed_logic["logic"]
        # Walk through each layer of the organization
        for n in range(4):
            if fields[n] not in ref:
                ref[fields[n]] = {}  # create a new layer if necessary
            ref = ref[fields[n]]  # walk to the next layer
        # Now populate the top layer
        ref["Type"] = fields[4]
        ref["Current"] = fields[5]
        ref["Initial"] = fields[6]
        ref["Low"] = fields[7]
        ref["High"] = fields[8]

    if bad_lines > 0:
        log.warning(f"Skipped {bad_lines} malformed lines")

    return parsed_logic


# Not sure if this is 2301E-specific
def _servlink_hello_txn(address: str):
    return _servlink_raw_txn(SVLSER_INIT_MSG, address, True)


# Not sure if this is 2301E-specific
def _servlink_sys_txn(sys_dict: dict, address: str):
    return _servlink_seq_txn(sys_dict["cmd"], address, sys_dict["type"])


# Not sure if this is 2301E-specific
def _servlink_rw_txn(
    rw_dict: dict, addr_dict: dict, address: str
):  # only one addr for now
    rw_bytes = _servlink_rw_fmt(rw_dict["cmd"], [addr_dict])
    return _servlink_seq_txn(rw_bytes, address, addr_dict["type"])


# Not sure if this is 2301E-specific
def _servlink_seq_txn(
    cmd_bytes: bytes, address: str, fmt: "type | None" = None, options: bool = False
):
    """Send a sequential Servlink serial message. Also track the Servlink
    sequence.

    Args:
        cmd_bytes: The data to write (data payload)
        address: The serial address
        fmt: The desired response type
        options: The options

    Returns:
        The parsed response
    """
    seq_bytes = _servlink_seq_fmt(cmd_bytes)
    txn_bytes = _servlink_raw_txn(seq_bytes, address, options)
    rsp = _servlink_rsp_trns(txn_bytes, fmt)

    global svl_seq_odd
    svl_seq_odd = not svl_seq_odd

    return rsp


# Not sure if this is 2301E-specific
def _servlink_raw_txn(wr_bytes: bytes, address: str, reset: bool = False):
    """Send a raw Servlink serial message. Optionally reset the Servlink
    sequence.

    Args:
        wr_bytes: The data to write (data payload)
        address: The serial address
        reset: Whether to reset the Servlink sequence

    Returns:
        The raw serial response
    """
    global svl_seq_odd
    if reset:
        svl_seq_odd = True

    svl_bytes = b"\x00\x00\x00"  # 3-char dead time
    svl_bytes += _servlink_raw_fmt(wr_bytes)
    svl_bytes += b"\x00\x00\x00"  # 3-char dead time

    return serial_txn(svl_bytes, address)


# Not sure if this is 2301E-specific
def _servlink_seq_fmt(cmd_bytes: bytes) -> bytes:
    """Apply Servlink sequence byte"""
    if svl_seq_odd:
        seq = b"\x21"
    else:
        seq = b"\x20"

    return seq + cmd_bytes


# Not sure if this is 2301E-specific
def _servlink_raw_fmt(wr_bytes: bytes) -> bytes:
    """Apply Servlink format"""
    svl_bytes = b"\x01"  # slave address?
    svl_bytes += wr_bytes
    svl_bytes += b"\x03"  # delimiter?
    # TODO: need to inject 0x10 0x20 sometimes, just not sure when
    svl_bytes += _servlink_crc(wr_bytes)

    return svl_bytes


# Not sure if this is 2301E-specific
def _servlink_rw_fmt(cmd_byte: bytes, addrs: list) -> bytes:
    """Compose Servlink R/W commands. Multiple address specifiers per command
    are allowed, but parsing the reply is not implemented in
    _servlink_rsp_trns() yet, so you'll just get back bytes.
    """
    svl_bytes = cmd_byte
    for d in addrs:
        svl_bytes += svl_data_type[d["type"]]
        svl_bytes += b"\xf0\x09"  # ?
        svl_bytes += d["addr"]

    return svl_bytes


# Not sure if this is 2301E-specific
def _servlink_rsp_trns(rd_bytes: bytes, fmt: "type") -> str:
    """Parse the Servlink response to transform it to the specified type.
    Multi-address responses are not yet implemented.

    Args:
        rd_bytes: The data to parse (raw response bytes)
        fmt: The desired response type

    Returns:
        The parsed response in the specified type
    """
    # Remove formatting bytes
    if len(rd_bytes) >= 7 and rd_bytes[-3] == 16 and rd_bytes[-4] == 3:
        # Sometimes the checksum has a 0x10 inserted before and a 0x20 ORed
        # with the MSB of the data. Note that this works just like, but is NOT
        # the same as, the 0x10 0x20 occurrence in the data described below.
        # Discard these bytes with the "normal" Servlink format bytes for now.
        #   0 - echoes byte 0 of command
        #   1 - echoes byte 1 of command
        #  -4 - 0x03 - delimiter?
        #  -3 - 0x10 - ?
        #  -2 - checksum first byte ORed with 0x20?
        #  -1 - checksum second byte
        data_bytes = rd_bytes[2:-4]
    elif len(rd_bytes) >= 6:
        # Normal response, discard Servlink format bytes for now.
        #   0 - echoes byte 0 of command
        #   1 - echoes byte 1 of command
        #  -3 - always 0x03 - delimiter?
        #  -2 - checksum first byte
        #  -1 - checksum second byte
        data_bytes = rd_bytes[2:-3]
    else:
        # Not enough bytes left! No data?
        return ""

    # Sometimes the data has a 0x10 inserted before and a 0x20 ORed with the
    # MSB of the data. For example, instead of looking like:
    #       0x 01 21 00 00 01 03 D8 CB
    # it looks like:
    #       0x 01 21 00 00 10 21 03 D8 CB
    # where the real data is "00 00 01", not "00 00 10 21" (the checksum agrees
    # with this as well).
    # This is currently detected by length, since each data type has an
    # expected length. It COULD be checked for when the CRC doesn't match, but
    # that starts to get muddy...
    # Note that this works just like, but is NOT the same as, the 0x10 0x20
    # occurrence in the checksum described above.
    #
    # Remove these "extra" values.
    if (fmt is int and len(data_bytes) == 7) or (fmt is bool and len(data_bytes) == 4):
        # Find the first non-zero byte, this should be the extra 0x10
        nz = next((i for i, x in enumerate(data_bytes) if x), None)
        # Remove the byte at index nz
        del data_bytes[nz]
        # The 0x20-ORed byte should now be at index nz, un-OR it
        data_bytes[nz] -= 32

    # Parse the data
    try:
        if fmt is str:
            if data_bytes[0] == 0 and data_bytes[-1] == 0:
                # strip pre/post 0x00's if any
                data_bytes = data_bytes[1:-1]
            return data_bytes.decode("utf-8", "replace").strip()
        elif fmt is int and len(data_bytes) == 6:
            return int.from_bytes(data_bytes, "big")
        elif fmt is bool and len(data_bytes) == 3:
            return int.from_bytes(data_bytes, "big") != 0
        elif (
            fmt is float
            and len(data_bytes) == 6
            and data_bytes[0] == 0
            and data_bytes[1] == 0
        ):  # we get back 6 bytes but floats are 4
            return struct.unpack(">f", data_bytes[2:])[0]
        elif fmt is not bytes:
            # Working as designed, but log to debug
            log.debug(
                f"Unmatched response type for {fmt} {pretty_hex_bytes(data_bytes)}"
            )
    except Exception as ex:
        log.error(f"Error parsing response for {pretty_hex_bytes(data_bytes)}: {ex}")

    # If we didn't return some other type, just return the bytes
    return pretty_hex_bytes(data_bytes)


# Not sure if this is 2301E-specific
def _servlink_crc(data_bytes: bytes):
    """Calculate Servlink CRC (little-endian CRC-16-MODBUS of the bytes
    between 0x01 and 0x03). Use int's so we can use bitwise operations.

    Args:
        data_bytes: The data bytes to checksum

    Returns:
        The two-byte checksum of data_bytes
    """
    crc = 65535  # 0xFFFF' -> 65535
    for i in range(len(data_bytes)):
        crc ^= data_bytes[i]
        for _j in range(8):
            if (crc & 1) != 0:  # 0x0001' -> 1
                crc >>= 1
                crc ^= 40961  # 0xA001' -> 40961
            else:
                crc >>= 1
    # byteorder='big' is the endianness of the Python int->byte conversion,
    # NOT the endianness of the checksum calculation!
    return crc.to_bytes(2, byteorder="big")


__all__ = ["WDW2301E"]
