import bisect
import time
from typing import Final

import serial
from serial.tools import list_ports

from peat import config, consts, log, state, utils

# Serial port connections if open, or None if not, keyed by address strings
serial_cxns = {}

# List of standardized baud rates
std_b: Final[list[int]] = [
    50,
    75,
    110,
    134,
    150,
    200,
    300,
    600,
    1200,
    1800,
    2400,
    4800,
    9600,
    19200,
    38400,
    57600,
    115200,
]


def find_serial_ports(filter_list: list[str] | None = None) -> list[str]:
    """
    Find host serial ports enumerated by the operating system.
    Filter by specified list, if any.
    """
    log.info(f"Searching for active serial ports... (filter_list: {filter_list})")

    try:
        listed_ports = [port.device for port in list_ports.comports()]
    except Exception as ex:
        log.warning(f"Failed to scan for serial ports: {ex}")
        return []

    if not listed_ports:
        log.warning("No serial ports on host")
        return []

    if filter_list is None:
        filter_list = listed_ports

    listed_ports.sort()
    active_port_set = set()

    for serial_port in list(set(filter_list) & set(listed_ports)):
        try:
            log.info(f"Trying serial port {serial_port}")

            # Don't bother with parameters, just see if it opens
            ser = serial.Serial(port=serial_port)
            if ser.isOpen():
                active_port_set.add(serial_port)
                log.info(f"Found active serial port: {serial_port}")
                ser.close()
        except serial.SerialException as ex:
            handle_scan_serial_exception(serial_port, ex)
        except OSError:
            log.warning(f"Hardware error accessing port {serial_port}, aborting")
            return []
        except Exception as ex:
            log.warning(f"Unknown error accessing port {serial_port}: {ex}")

    return sorted(active_port_set)


def open_serial_port(address: str, baudrate: int, timeout: float) -> bool:
    """
    Open the specified serial port.

    Since the code where the connection should be closed may not be
    able to communicate with the code where it needs to be opened,
    just be robust about closing and re-opening the connection.

    Args:
        address: The address string of the port to close
        baudrate: The baud rate
        timeout: The timeout in seconds

    Returns:
        :obj:`True` if the port is opened successfully, :obj:`False` otherwise
    """
    log.info(f"Attempting to open serial port {address} at baudrate {baudrate}")
    close_serial_port(address)

    try:
        serial_cxns[address] = serial.Serial(
            port=address,
            baudrate=baudrate,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=timeout,
            write_timeout=timeout,
        )
        if serial_cxns[address].isOpen():
            log.info(f"Opened serial port {address} at {baudrate} baud")
            return True
        else:
            log.debug(f"Couldn't open serial port {address} at baud {baudrate}")
    except serial.SerialException as ex:
        raise ex
    except Exception as ex:
        log.debug(f"Error opening serial port {address} at baud {baudrate}: {ex}")

    return False


def close_serial_port(address: str) -> bool:
    """
    Close the specified serial port.
    Handle closing an un-opened port gracefully.

    Args:
        address: The address string of the port to close

    Returns:
        :obj:`True` if the port is closed successfully, :obj:`False` otherwise
    """
    if address not in serial_cxns or serial_cxns[address] is None:
        return True

    if not serial_cxns[address].isOpen():
        serial_cxns[address] = None
        return True

    try:
        serial_cxns[address].close()
        serial_cxns[address] = None
        return True
    except Exception as ex:
        log.error(f"Error closing serial port {address}: {ex}")

    return False


def port_nums_to_addresses(port_values: list[str]) -> list[str]:
    """
    Converts a list of mixed port value strings to a list of unique serial
    port address strings.

    .. code-block:: python

       >>> import platform
       >>> from peat.protocols.serial import port_nums_to_addresses
       >>> platform.system()  # doctest: +SKIP
       'Linux'
       >>> port_nums_to_addresses(["0-1", "0", "1-1"])  # doctest: +SKIP
       ['/dev/ttyS0', '/dev/ttyS1', '/dev/ttyUSB0', '/dev/ttyUSB1']
       >>> port_nums_to_addresses(["/dev/ttyS0", "/dev/ttyUSB0"])  # doctest: +SKIP
       ['/dev/ttyS0', '/dev/ttyUSB0']

    Args:
        port_values: Mixed port number or dash-separated range strings to convert

    Returns:
        Sorted :class:`list` of unique platform-specific serial port address strings
    """
    if not isinstance(port_values, list):
        log.critical(f"Expected a list of serial port values, got '{type(port_values).__name__}'")
        state.error = True
        return []

    port_addr_set = set()
    try:
        for value in port_values:
            v = value.strip().split("-")
            if len(v) == 1 and isint(v[0]):
                # single number - convert to port string(s) and add to set
                port_addr_set.update(platform_port_fmt(int(v[0])))
            elif len(v) == 1 and ("/" in v[0] or "COM" in v[0]):
                # platform-specific port string, e.g. /dev/ttyS0 or COM0
                port_addr_set.add(v[0].strip())
            elif len(v) == 2 and isint(v[0]) and isint(v[1]) and int(v[0]) <= int(v[1]):
                # ascending range - convert each number in it and add to set
                for i in range(int(v[0]), int(v[1]) + 1):
                    port_addr_set.update(platform_port_fmt(i))
            else:
                log.warning(f"Unable to parse port value: {value}")
    except OSError as err:
        log.error(f"Failed to convert serial port strings: {err}")
        return []

    sorted_ports = sorted(port_addr_set)
    log.info(
        f"Converted {len(port_values)} strings to {len(sorted_ports)} "
        f"platform-specific serial ports"
    )
    log.trace(
        f"Converted {len(port_values)} serial port strings"
        f"\nInput: {port_values}\nOutput: {sorted_ports}"
    )

    return sorted_ports


def platform_port_fmt(num: int) -> list[str]:
    """
    Formats an integer into a platform-specific serial port address string.

    Args:
        num: An integer to format into a platform-specific serial port string

    Returns:
        A list of platform-specific serial port strings
    """
    pnum = abs(num)
    if consts.POSIX:
        return [
            f"/dev/ttyS{pnum}",
            f"/dev/ttyUSB{pnum}",
            f"/dev/ttyACM{pnum}",
        ]
    elif consts.WINDOWS:
        return [f"COM{pnum}"]
    else:
        raise OSError("serial port parsing not supported on this platform")


def isint(s: str) -> bool:
    """
    If a string is a valid :class:`int`.
    """
    try:
        int(s)
        return True
    except ValueError:
        return False


def parse_baudrates(baudrate_values: list[str]) -> list[int]:
    """
    Converts a list of mixed baud rate value strings to a list of
    standardized baud rates with duplicates removed.

    .. code-block:: python

       >>> from peat.protocols.serial import parse_baudrates
       >>> parse_baudrates(["9600"])
       [9600]
       >>> parse_baudrates(["9600-115200"])
       [9600, 19200, 38400, 57600, 115200]
       >>> parse_baudrates(["9600-115200", "57600"])
       [9600, 19200, 38400, 57600, 115200]

    Args:
        baudrate_values: Mixed baud rate number or dash-separated
            range strings to convert

    Returns:
        A :class:`list` of unique standardized baud rate integers sorted in
            reverse order (highest to lowest)
    """
    # TODO: generalize and deduplicate the core logic between parse_baudrates
    #   and port_nums_to_addresses, they're doing basically the same thing
    #   with slightly different calls.
    if not isinstance(baudrate_values, list):
        log.critical(
            f"Expected a list of baud rate values, got '{type(baudrate_values).__name__}'"
        )
        state.error = True
        return []

    baudrate_set = set()
    for value in baudrate_values:
        v = value.strip().split("-")
        if len(v) == 1 and isint(v[0]):
            # single number - standardize and add to set
            baudrate_set.add(std_b[std_b_idx(int(v[0]))])
        elif len(v) == 2 and isint(v[0]) and isint(v[1]) and int(v[0]) <= int(v[1]):
            # ascending range - add lowest and highest rates and any in between
            for i in range(std_b_idx(int(v[0])), std_b_idx(int(v[1])) + 1):
                baudrate_set.add(std_b[i])
        else:
            log.warning(f"Unable to parse baud rate: {value}")

    return sorted(baudrate_set)


def std_b_idx(baudrate: int) -> int:
    """
    Convert an arbitrary integer to the appropriate ``std_b`` index.
    """
    if baudrate >= std_b[-1]:
        return len(std_b) - 1

    return bisect.bisect_right(std_b, baudrate) - 1


def serial_txn(wr_bytes: bytes, address: str) -> bytearray | None:
    """
    Performs a serial transaction (writes and then reads).

    Args:
        wr_bytes: The :class:`bytes` to write
        address: The serial port string (``/dev/ttyS1``, ``COM1``, etc)

    Returns:
        The :class:`bytearray` that was read, if any
    """
    if serial_write(wr_bytes, address) >= 0:
        time.sleep(0.5)
        return serial_read(address)
    return None


def serial_write(wr_bytes: bytes, address: str) -> int:
    """
    Writes bytes to an open serial port.

    Args:
        wr_bytes: The :class:`bytes` to write
        address: The serial port string (``/dev/ttyS1``, ``COM1``, etc)

    Returns:
        The number of :class:`bytes` written, or ``-1`` if there was an error
    """
    if address not in serial_cxns or not serial_cxns[address].isOpen():
        log.error(f"Error writing to serial port {address}: port not open")
        return -1

    try:
        serial_cxns[address].reset_input_buffer()
        serial_cxns[address].reset_output_buffer()

        br = serial_cxns[address].baudrate

        if config.DEBUG >= 3:
            log.trace3(f"Writing to {address} @ {br} baud: {pretty_hex_bytes(wr_bytes)}")

        num_written = serial_cxns[address].write(wr_bytes)

        if config.DEBUG >= 3:
            log.trace3(f"Wrote {num_written} bytes to {address} @ {br} baud")

        num_expected = len(wr_bytes)
        if num_written != num_expected:
            log.warning(
                f"Incomplete write to {address} @ {br} baud, expected "
                f"{num_expected} bytes, wrote {num_written} bytes"
            )

        serial_cxns[address].flush()

        return num_written
    except Exception as ex:
        log.error(f"Error writing to serial port {address}: {ex}")

    return -1


def serial_read(address: str) -> bytearray | None:
    """
    Reads bytes from an open serial port.

    Args:
        address: The serial port string (``/dev/ttyS1``, ``COM1``, etc)

    Returns:
        The :class:`bytearray` that was read, including an empty array if
        nothing was read but there were no errors, or :obj:`None` if there were errors
    """
    if address not in serial_cxns or not serial_cxns[address].isOpen():
        log.error(f"Error reading from serial port {address}: port not open")
        return None

    try:
        rd_bytes = bytearray()

        while serial_cxns[address].in_waiting > 0:
            rd_bytes.extend(serial_cxns[address].read())
            time.sleep(0.01)

        if config.DEBUG >= 2:
            br = serial_cxns[address].baudrate
            log.trace2(
                f"Read {len(rd_bytes)} bytes from {address} @ {br} baud: "
                f"{pretty_hex_bytes(rd_bytes)}"
            )

        return rd_bytes
    except Exception as ex:
        log.error(f"Error reading from serial port {address}: {ex}")


def pretty_hex_bytes(b: bytearray | bytes) -> str:
    if not b:
        return "0x None"
    return "0x " + " ".join([f"{x:02X}" for x in bytes(b)])


def handle_scan_serial_exception(port: str, ex: Exception) -> bool:
    """
    Handle pyserial's ``serial.SerialException`` instances.

    Returns:
        :obj:`True` if the exception is regular, :obj:`False` if it's related to
        the port being in use by another program or the port not
        existing on the host.
    """
    ex_str = str(ex).lower()
    is_regular = False

    # PermissionError(13, 'Access is denied.', None, 5)
    if "access is denied" in ex_str or "permissionerror(13" in ex_str:
        # TODO: Linux?
        msg = (
            "the port is unable to be opened due to a permission issue. "
            "Make sure no other programs are currently using the serial "
            "port, such as PuTTY or SEL Quickset. The Process Explorer tool "
            "(part of Microsoft SysInternals) can be used to see what "
            "processes are using a serial port."
        )

        # If we're admin, then mark port as active and note about assumption
        # we're making. Otherwise, it's an error.
        if utils.are_we_superuser():
            log.warning(
                f"Note: {msg} -- since PEAT is running as Administrator "
                f"and the port is in use, it is being marked as active."
            )
            is_regular = True
        else:
            log.error(f"Failed to scan serial port {port}: {msg}")
    # Windows: "FileNotFoundError(2, 'The system cannot find the file specified.', None, 2)"
    # Linux: "[Errno 2] No such file or directory: '/dev/ttyUSB4'"
    elif "filenotfounderror" in ex_str or "no such file or directory" in ex_str:
        log.warning(
            f"Failed to scan serial port {port}: the port either isn't connected or doesn't exist"
        )
    else:
        log.warning(f"Unknown SerialException on {port}: {ex}")
        is_regular = True

    return is_regular


__all__ = [
    "close_serial_port",
    "find_serial_ports",
    "handle_scan_serial_exception",
    "open_serial_port",
    "parse_baudrates",
    "port_nums_to_addresses",
    "pretty_hex_bytes",
    "serial_read",
    "serial_txn",
    "serial_write",
]
