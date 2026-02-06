import os.path
import re
import socket
import subprocess
from collections import namedtuple
from functools import lru_cache
from typing import Final

# NOTE: the reason we use the manuf package instead of Scapy's conf.manufdb
#   is the manuf package bundles the manuf file in the package itself instead
#   of relying on it being on the system, as well as having a more robust parser.
# TODO (05/06/2024): scapy started bundling manuf in April 2024, maybe use that?
try:
    from manuf.manuf import MacParser as MacParserClass
except ImportError:
    MacParserClass = None
from scapy.packet import Packet

from peat import config, consts, log, state, utils

from .addresses import clean_mac

MAC_RE_COLON: Final[str] = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
MAC_RE_DASH: Final[str] = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
IPV4_RE: Final[str] = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
MANUF_PATH = None
MAC_PARSER = None

# Vendor tuple
# Manually define here instead of importing from manuf because manuf
# might not always be present.
Vendor = namedtuple("Vendor", ["manuf", "manuf_long", "comment"])


def scapy_human_field(obj: Packet, field: str) -> str:
    """
    Returns "human-friendly" version of a Packet field.
    """
    return obj.get_field(field).i2repr(obj, getattr(obj, field))


@lru_cache(maxsize=1024)
def mac_to_vendor(mac: str) -> Vendor | None:
    """
    Lookup the vendor using the :term:`OUI` of a MAC address.

    To update the manuf file bundled with peat:

    .. code-block:: shell

       # On Linux
       pdm run update-manuf-linux

       # On Windows
       pdm run update-manuf-windows

    Examples:

    .. code-block:: python

       >>> from peat.protocols.common import mac_to_vendor
       >>> mac_to_vendor("00:30:A7:00:00:01")
       Vendor(manuf='SchweitzerEn', manuf_long='Schweitzer Engineering', comment=None)
       >>> mac_to_vendor("00:16:3E:00:00:01")
       Vendor(manuf='Xensource', manuf_long='Xensource, Inc.', comment=None)
       >>> mac_to_vendor("B4:B1:5A:00:00:01")
       Vendor(manuf='SiemensEnerg', manuf_long='Siemens AG Energy Management Division', comment=None)
       >>> mac_to_vendor("a4:4c:c8:00:00:01")
       Vendor(manuf='Dell', manuf_long='Dell Inc.', comment=None)
       >>> mac_to_vendor("f8:59:71:00:00:01")
       Vendor(manuf='Intel', manuf_long='Intel Corporate', comment=None)
       >>> mac_to_vendor("00:50:56:00:00:01")
       Vendor(manuf='VMware', manuf_long='VMware, Inc.', comment=None)

    Args:
        mac: Colon-separated 48-bit (6-octet) MAC address to lookup

    Returns:
        Vendor information as a :class:`~collections.namedtuple`,
        or :obj:`None` if the lookup or the address failed (likely
        due to a malformed MAC address).
        The vendor object has 3 attributes:

        - ``manuf``
        - ``manuf_long``
        - ``comment``
    """  # noqa: E501
    if MacParserClass is None:
        log.warning(
            f"Failed OUI lookup for MAC address {mac}: the 'manuf' package is not installed"
        )
        return None

    global MAC_PARSER
    global MANUF_PATH

    if not MANUF_PATH:
        MANUF_PATH = utils.get_resource(__package__, "manuf")

    if not MAC_PARSER:
        if config.DEBUG >= 2:
            log.debug(f"manuf source: {MANUF_PATH}")
        MAC_PARSER = MacParserClass(manuf_name=MANUF_PATH, update=False)

    try:
        mac = clean_mac(mac)  # Cleanup address for lookup
        result = MAC_PARSER.get_all(mac)

        if not all(x is None for x in result):  # Every value will be None if lookup failed
            return result

        log.warning(f"OUI lookup failed for MAC address '{mac}'")
    except ValueError:
        log.exception(f"Failed to parse MAC address '{mac}' (likely malformed)")

    return None


@lru_cache(maxsize=1024)
def mac_to_vendor_string(mac: str) -> str:
    """
    Resolve a MAC address to a vendor string for use with "mac_vendor"
    field in data model. Simplified wrapper around ``mac_to_vendor()``.

    This will use long-form vendor name if resolved,
    and fallback to short form if there is no long form.

    Args:
        mac: Colon-separated 48-bit (6-octet) MAC address to lookup

    Returns:
        Vendor string, or empty string if lookup failed
    """
    if not mac or mac == "00:00:00:00:00:00":
        return ""

    try:
        vendor = mac_to_vendor(mac)
    except Exception:
        log.exception(f"exception resolving vendor for MAC address '{mac}'")
    else:
        if vendor and vendor.manuf_long:
            return vendor.manuf_long
        elif vendor and vendor.manuf:
            return vendor.manuf

    return ""


@lru_cache
def mac_to_ip(mac: str) -> str:
    """
    Lookup the IPv4 address for a MAC address.

    On Linux (and OSX), the local ARP cache is searched (``/proc/net/arp``).
    On Windows, ``arp.exe`` is used.

    Args:
        mac: MAC address of the device, colon-separated

    Returns:
        IPv4 address (dotted-decimal), or an empty string
        if the IP address could not be determined
    """
    if not mac:
        return ""

    log.trace(f"Getting IP address for {mac}")

    if not isinstance(mac, str) or ":" not in mac:
        log.critical(f"Invalid MAC address passed to mac_to_ip: {mac}")
        state.error = True
        return ""

    try:
        mac = mac.lower()
        if consts.WSL or consts.WINDOWS:
            ip = _get_ip_from_mac_arpexe(mac)
        elif consts.POSIX:
            ip = _search_arptable(IPV4_RE + r".*" + re.escape(mac))
        else:
            log.error("Failed mac_to_ip: unsupported platform")
            return ""
    except Exception as ex:
        log.warning(f"Could not get IP address for MAC '{mac}': {ex}")
        return ""

    if not ip:
        log.debug(f"Failed to find IPv4 address for MAC '{mac}'")

    return ip


@lru_cache
def ip_to_mac(ip: str) -> str:
    """
    Resolve the MAC address for a IPv4 address.

    On Linux (and OSX), the local :term:`ARP` cache is searched (``/proc/net/arp``).
    On Windows, Scapy is used, with ``arp.exe`` used as a fallback.

    .. warning::
       On Windows, this may result in a :term:`ARP` request being made on the
       local subnet if the PEAT configuration option ``RESOLVE_MAC`` is True.

    Args:
        ip: IPv4 address of the device (Note: this cannot be a hostname!)

    Returns:
        MAC address as a colon-delimited string, or an empty string
        if the MAC address could not be determined
    """
    if not ip:
        return ""

    if ip in ["0.0.0.0", "127.0.0.1"]:
        return ""

    log.trace(f"Getting MAC address for {ip}")

    if not isinstance(ip, str) or "." not in ip:
        log.critical(f"Invalid IPv4 address passed to ip_to_mac: {ip}")
        state.error = True
        return ""

    try:
        if consts.WSL:
            mac_address = _get_mac_from_ip_arpexe(ip)
        elif consts.POSIX:
            mac_address = _search_arptable(re.escape(ip) + r".*" + MAC_RE_COLON)
        elif consts.WINDOWS:
            mac_address = ""

            # Use Scapy getmacbyip() to send a ARP request to resolve the MAC,
            # if RESOLVE_MAC configuration option is enabled.
            #
            # Scapy getmacbyip() does not inherently require any special permissions on Windows.
            # On POSIX systems, however, it requires root permissions.
            #
            # cegoes, 09/20/2024:
            #   on Windows, scapy may need Administrator anyway to be able to
            #   determine the default route and send a ARP request.
            if config.RESOLVE_MAC:
                if config.DEBUG >= 3:
                    log.debug(f"Using Scapy getmacbyip() to get MAC for {ip}")

                # import here to avoid triggering a scapy import unless it's needed (slow)
                from scapy.layers.l2 import getmacbyip

                res: str | tuple[str, float] = getmacbyip(ip)

                # Handle weird edge case where Scapy will sometimes return
                # a tuple when running as Administrator on Windows.
                mac_address: str | None = res[0] if isinstance(res, tuple) else res
                if mac_address is None:
                    mac_address = ""

                # 09/20/2024:
                #   If scapy isn't able to determine default route, it may
                #   return "ff:ff:ff:ff:ff:ff" as the MAC address.
                #
                # Scapy will sometimes return a zero MAC address.
                if mac_address and mac_address.upper() in [
                    "00:00:00:00:00:00",
                    "FF:FF:FF:FF:FF:FF",
                ]:
                    mac_address = ""

            # Fall back to Windows arp.exe if Scapy fails or ARP lookups disabled
            if not mac_address:
                mac_address = _get_mac_from_ip_arpexe(ip)
        else:
            log.error("Failed ip_to_mac: unsupported platform")
            return ""
    except Exception as ex:
        log.warning(f"Could not get MAC address for {ip} due to an error: {ex}")
        return ""

    # Ensure we return an empty string on failures
    if mac_address is None or mac_address == "00:00:00:00:00:00":
        mac_address = ""

    # MAC was not found
    if mac_address == "":
        log.debug(f"Failed to find MAC address for {ip}")
    # If a MAC was found, convert it to upper-case
    elif isinstance(mac_address, str):
        mac_address = clean_mac(mac_address)
    else:
        log.warning(
            f"Failed to get MAC address for {ip}: invalid type "
            f"'{type(mac_address).__name__}' for MAC address {mac_address}"
        )
        mac_address = ""

    return mac_address


# TODO: do a timed cache for the ARP table lookups.
# https://cachetools.readthedocs.io/en/latest/#cachetools.TTLCache
#
# Currently, if there are 300 IPs being searched for, the ARP file is read
# 300 times, which is really inefficient. Instead, we should
# cache the result and expire it after 15 seconds or so.
# ARP tables usually refresh every 30 or 60 seconds anyway.
#
# This is even more pronounced on Windows, because it's running
# a subprocess vs just reading a file.
def _search_arptable(regex: str) -> str:
    """
    Search ``/proc/net/arp`` for an address (IP or MAC) using a regex.
    """
    if config.DEBUG >= 3:
        log.debug(f"Searching /proc/net/arp using regex: '{regex}'")

    if not os.path.exists("/proc/net/arp"):
        log.error(
            "Failed arp table lookup: /proc/net/arp does not exist, "
            "your platform is abnormal or unsupported"
        )
        return ""

    with open("/proc/net/arp") as arpfile:
        arp_table = arpfile.read()

    if not arp_table:
        log.error("No data in /proc/net/arp")
        return ""

    # Update ARP table in state for debugging purposes
    state.arp_table = arp_table

    # IP address       HW type     Flags       HW address            Mask     Device
    # 192.0.2.1        0x1         0x2         00:00:00:00:00:01     *        ens33
    matched = re.search(regex, arp_table)
    if matched is not None:
        return matched.groups()[0]

    if config.DEBUG >= 3:
        log.debug(f"Failed to search /proc/net/arp using '{regex}'")

    return ""


def _get_ip_from_mac_arpexe(mac: str) -> str:
    """
    Lookup IP from a MAC using arp.exe on Windows.
    """
    if config.DEBUG >= 3:
        log.debug(f"Running 'arp.exe -a' to find IP for {mac}")

    arp_output = _get_arpexe_output()
    if arp_output:
        regex = IPV4_RE + r".*" + re.escape(mac.replace(":", "-"))
        m = re.search(regex, arp_output)
        if m and m.groups():
            return m.groups()[0]

    log.debug(f"Failed to get IP using 'arp.exe -a' for {mac}")
    return ""


def _get_mac_from_ip_arpexe(ip: str) -> str:
    """
    Lookup MAC from a IP using arp.exe on Windows.
    """
    if config.DEBUG >= 3:
        log.debug(f"Running 'arp.exe -a' to find find MAC for IP {ip}")

    arp_output = _get_arpexe_output()
    if arp_output:
        m = re.search(MAC_RE_DASH, arp_output)
        if m and m.groups():
            return m.groups()[0].replace("-", ":")

    log.debug(f"Failed to get MAC using 'arp.exe -a' for {ip}")
    return ""


def _get_arpexe_output() -> str:
    # Interface: 192.168.215.1 --- 0x13
    #   Internet Address      Physical Address      Type
    #   224.0.0.22            00-00-00-00-00-01     static
    #   224.0.0.251           00-00-00-00-00-02     static
    #   239.255.255.250       00-00-00-00-00-03     static
    proc = subprocess.run(["arp.exe", "-a"], stdout=subprocess.PIPE, check=False)

    if proc.returncode == 0 and proc.stdout:
        arp_output = proc.stdout.decode()
        state.arp_table = arp_output
        return arp_output

    if config.DEBUG >= 3:
        log.debug(f"** arp.exe failed, proc object dump below **\n{proc}")

    return ""


def raw_socket_capable() -> bool:
    """
    Determines if PEAT has permissions to use RAW sockets (``SOCK_RAW``).
    """
    try:
        if consts.LINUX:
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        else:
            socket.socket(socket.AF_INET, socket.SOCK_RAW)
    except OSError:
        log.debug("Unable to use RAW sockets")
        return False
    except Exception as ex:
        log.warning(
            "Unknown exception occurred while checking raw socket "
            "capabilities. You might be on an unsupported platform."
        )
        log.debug(str(ex))
        return False
    else:
        return True


__all__ = [
    "ip_to_mac",
    "mac_to_ip",
    "mac_to_vendor",
    "mac_to_vendor_string",
    "raw_socket_capable",
]
