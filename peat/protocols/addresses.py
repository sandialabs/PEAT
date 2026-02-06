import itertools
import json
import re
import socket
from functools import lru_cache
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    _BaseV4,
    ip_address,
    ip_network,
)
from pathlib import Path

from peat import ParseError, log, state

ADDR_RANGE_REGEX = re.compile(
    r"((\d{1,3}|\d{1,3}-\d{1,3})"
    r"\.(\d{1,3}|\d{1,3}-\d{1,3})"
    r"\.(\d{1,3}|\d{1,3}-\d{1,3})"
    r"\.(\d{1,3}|\d{1,3}-\d{1,3}))",
    re.IGNORECASE | re.ASCII,
)


def address_to_pathname(address: str) -> str:
    """
    Converts a address or other host identifier to a suitable filepath name.
    """
    return address.strip().lower().replace("/", "_").replace(" ", "_")


@lru_cache(maxsize=2048)
def resolve_hostname_to_ip(hostname: str) -> str:
    if not hostname:
        return ""

    if hostname == "localhost":
        return "127.0.0.1"

    try:
        return socket.gethostbyname(hostname)
    except OSError as ex:
        log.debug(f"Failed to resolve hostname '{hostname}': {ex}")
        return ""


@lru_cache(maxsize=1024)
def resolve_ip_to_hostname(ip: str) -> str:
    if not ip:
        return ""

    if ip == "127.0.0.1":
        return "localhost"

    if ip == "0.0.0.0":
        return ""

    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, IndexError) as ex:
        log.debug(f"Failed to resolve IP '{ip}': {ex}")
        return ""


def expand_commas_and_clean_strings(
    host_list: list[str | bytes | IPv4Address | IPv4Network | Path],
) -> list[str | bytes | IPv4Address | IPv4Network | Path]:
    """
    Expand strings with ',' characters into separate items, convert bytes
    to str, and remove items that are only whitespace or empty strings.
    """
    expanded = []

    for item in host_list:
        if isinstance(item, (bytes, str)):
            # Convert bytes to str
            if isinstance(item, bytes):
                item = item.decode()

            item = item.strip()
            if not item:
                continue

            # Expand strings with commas in them
            if "," in item:
                for sub_item in item.strip().split(","):
                    sub_item = sub_item.strip()
                    if sub_item:
                        expanded.append(sub_item)
                continue

        expanded.append(item)

    return expanded


def expand_filenames_to_hosts(
    host_list: list[str | bytes | IPv4Address | IPv4Network | Path],
) -> list[str | bytes | IPv4Address | IPv4Network]:
    """
    Read host data from any hosts that are filenames, and remove them from the list.
    """
    expanded = []

    for list_item in host_list:
        is_path = False

        if isinstance(list_item, (bytes, str, Path)):
            # ensure byte conversion to check filename doesn't affect source data
            to_test = list_item

            if isinstance(to_test, bytes):
                to_test = to_test.decode()

            # Ensure filenames don't get included in list of hosts
            # if the file doesn't exist
            if isinstance(to_test, str) and (
                to_test.endswith(".txt") or to_test.endswith(".json")
            ):
                is_path = True

            try:
                if isinstance(to_test, Path):
                    pth = to_test.resolve()
                else:
                    pth = Path(to_test).resolve()

                if pth.is_file():
                    log.info(f"Reading hosts from file {pth.as_posix()}")
                    is_path = True
                    file_text = pth.read_text(encoding="utf-8")

                    if pth.suffix == ".json":
                        # Note: this assumes JSON data is a list
                        raw_data = json.loads(file_text)
                    else:
                        # text data can be space, tab, or newline delimited
                        raw_data = file_text.split()

                    data = [str(x).strip() for x in raw_data if x]
                    expanded.extend(data)
                    log.info(f"{len(data)} hosts were read from file {pth.name}")
                elif pth.exists():
                    log.error(f"Host file '{str(pth)}' exists but isn't a valid file")
                    state.error = True
            except Exception:
                log.exception(
                    f"unknown error occurred while checking if hosts "
                    f"are filepaths, host_list={host_list}"
                )
                state.error = True

        if not is_path and not isinstance(list_item, Path):
            expanded.append(list_item)

    return expanded


def hosts_to_ips(
    host_list: list[str | bytes | IPv4Address | IPv4Network],
) -> list[str]:
    """
    Converts a list of mixed host strings to a list of unique IPv4 addresses.

    The mixed host strings can consist of IPv4 addresses in "dotted-decimal"
    format, IPv4 subnets in :term:`CIDR` notation, Nmap-style IPv4 address
    ranges, Nmap-style IPv4 network ranges, combinations of ranges, hostnames,
    and domain names (e.g. a :term:`FQDN`).

    If a file or set of files is specified, they will be read and the hosts
    will be added to the list of hosts to parse. Host strings in files can be
    space, tab, or newline-separated.  Basically, PEAT will call ``.split()``
    on whatever is in the file. JSON files will be loaded as JSON and
    treated as an array of strings.

    Hostnames and domain names will be resolved into IPv4 addresses, and
    duplicate, malformed, or invalid addresses will be removed.

    Examples

    - ``localhost``         (Hostname)
    - ``docs.python.org``   (Domain name)
    - ``192.0.2.23``        (Standard dotted-decimal IPv4 address)
    - ``192.0.2.0/24``      (:term:`CIDR`-specified subnet)
    - ``192.0.2.20-40``     (Nmap-style host range)
    - ``192.0.2-3.0``     (Nmap-style network range)
    - ``192.0.2-9.14-17``   (Combination of network and host ranges)
    - ``172-192.16-30.80-90.12-14`` (Multiple combinations)
    - ``targets.txt``       (Text file with hosts)
    - ``hosts.json``        (JSON file with array of hosts)
    - ``192.0.2.20,192.0.2.30`` (Comma-separated hosts)

    .. warning::
       Valid addresses that are not generally used, such as multicast or
       reserved address spaces, will result in warnings emitted to logging
       and will still be returned in the list of results.

    Args:
        host_list: Mixed host strings to convert. These can include
            IPv4 address strings (dotted-decimal notation), hostnames,
            subnets (:term:`CIDR` notation), Nmap-style host address
            ranges, and/or :mod:`ipaddress` objects
            (:class:`~ipaddress.IPv4Address`/:class:`~ipaddress.IPv4Network`).

    Returns:
        List of unique dotted-decimal IPv4 address strings
    """
    if not isinstance(host_list, list):
        log.error(f"Expected a list of hosts, got '{type(host_list).__name__}'")
        state.error = True
        return []

    # note: assumes someone isn't trying to pass a filename with a ',' in it
    commas_expanded = expand_commas_and_clean_strings(host_list)
    expanded_hosts = expand_filenames_to_hosts(commas_expanded)
    ipaddress_objects = hosts_to_objs(expanded_hosts)
    string_addresses = ip_objs_to_ips(ipaddress_objects)

    return string_addresses


def hosts_to_objs(
    host_list: list[str | bytes | IPv4Address | IPv4Network],
) -> list[_BaseV4]:
    """
    Converts a list of mixed host strings into :mod:`ipaddress` objects.

    Args:
        host_list: Mixed host strings to convert (refer to
            :func:`~peat.protocols.addresses.hosts_to_ips` for details)

    Returns:
        List of :mod:`ipaddress` objects (:class:`~ipaddress.IPv4Address`
        and :class:`~ipaddress.IPv4Network`)
    """
    log.trace(f"Converting {len(host_list)} hosts into ipaddress objects")

    # Use a set to prevent duplicates
    obj_set = set()  # type: set[_BaseV4]

    for host in host_list:
        # If it's already an object, just add it
        if isinstance(host, (IPv4Address, IPv4Network)):
            obj_set.add(host)
        elif isinstance(host, (str, bytes)):
            if host == "all":
                continue

            try:
                ip_obj = host_string_to_objs(host)

                if isinstance(ip_obj, (set, list)):
                    obj_set.update(ip_obj)
                else:
                    obj_set.add(ip_obj)
            except (ValueError, AddressValueError, OSError, socket.gaierror) as err:
                log.warning(f"Failed to process host string '{host}', skipping...")
                log.debug(f"Error that occurred for host string '{host}': {err}")
        else:
            log.critical(
                f"Cannot convert '{repr(host)}' to an IP address, "
                f"invalid type '{type(host).__name__}'"
            )
            state.error = True

    log.trace(f"Converted {len(host_list)} host strings into {len(obj_set)} ipaddress objects")

    return list(obj_set)  # Convert set to list


def host_string_to_objs(
    host_string: str | bytes, strict_network: bool = True
) -> _BaseV4 | set[IPv4Address]:
    """
    Converts a mixed host string into :mod:`ipaddress` object(s).

    .. code-block:: python
       :caption: Examples converting strings to IPv4Address objects

       >>> from pprint import pprint
       >>> from peat.protocols.addresses import host_string_to_objs
       >>> pprint(host_string_to_objs("192.168.2-3.142-144"))
       {IPv4Address('192.168.2.142'),
        IPv4Address('192.168.2.143'),
        IPv4Address('192.168.2.144'),
        IPv4Address('192.168.3.142'),
        IPv4Address('192.168.3.143'),
        IPv4Address('192.168.3.144')}
       >>> pprint(host_string_to_objs("192.168.3.140-142"))
       {IPv4Address('192.168.3.140'),
        IPv4Address('192.168.3.141'),
        IPv4Address('192.168.3.142')}
       >>> host_string_to_objs("172.16.0.0/30")
       IPv4Network('172.16.0.0/30')
       >>> host_string_to_objs("localhost")
       IPv4Address('127.0.0.1')
       >>> host_string_to_objs(b"192.168.3.1")
       IPv4Address('192.168.3.1')

    .. warning::
       The IP range parsing isn't robust and can match bogus
       values like ``999.353.23-35.22`` or ```000-000.999-999.-1.0``

    Args:
        host_string: Host string to convert (refer to
            :func:`~peat.protocols.addresses.hosts_to_ips` for details)
        strict_network: If network parsing is strict, in other words host bits
            being set in a network address will result in an error if this
            is :obj:`True`.

    Returns:
        Either a single instance or :class:`set` of :mod:`ipaddress` objects
        (:class:`~ipaddress.IPv4Address` and :class:`~ipaddress.IPv4Network`)
    """
    # Convert bytes to str
    if isinstance(host_string, bytes):
        host_string = host_string.decode()

    # Strip excess whitespace
    host = host_string.strip().replace(" ", "")

    # Process as a network/subnet
    #   Example: 192.0.2.0/24
    if host.count("/") == 1 and host.count(".") == 3:
        return ip_network(host, strict=strict_network)

    # Process as a range of dotted-decimal IPv4 addresses
    match = None
    groups = ()
    # '-' is checked first to short-circuit and skip matching for the
    # common case (e.g. not a range).
    if "-" in host and host.count(".") == 3:
        # NOTE: technically this will match bogus values like "999.353.23-35.22"
        match = ADDR_RANGE_REGEX.fullmatch(host)
        if match:
            groups = match.groups()

    # If there's a '-' and it matched the regex, then it's definitely an IP range
    # Group 1:   "192.0.2-3.140-150"
    # Group 2-5: "192", "168", "2-3", "140-150"
    if match and groups and len(groups) == 5 and "-" in groups[0]:
        # This bit is somewhat complicated...
        # Essentially, we carve the string into 4 octets,
        # then convert each of those octets into a iterable.
        # The iterables are then passed to itertools.product().
        processed_octets = []
        range_encountered = False

        for i, octet in enumerate(groups[1:]):
            if "-" in octet:
                # 140-145 => range(140, 146) (Python's range() needs +1)
                start, end = octet.split("-")
                processed_octets.append(range(int(start), int(end) + 1))
                range_encountered = True
            elif octet == "0" and range_encountered and i != 3:
                # Any zero-octet occurring after a range is encountered
                # is converted to a list of 256 integers (0 to 255).
                # We assume they are all valid hosts since subnet
                # information is not provided.
                processed_octets.append(range(256))  # .0 - .255
            elif octet == "0" and range_encountered and i == 3:
                # Exclude subnet and broadcast from the final zero-set
                processed_octets.append(range(1, 254))  # .1 - .254
            else:
                # Since strings are interpreted as iterables by product(),
                # we convert them to an integer and make a 1-element list.
                processed_octets.append([int(octet)])

        # Extract addresses from the range
        addr_set = set()
        for addr_tuple in itertools.product(*processed_octets):
            addr_string = ".".join(str(t) for t in addr_tuple)
            addr_set.add(ip_address(addr_string))

        return addr_set

    # We've eliminated subnets and address ranges, so it's likely a single host
    try:
        # Attempt to parse as an IP address
        ip = ip_address(host)
    except ValueError:
        # If it's not a valid IP, let's try and see if it's a hostname.
        # If it's a hostname or FQDN, the address will be resolved
        # and returned as a string. Then we create a IPv4 address
        # object as normal.
        resolved_address = socket.gethostbyname(host)
        ip = ip_address(resolved_address)

    # Warn about host address classes that are likely not valid
    for attr in ["is_multicast", "is_unspecified", "is_reserved", "is_link_local"]:
        if getattr(ip, attr) is True:
            log.warning(f"IP {str(ip)} {attr.replace('_', ' ')}")

    return ip


def ip_objs_to_ips(ip_obj_list: list[_BaseV4]) -> list[str]:
    """
    Converts :mod:`ipaddress` objects to unique IPv4 address strings.

    Args:
        ip_obj_list: :mod:`ipaddress` objects to convert

    Returns:
        Sorted list of unique IPv4 address strings

    Raises:
        ParseError: One of the objects is not a :mod:`ipaddress` object instance
    """
    address_set = set()  # type: set[str]

    for ip_obj in ip_obj_list:
        if isinstance(ip_obj, IPv4Address):
            # str() cast converts IPAddress object to a unicode string
            address_set.add(str(ip_obj))
        elif isinstance(ip_obj, IPv4Network):
            # Get all the valid hosts in the subnet
            for ip in ip_obj.hosts():
                address_set.add(str(ip))
        else:
            raise ParseError(f"Invalid IP object type: {type(ip_obj).__name__}")

    log.trace(
        f"Converted {len(ip_obj_list)} ipaddress objects "
        f"into {len(address_set)} IPv4 address strings"
    )

    return sort_ips(address_set)  # Convert set to list and sort before returning


@lru_cache
def ip_is_local_interface(ip: str) -> bool:
    """
    Checks if a IP matches any of the local machine's :term:`NIC` IPs.

    Args:
        ip: IPv4 address string to check

    Returns:
        If the IP matches that of a network interface on the local machine
    """
    for interface in state.local_interface_objects:
        if str(interface.ip) == ip:
            return True
    return False


@lru_cache(maxsize=1024)
def ip_in_local_subnet(ip: str | IPv4Address) -> bool:
    """
    Checks if a IP is in any of the locally connected subnets.

    .. note::
       This function does NOT check that a host actually exists! It only
       asserts that an address mathematically falls into the range of
       local subnets connected to the system running PEAT.

    Args:
        ip: IPv4 address string to check

    Returns:
        If the address is in a locally connected network
    """
    if not isinstance(ip, IPv4Address):
        ip = IPv4Address(ip)

    for local_network in state.local_networks:  # type: IPv4Network
        if ip in local_network:
            return True

    return False


@lru_cache
def network_is_local(net: IPv4Network) -> bool:
    """
    Checks if a network address space is a subset of a local subnet.

    This checks to see if the network fits partially into or is equal to
    any of the subnets connected to the local system.

    Args:
        net: IPv4 network to check

    Returns:
        If the network address space fits in a local subnet
    """
    return any(net.subnet_of(local) for local in state.local_networks)


def sort_ips(ip_list: list[str] | set[str]) -> list[str]:
    """
    Sort IPv4 address strings in ascending order by integer IPs.
    """
    return sorted(ip_list, key=lambda x: socket.inet_pton(socket.AF_INET, x))


@lru_cache
def split_ipv4_cidr(addr: str) -> tuple[str, str]:
    """
    Convert subnet mask from :term:`CIDR` bits to full dotted-decimal.

    Args:
        addr: IPv4 address with :term:`CIDR` subnet, e.g. ``172.16.0.20/24``

    Returns:
        Tuple with the host IPv4 address (``172.16.0.20``) and
        dotted-decimal subnet mask (``255.255.255.0``)
    """
    return addr.partition("/")[0], str(IPv4Network(addr, strict=False).netmask)


def clean_ipv4(addr: str) -> str:
    """
    Strip leading zeros from a IPv4 address e.g. 192.000.002.004 => 192.0.2.4
    """
    if not addr:
        return ""
    return ".".join(str(int(x)) for x in addr.split("."))


def clean_mac(mac: str) -> str:
    """
    Clean and format MAC address strings.
    """
    if not mac or not mac.strip():
        return ""

    # Replace Windows-style '-' characters with ':'
    if "-" in mac:
        mac = mac.replace("-", ":")
    mac = mac.strip().upper()

    # Fill in missing characters
    if len(mac) != 17:
        new_mac = []
        for part in mac.split(":"):
            if len(part) == 0:  # fill in missing zeroes
                new_mac.append("00")
            elif len(part) == 1:  # add leading zero
                new_mac.append(f"0{part}")
            else:
                new_mac.append(part)
        mac = ":".join(new_mac)

    return mac


__all__ = [
    "address_to_pathname",
    "clean_ipv4",
    "clean_mac",
    "expand_commas_and_clean_strings",
    "expand_filenames_to_hosts",
    "host_string_to_objs",
    "hosts_to_ips",
    "hosts_to_objs",
    "ip_in_local_subnet",
    "ip_is_local_interface",
    "ip_objs_to_ips",
    "network_is_local",
    "resolve_hostname_to_ip",
    "resolve_ip_to_hostname",
    "sort_ips",
    "split_ipv4_cidr",
]
