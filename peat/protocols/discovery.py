"""
Discovery of hosts on a Ethernet network (commonly called "scanning").

**Raw Sockets**

Several functions require the use of raw sockets. On Linux, these require
either root permissions, or the ``cap_net_raw`` capability applied to the
Python interpreter. On Windows, the program must be running with Administrator
permissions, usually from an elevated command prompt.

Further reading about getting raw socket permissions on Linux

- https://stackoverflow.com/a/27059188
- https://stackoverflow.com/a/47982075
- https://stackoverflow.com/a/30826137
- https://gist.github.com/tomix86/32394a43be70c337cbf1e0c0a56cbd8d
- http://man7.org/linux/man-pages/man7/capabilities.7.html
"""

import timeit
from collections.abc import Iterable
from concurrent import futures

from scapy.all import RandShort, sr1
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import arping

from peat import config, log, state, utils

from .addresses import ip_in_local_subnet, ip_is_local_interface, sort_ips
from .ip import check_tcp_port


def check_host(
    ip: str, timeout: float = 1.0, icmp_fallback_tcp_syn: bool | None = None
) -> bool:
    """
    Checks if a network host is online.

    .. note::
       Requests to ``127.0.0.1`` will always return :obj:`True`

    Args:
        ip: IPv4 address of host
        timeout: Number of seconds to wait for a response
        icmp_fallback_tcp_syn: In the case of a :term:`ICMP` failure, fallback to
            attempting a TCP SYN RST to check if the host is online.
            The edge case is this: if we are able to use raw sockets and
            the host is NOT in a local subnet, then ICMP requests will be used.
            Certain devices (such as the SEL RTAC) and many firewalls drop
            ICMP requests. We still want to check if the host is online,
            therefore we use TCP as a fallback. If the device is sensitive
            to TCP RST's, then this argument should be set to :obj:`False`. The
            TCP port used is configured by the ``SYN_PORT`` PEAT configuration
            option (e.g. ``export PEAT_SYN_PORT=80``).

    Returns:
        If the host is online
    """
    if icmp_fallback_tcp_syn is None:
        icmp_fallback_tcp_syn = config.ICMP_FALLBACK_TCP_SYN

    # Minor hack to skip ARP/ICMP check for quick testing using localhost
    if ip == "127.0.0.1":
        log.debug("Skipping online check of 127.0.0.1 since it's localhost")
        return True

    # If it's actually a local interface, skip
    if ip_is_local_interface(ip):
        log.debug(
            f"Skipping online check of {ip} since it's "
            f"an interface on the local system"
        )
        return False

    # If we're able to use raw sockets, try using better methods
    if not config.FORCE_ONLINE_METHOD_TCP and (
        config.FORCE_ONLINE_METHOD_PING or state.raw_socket_capable
    ):
        # Use ARP if IP is in a local subnet (lightest and safest)
        if ip_in_local_subnet(ip):
            return check_host_arp(ip, timeout)
        # Otherwise, use pings (ICMP requests)
        else:
            remote_result = check_host_icmp(ip, timeout)
            # Fallback to TCP SYN-RST if ICMP check fails and flag is enabled
            if not remote_result and icmp_fallback_tcp_syn:
                remote_result = check_tcp_port(
                    ip, config.SYN_PORT, timeout, reset=True, syn_sweep=True
                )
            return remote_result

    # Fallback to the old unsafe and noisy TCP SYN sweep method
    log.trace3(f"Falling back to TCP SYN online check for {ip}")
    return check_tcp_port(ip, config.SYN_PORT, timeout, reset=True, syn_sweep=True)


def check_host_arp(ip: str, timeout: float = 1.0):
    """
    Check if a host is online using :term:`ARP` ``who-has`` requests.

    .. note::
       This function requires the ability to use raw sockets.

    Example ``tcpdump`` output of lookups for ``192.0.2.200`` and ``192.0.2.201``:

    .. code-block::

        ARP, Request who-has 192.0.2.200 tell 192.0.2.20, length 28
        ARP, Request who-has 192.0.2.201 tell 192.0.2.20, length 28
        ARP, Reply 192.0.2.200 is-at 00:00:00:00:00:00, length 46
        ARP, Reply 192.0.2.201 is-at 00:00:00:00:00:01, length 46

    Args:
        ip: IPv4 address of host
        timeout: Number of seconds to wait for a response

    Returns:
        If the host is online
    """
    if config.DEBUG >= 3:
        log.debug(f"Using ARP to check {ip} (timeout: {timeout})")

    try:
        # This will automatically use the proper interface for the who-has
        # request even if the network being queried isn't on the default
        # interface.
        answers = arping(ip, verbose=0, timeout=timeout, cache=True)[0]
        if answers is not None and len(answers) >= 1:
            log.trace2(f"ARP check of {ip} succeeded")
            return True
    except OSError:
        log.debug(f"Lacking system permissions to send ARP request to {ip}")
    except Exception:
        log.exception(f"failed to arping {ip}")

    return False


def check_host_icmp(ip: str, timeout: float = 1.0):
    """
    Check if a host is online using an :term:`ICMP` request (``ping``).

    .. note::
       This function requires the ability to use raw sockets.

    Pings can be accomplished without raw sockets via the ``ping``
    command. However, calling a system command is extremely costly,
    and would result in dramatically increased scanning times.
    Therefore, the use of raw sockets is preferred to ensure the
    check finishes in a reasonable amount of time.

    Args:
        ip: IPv4 address of host
        timeout: Number of seconds to wait for a response

    Returns:
        If the host is online
    """
    if config.DEBUG >= 3:
        log.debug(f"Using ICMP to check {ip} (timeout: {timeout})")

    # Setting ID fields prevents some filtering by routers and firewalls
    packet = IP(dst=ip, id=int(RandShort())) / ICMP(id=int(RandShort()))
    result = None

    try:
        # sr1 = "Send/Receive 1"
        result = sr1(packet, timeout=timeout, verbose=0)
    except OSError:
        log.debug(f"Lacking system permissions to send ICMP request to {ip}")
    except Exception:
        log.exception(f"failed to send ICMP request to {ip}")

    if result:
        code = result.getlayer(ICMP).code
        if code == 0:
            log.trace2(f"ICMP check of {ip} succeeded")
            return True

        log.trace2(
            f"ICMP request to {ip} failed with code {code} (timeout: {timeout:.2f})"
        )

    return False


def check_host_syn_sweep(ip: str, ports: list[int], timeout: float = 1.0) -> bool:
    """
    Checks if a host is online using TCP SYN requests to a range of ports.

    TCP SYN requests are sent to the specified ports, and if the device
    responds in any way, it is considered to be "online".

    Args:
        ip: IPv4 address of host
        ports: TCP ports to check
        timeout: Number of seconds to wait for a response

    Returns:
        If the host is online
    """
    if config.DEBUG >= 3:
        log.debug(f"Using TCP SYNs to check {ip} (timeout: {timeout})")

    for port in ports:
        try:
            if check_tcp_port(ip, port, timeout, reset=True, syn_sweep=True):
                log.trace2(f"TCP SYN check of {ip} succeeded")
                return True
        except Exception as err:
            log.debug(f"failed to TCP SYN port {port} on {ip}: {err}")
            return False  # Critical error, exit out of loop early

    return False  # All hosts failed


def get_reachable_hosts(
    ip_list: list[str], ports: Iterable[int] | None = None
) -> list[str]:
    """
    Checks for online hosts.

    .. note::
       If the ports parameter is specified, then purely TCP SYN requests will
       be used. Otherwise, :term:`ARP` and/or :term:`ICMP` requests will be used.

    Args:
        ip_list: IPv4 addresses to check
        ports: Ports to attempt to check if hosts are responding

    Returns:
        Sorted :class:`list` of IP addresses of hosts that are responding
    """
    # Warn if user is forcing pings but we're not able to do them
    if config.FORCE_ONLINE_METHOD_PING and not state.raw_socket_capable:
        log.warning(
            "FORCE_ONLINE_METHOD_PING is enabled but the system "
            "is not able to use RAW sockets, the uptime check will "
            "likely fail with an exception."
        )
    elif config.FORCE_ONLINE_METHOD_TCP and state.raw_socket_capable:
        log.warning(
            "FORCE_ONLINE_METHOD_TCP is enabled when the system is "
            "able to use ARP/ICMP, online checks will only use TCP SYNs."
        )

    hosts = sort_ips(ip_list)  # Sort IPs for determinism
    valid_hosts: list[str] = []
    start_time = timeit.default_timer()

    with futures.ThreadPoolExecutor(config.MAX_THREADS) as executor:
        if ports:
            ports = sorted(ports)  # Sort ports for determinism
            log.info(
                f"Checking online status of {len(hosts)} hosts using "
                f"{len(ports)} TCP ports: {str(ports).strip('[]')}"
            )
            results: list[tuple[futures.Future, str]] = [
                (executor.submit(check_host_syn_sweep, ip, ports), ip) for ip in hosts
            ]
        else:
            if not config.FORCE_ONLINE_METHOD_TCP:
                log.info(
                    f"Checking online status of {len(hosts)} hosts "
                    f"using ARP and/or ICMP requests"
                )
            else:
                log.warning(
                    f"Forcing check of {len(hosts)} hosts using TCP SYNs "
                    f"since FORCE_ONLINE_METHOD_TCP is enabled"
                )

            results: list[tuple[futures.Future, str]] = [
                (executor.submit(check_host, ip), ip) for ip in hosts
            ]

        for res in results:
            try:
                if res[0].result() is True:
                    valid_hosts.append(res[1])
            except Exception as err:
                log.trace(f"Error in get_reachable_hosts: {err}")
                continue

    time_elapsed = timeit.default_timer() - start_time
    if valid_hosts:  # Sort the results for determinism
        valid_hosts = sort_ips(valid_hosts)
        log.info(
            f"{len(valid_hosts)} hosts are responding (checked "
            f"{len(hosts)} hosts in {utils.fmt_duration(time_elapsed)})"
        )

    return valid_hosts


__all__ = [
    "check_host",
    "check_host_arp",
    "check_host_icmp",
    "check_host_syn_sweep",
    "get_reachable_hosts",
]
