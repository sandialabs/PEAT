import errno
import os
import socket
import struct
from pprint import pformat
from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM
from collections.abc import Callable

from peat import config, consts, log
from peat.protocols.snmp import SNMP


def check_tcp_port(
    ip: str,
    port: int,
    timeout: float | None = None,
    reset: bool = False,
    syn_sweep: bool = False,
) -> bool:
    """
    Check if a TCP port is open on the given IP address.

    By default, this is essentially a bargain-basement ``nmap -sT`` ("Connect scan").
    It will finalize connections using TCP FIN, which can sometimes result
    in issues with devices continuing to send data. Therefore, I recommended
    enabling reset, which closes connections with TCP RST instead of FIN.

    In other words (from Stack Overflow FIN vs RST):

    - FIN says: "I finished talking to you, but I'll still listen to
        everything you have to say until you say that you're done."
    - RST says: "There is no conversation. I won't say anything and
        I won't listen to anything you say."

    Further reading

    - nmap connect scan: https://nmap.org/book/scan-methods-connect-scan.html
    - SO_LINGER: https://www.nybek.com/blog/2015/03/05/cross-platform-testing-of-so_linger/
    - SO_LINGER Python: https://stackoverflow.com/a/6440364
    - FIN vs RST: https://stackoverflow.com/a/13050021

    .. warning::
        VMware VM interfaces will cause this function to return :obj:`True` for most ports!

    Args:
        ip: IPv4 address of the host to check
        port: TCP port number to check
        timeout: Number of seconds to wait for a response
        reset: Close the connection with [ACK, RST] instead of a [FIN]
            by setting SO_LINGER timeout to 0. This is generally useful
            to prevent issues with devices that will respond with data
            and cause issues (like errno 11 "Resource temporarily unavailable").
            This is similar to ``nmap -sS`` ("SYN scan").
        syn_sweep: If connection refused (code 111) should be considered "open".
            Commonly used when checking if a host is online and responding.
            This also changes the amount of logging output to accommodate
            SYN sweep scanning, which generates a lot of errors.

    Returns:
        If the port is open, or the host is responding (if ``syn_sweep`` is set)
    """
    with socket.socket(AF_INET, SOCK_STREAM) as sock:
        # NOTE(cegoes): Setting timeout on Windows results in code 10035 errors
        #   even if the host is online. I don't know why this is happening and
        #   can't afford to spend any more time investigating at the moment.
        #   This means scanning as a standard user (not admin) will likely
        #   not work reliably or at all. The workaround for now is to
        #   run PEAT as an Administrator.
        # NOTE 2(cegoes): Setting timeout is also causing issues on POSIX
        #   platforms. Some of the calls were resulting in socket error code
        #   11 ("EWOULDBLOCK/EAGAIN" or "Resource Temporarily Unavailable").
        #   The issue only seemed to occur when running threaded in
        #   concurrent.futures, which I'm still not sure why it's occurring.
        #   The issue was manifesting primarily with the FTP service on SEL
        #   devices, which seem to REALLY want to open a full FTP connection
        #   when you attempt a TCP connect, and won't let you go.
        if timeout is not None:
            sock.settimeout(timeout)

        if reset:
            # "Turn the SO_LINGER socket option on and set the linger time
            # to 0 seconds. This will cause TCP to abort the connection
            # when it is closed, flush the data and send a RST."
            # https://stackoverflow.com/a/6440364
            # "Windows uses shorts in struct linger, where Linux uses ints"
            linger = struct.pack("hh" if consts.WINDOWS else "ii", 1, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)

        try:
            result = sock.connect_ex((ip, port))
        except TimeoutError:  # Port is filtered
            log.log(
                "TRACE4" if syn_sweep else "TRACE2",
                f"TCP port check timed out to {ip}:{port} (timeout: {timeout:.2f})",
            )
            return False
        except Exception as err:  # Something unexpected happened
            log.debug(f"TCP scan of {ip}:{port} failed due to an exception: {err}")
            return False

    # 0 => Success, 111 => Connection refused (something is there)
    # socket errno reference: https://gist.github.com/gabrielfalcao/4216897
    # WinError codes reference: https://support.microsoft.com/en-us/help/819124
    if result == 0 or (syn_sweep and result in [111, 10061]):
        if config.DEBUG >= 4:
            log.trace4(f"{ip}:{port} scan succeeded: {err_code_to_str(result)}")
        return True

    if (not syn_sweep and config.DEBUG >= 3) or config.DEBUG >= 4:
        log.trace3(
            f"TCP scan of {ip}:{port} failed due to "
            f"an error: {err_code_to_str(result)}"
        )

    return False


def check_udp_service(
    ip: str, service: str, port: int | None = None, timeout: float = 1.0
) -> bool:
    """
    Check if a specific UDP service is listening.

    Args:
        ip: IPv4 address of the host to check
        service: Name of the service to check
        port: UDP port number to check
        timeout: Number of seconds to wait for a response

    Returns:
        If the service is listening
    """
    name = service.lower()

    if name == "snmp":
        if port is None:
            port = 161  # Set to SNMP default port

        # Full list of community strings: goo.gl/4kANPb
        snmp_communities = ["public", "private"]
        for community in snmp_communities:
            snmp = SNMP(ip, port, timeout, community=community)
            val = snmp.get(identity="1.3.6.1.2.1.1.1.0")
            if val:
                return True

        log.trace2(
            f"SNMP service check failed for {ip}\nCommunity "
            f"strings attempted: {pformat(snmp_communities)}"
            f"\tPort: {port}\tTimeout: {timeout:.2f}"
        )
        return False
    else:
        log.error(f"Unknown UDP service passed to check_udp_service: {service}")
        return False


def fingerprint(
    ip: str, port: int, timeout: float, payload: bytes, finger_func: Callable
) -> dict | None:
    """
    Fingerprints (verifies) a UDP device.

    The provided socket, ip, port, and byte payload are used in a discovery
    packet to determine if the device is eligible to be fingerprinted. If so,
    it then uses the provided fingerprint function object to verify and return
    details about the device.

    Args:
        ip: IPv4 address of device
        port: UDP port to use
        timeout: Timeout for function
        payload: Payload to send in the discovery
        finger_func: Function to use to verify the device

    Returns:
        The device description :class:`dict`, or :obj:`None`
        if it failed or there was an error
    """
    log.trace2(f"Fingerprinting device {ip}:{port}")

    sock = make_udp_socket(timeout)
    if sock is None:
        return None

    with sock:
        if send_discovery_packet(sock, ip, port, payload):
            try:
                return finger_func(sock)
            except TimeoutError:
                log.trace2(
                    f"Discovery packet succeeded, but fingerprint "
                    f"function timed out to device {ip}:{port}"
                )
            except Exception as err:
                log.debug(
                    f"Failed to receive a response from an unknown "
                    f"device due to an error: {err}"
                )
                raise err from None
        return None


def make_udp_socket(
    timeout: float | None = None, broadcast: bool = False
) -> socket.socket | None:
    """
    Creates and binds a IPv4 UDP :class:`~socket.socket`.

    Args:
        timeout: Timeout to set for the socket, in seconds
        broadcast: If the socket should be a broadcast socket

    Returns:
        The created UDP :class:`~socket.socket`
    """
    sock = socket.socket(AF_INET, SOCK_DGRAM)

    if timeout is not None:
        sock.settimeout(timeout)

    if broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        # '' : Equivalent to '0.0.0.0', which is 'all interfaces'
        # 0  : Let the OS choose a port
        sock.bind(("", 0))
    except Exception as ex:
        log.error(f"Failed to bind UDP socket: {ex}")
        return None

    return sock


def send_discovery_packet(
    sock: socket.socket, ip: str, port: int, payload: bytes
) -> bool:
    """
    Send initial hello packet used to fingerprint the device.

    Args:
        sock: :class:`~socket.socket` to use
        ip: IPv4 address to send packet to
        port: Port to send packet to
        payload: Payload to send

    Returns:
        If the send was successful
    """
    log.trace2(f"Sending discovery packet to {ip}:{port}")

    try:
        sock.sendto(payload, (ip, port))
    except Exception as err:
        log.error(f"Failed to send discovery packet to {ip}:{port}: {err}")
        return False

    return True


def err_code_to_str(code: int) -> str:
    """
    Translates a :mod:`socket` error code to a human-readable string.

    Args:
        code: Integer code to lookup

    Returns:
        Human-readable form of the error code, such as
        ``Operation not permitted`` or ``EPERM``. If the code
        is unable to be looked up, the original code will
        be returned as a string.
    """
    if consts.WINDOWS and hasattr(socket, "errorTab"):
        err_str = socket.errorTab.get(code)
    else:
        try:
            err_str = os.strerror(code)
        except ValueError:
            err_str = errno.errorcode.get(code)

    if err_str:
        return f"{err_str} (Code: {code})"

    return str(code)


__all__ = [
    "check_tcp_port",
    "check_udp_service",
    "err_code_to_str",
    "fingerprint",
    "make_udp_socket",
    "send_discovery_packet",
]
