import errno
import socket
import sys
import threading

import pytest

from peat import consts
from peat.protocols import check_tcp_port, make_udp_socket, send_discovery_packet
from peat.protocols import ip as ip_module
from peat.protocols.ip import CONN_REFUSED_CODES


def test_check_tcp_port_fails():
    assert check_tcp_port("127.0.0.1", 44818, 0.01) is False


@pytest.fixture
def closed_local_port() -> int:
    """A localhost TCP port that nothing is listening on."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.skipif(consts.WSL, reason="Doesn't work in WSL")
def test_check_tcp_port_refused_syn_sweep(closed_local_port):
    """
    A refused connection means the host is online when doing a SYN sweep.

    On Windows, this also checks that SYN retransmissions are disabled: with them,
    the refusal arrives after about 2 seconds, so the 1 second timeout expires first.
    """
    assert check_tcp_port("127.0.0.1", closed_local_port, 1.0, reset=True, syn_sweep=True)


def test_check_tcp_port_refused_not_open(closed_local_port):
    """A refused connection means the port is closed when not doing a SYN sweep."""
    assert check_tcp_port("127.0.0.1", closed_local_port, 1.0) is False


def test_check_tcp_port_open():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        assert check_tcp_port("127.0.0.1", listener.getsockname()[1], 1.0, reset=True)


def test_make_udp_socket_basic():
    """Basic socket."""
    with make_udp_socket() as sock:
        assert sock.family == socket.AF_INET
        assert sock.type == socket.SOCK_DGRAM


def test_make_udp_socket_timeout():
    """With timeout specified."""
    timeout = 1.0
    with make_udp_socket(timeout=1.0) as sock:
        assert sock.family == socket.AF_INET
        assert sock.gettimeout() == timeout


def test_make_udp_socket_broadcast():
    """Broadcast socket."""
    with make_udp_socket(broadcast=True) as sock:
        assert sock.family == socket.AF_INET
        assert sock.type == socket.SOCK_DGRAM
        # Linux and Windows return 1, while macOS (BSD) returns the
        # value of the SO_BROADCAST flag (32). Both mean it's enabled.
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) != 0


def test_make_udp_socket_no_broadcast():
    with make_udp_socket() as sock:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) == 0


def test_conn_refused_codes():
    # Native ECONNREFUSED (111 on Linux, 61 on macOS) and Winsock's WSAECONNREFUSED
    assert errno.ECONNREFUSED in CONN_REFUSED_CODES
    assert 10061 in CONN_REFUSED_CODES
    if sys.platform == "darwin":
        assert 61 in CONN_REFUSED_CODES
    elif sys.platform == "linux":
        assert 111 in CONN_REFUSED_CODES


def test_check_tcp_port_syn_sweep_refused(mocker):
    """A refused connection means the host is up when doing a SYN sweep, on any platform."""
    mock_sock = mocker.MagicMock()
    mocker.patch("peat.protocols.ip.socket.socket", return_value=mock_sock)
    # The native code (111 on Linux, 61 on macOS) and Winsock's code
    for code in [errno.ECONNREFUSED, 10061]:
        mock_sock.__enter__.return_value.connect_ex.return_value = code
        assert check_tcp_port("192.0.2.1", 80, syn_sweep=True) is True
        assert check_tcp_port("192.0.2.1", 80, syn_sweep=False) is False


def test_send_discovery_packet_fails():
    with socket.socket() as sock:
        result = send_discovery_packet(sock, "127.0.0.1", 44818, b"")
        assert result is False


@pytest.fixture
def udp_responder():
    """A localhost UDP server that replies to b"hello" with b"world"."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(2.0)

    def respond():
        try:
            data, addr = server.recvfrom(1024)
            if data == b"hello":
                server.sendto(b"world", addr)
        except OSError:
            pass

    thread = threading.Thread(target=respond, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    thread.join(timeout=3.0)
    server.close()


@pytest.fixture
def closed_udp_port() -> int:
    """A localhost UDP port that nothing is listening on."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_fingerprint(udp_responder):
    def finger_func(sock: socket.socket) -> dict:
        data, _ = sock.recvfrom(1024)
        return {"response": data}

    result = ip_module.fingerprint("127.0.0.1", udp_responder, 1.0, b"hello", finger_func)
    assert result == {"response": b"world"}


def test_fingerprint_no_response(closed_udp_port):
    """
    Nothing listening on the port returns None. On Windows this is reported as a
    connection reset (ICMP port unreachable), and on Linux and macOS as a timeout.
    """

    def finger_func(sock: socket.socket) -> dict:
        data, _ = sock.recvfrom(1024)
        return {"response": data}

    assert ip_module.fingerprint("127.0.0.1", closed_udp_port, 0.5, b"hello", finger_func) is None


def test_fingerprint_reraises_unexpected_errors(udp_responder):
    def finger_func(sock: socket.socket) -> dict:
        sock.recvfrom(1024)
        raise ValueError("bad response")

    with pytest.raises(ValueError, match="bad response"):
        ip_module.fingerprint("127.0.0.1", udp_responder, 1.0, b"hello", finger_func)


def test_check_udp_service_snmp(mocker):
    snmp = mocker.patch.object(ip_module, "SNMP")
    snmp.return_value.get.side_effect = [None, "SEL-751 relay"]

    assert ip_module.check_udp_service("192.0.2.1", "SNMP", timeout=0.5) is True
    # "public" fails, then "private" succeeds, both on the default SNMP port
    assert snmp.call_args_list == [
        mocker.call("192.0.2.1", 161, 0.5, community="public"),
        mocker.call("192.0.2.1", 161, 0.5, community="private"),
    ]


def test_check_udp_service_snmp_custom_port(mocker):
    snmp = mocker.patch.object(ip_module, "SNMP")
    snmp.return_value.get.return_value = "device"
    assert ip_module.check_udp_service("192.0.2.1", "snmp", port=1161) is True
    snmp.assert_called_once_with("192.0.2.1", 1161, 1.0, community="public")


def test_check_udp_service_snmp_no_response(mocker):
    snmp = mocker.patch.object(ip_module, "SNMP")
    snmp.return_value.get.return_value = None
    assert ip_module.check_udp_service("192.0.2.1", "snmp") is False
    assert snmp.call_count == 2


def test_check_udp_service_unknown_service():
    assert ip_module.check_udp_service("192.0.2.1", "not-a-service") is False


@pytest.mark.slow
def test_check_udp_service_snmp_localhost_closed(closed_udp_port):
    """A real SNMP request to a closed port fails cleanly, on every platform."""
    assert (
        ip_module.check_udp_service("127.0.0.1", "snmp", port=closed_udp_port, timeout=0.2)
        is False
    )
