import errno
import socket
import sys

from peat.protocols import check_tcp_port, make_udp_socket, send_discovery_packet
from peat.protocols.ip import CONN_REFUSED_CODES

# TODO: test check_udp_service()
# TODO: check fingerprint()


def test_check_tcp_port_fails():
    assert check_tcp_port("127.0.0.1", 44818, 0.01) is False


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
