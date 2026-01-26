import socket

from peat.protocols import check_tcp_port, make_udp_socket, send_discovery_packet

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
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) == 1


def test_send_discovery_packet_fails():
    with socket.socket() as sock:
        result = send_discovery_packet(sock, "127.0.0.1", 44818, b"")
        assert result is False
