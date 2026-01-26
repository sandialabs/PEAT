from peat.protocols.enip import EnipSocket


def test_enip_socket_class():
    e_sock = EnipSocket("127.0.0.1", 44818, 1.0)
    assert "127.0.0.1" in str(e_sock)
    assert "127.0.0.1" in repr(e_sock)
    assert "1.0" in repr(e_sock)
