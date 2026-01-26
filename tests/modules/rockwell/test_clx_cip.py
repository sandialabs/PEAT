from peat.modules.rockwell.clx_cip import ClxCIP


def test_clx_cip_class():
    assert "127.0.0.1" in str(ClxCIP("127.0.0.1", 44818, 1.0, 1))
    assert "127.0.0.1" in repr(ClxCIP("127.0.0.1", 44818, 1.0, 1))
