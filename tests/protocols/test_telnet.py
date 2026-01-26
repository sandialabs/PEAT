from peat import config
from peat.protocols import telnet


def test_telnet_class(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path})
    ip = "127.0.0.1"
    tn = telnet.Telnet(ip)
    assert str(tn) == ip
    assert not tn.connected
