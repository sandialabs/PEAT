import errno

from peat.protocols import common

# TODO: test mac_to_ip using mocked input for proc/net/arp + arp.exe
# TODO: test ip_to_mac using mocked input for proc/net/arp + arp.exe
# TODO: test _search_arptable directly using mocked input
# TODO: test _get_ip_from_mac_arpexe directly using mocked input
# TODO: test _get_mac_from_ip_arpexe directly using mocked input


def test_mac_to_vendor():
    expected_asus = ["ASUSTekCOMPU", "ASUSTek COMPUTER INC.", None]
    assert list(common.mac_to_vendor("BC:EE:7B:00:00:00")) == expected_asus
    expected_sel = ["SchweitzerEn", "Schweitzer Engineering", None]
    assert list(common.mac_to_vendor("00:30:A7:15:62:BF")) == expected_sel
    assert common.mac_to_vendor("") is None
    assert common.mac_to_vendor("ff:ff:ff:ff:ff") is None


def test_mac_to_vendor_string():
    assert common.mac_to_vendor_string("BC:EE:7B:00:00:00") == "ASUSTek COMPUTER INC."
    assert common.mac_to_vendor_string("00:30:A7:15:62:BF") == "Schweitzer Engineering"
    assert common.mac_to_vendor_string("") == ""
    assert common.mac_to_vendor_string("ff:ff:ff:ff:ff") == ""


def test_mac_to_ip_junk_string():
    assert common.mac_to_ip("testingtestingtesting") == ""


def test_mac_to_ip_empty_string():
    assert common.mac_to_ip("") == ""


def test_mac_to_ip_none():
    assert common.mac_to_ip(None) == ""


def test_ip_to_mac_127_0_0_1():
    assert common.ip_to_mac("127.0.0.1") == ""
    assert common.ip_to_mac("0.0.0.0") == ""


def test_ip_to_mac_localhost():
    """Hostnames should fail."""
    assert common.ip_to_mac("localhost") == ""


def test_ip_to_mac_junk_string():
    assert common.ip_to_mac("testingtestingtesting") == ""


def test_ip_to_mac_empty_string():
    assert common.ip_to_mac("") == ""


def test_ip_to_mac_none():
    assert common.ip_to_mac("") == ""
    assert common.ip_to_mac(None) == ""


MACOS_ARP_OUTPUT = """\
? (192.0.2.1) at 0:0:5e:0:53:a on en0 ifscope [ethernet]
? (192.0.2.20) at (incomplete) on en0 ifscope [ethernet]
? (192.0.2.33) at 00:30:a7:15:62:bf on en0 ifscope [ethernet]
? (192.0.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""


def test_parse_arp_macos():
    assert common._parse_arp_macos("") == []
    assert common._parse_arp_macos(MACOS_ARP_OUTPUT) == [
        ("192.0.2.1", "00:00:5e:00:53:0a"),
        ("192.0.2.33", "00:30:a7:15:62:bf"),
        ("192.0.2.255", "ff:ff:ff:ff:ff:ff"),
        ("224.0.0.251", "01:00:5e:00:00:fb"),
    ]


def test_ip_to_mac_macos(mocker):
    mocker.patch("peat.consts.MACOS", True)
    mocker.patch("peat.consts.WSL", False)
    mocker.patch.object(common, "_get_arp_macos_output", return_value=MACOS_ARP_OUTPUT)
    common.ip_to_mac.cache_clear()
    try:
        assert common.ip_to_mac("192.0.2.1") == "00:00:5E:00:53:0A"
        assert common.ip_to_mac("192.0.2.33") == "00:30:A7:15:62:BF"
        assert common.ip_to_mac("192.0.2.20") == ""  # incomplete
        assert common.ip_to_mac("192.0.2.99") == ""  # not in table
    finally:
        common.ip_to_mac.cache_clear()


def test_mac_to_ip_macos(mocker):
    mocker.patch("peat.consts.MACOS", True)
    mocker.patch("peat.consts.WSL", False)
    mocker.patch("peat.consts.WINDOWS", False)
    mocker.patch.object(common, "_get_arp_macos_output", return_value=MACOS_ARP_OUTPUT)
    common.mac_to_ip.cache_clear()
    try:
        assert common.mac_to_ip("00:00:5E:00:53:0A") == "192.0.2.1"
        assert common.mac_to_ip("00:30:a7:15:62:bf") == "192.0.2.33"
        assert common.mac_to_ip("00:30:a7:15:62:00") == ""
    finally:
        common.mac_to_ip.cache_clear()


def test_macos_bpf_capable(mocker):
    mocker.patch.object(common.glob, "glob", return_value=["/dev/bpf1", "/dev/bpf0"])
    opened = []

    def fake_open(path, _flags):
        opened.append(path)
        if path == "/dev/bpf0":
            raise OSError(errno.EBUSY, "Resource busy")
        return 99

    mocker.patch.object(common.os, "open", side_effect=fake_open)
    close = mocker.patch.object(common.os, "close")
    assert common._macos_bpf_capable() is True
    assert opened == ["/dev/bpf0", "/dev/bpf1"]
    close.assert_called_once_with(99)


def test_macos_bpf_capable_no_permissions(mocker):
    mocker.patch.object(common.glob, "glob", return_value=["/dev/bpf0"])
    mocker.patch.object(common.os, "open", side_effect=OSError(errno.EACCES, "Permission denied"))
    assert common._macos_bpf_capable() is False

    mocker.patch.object(common.glob, "glob", return_value=[])
    assert common._macos_bpf_capable() is False


def test_raw_socket_capable_macos(mocker):
    mocker.patch("peat.consts.MACOS", True)
    mocker.patch.object(common, "_macos_bpf_capable", return_value=True)
    assert common.raw_socket_capable() is True
