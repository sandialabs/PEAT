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
