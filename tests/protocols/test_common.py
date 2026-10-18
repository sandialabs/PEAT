import pytest

from peat.protocols import common


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


ARPEXE_OUTPUT = """
Interface: 192.0.2.5 --- 0x13
  Internet Address      Physical Address      Type
  192.0.2.1             00-30-a7-00-00-01     dynamic
  192.0.2.10            00-30-a7-00-00-10     dynamic
  192.0.2.255           ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""


def test_get_mac_from_ip_arpexe(mocker):
    mocker.patch.object(common.shutil, "which", return_value="arp.exe")
    mocker.patch.object(common, "_get_arpexe_output", return_value=ARPEXE_OUTPUT)
    assert common._get_mac_from_ip_arpexe("192.0.2.10") == "00:30:a7:00:00:10"
    assert common._get_mac_from_ip_arpexe("192.0.2.1") == "00:30:a7:00:00:01"
    assert common._get_mac_from_ip_arpexe("192.0.2.2") == ""
    assert common._get_mac_from_ip_arpexe("2.0.2.1") == ""


def test_get_ip_from_mac_arpexe(mocker):
    mocker.patch.object(common.shutil, "which", return_value="arp.exe")
    mocker.patch.object(common, "_get_arpexe_output", return_value=ARPEXE_OUTPUT)
    assert common._get_ip_from_mac_arpexe("00:30:a7:00:00:10") == "192.0.2.10"
    assert common._get_ip_from_mac_arpexe("00:30:a7:00:00:01") == "192.0.2.1"
    assert common._get_ip_from_mac_arpexe("00:30:a7:00:00:02") == ""


def test_get_arpexe_output_non_utf8(mocker):
    mocker.patch.object(common.shutil, "which", return_value="arp.exe")
    proc = mocker.Mock(returncode=0, stdout=b"Schnittstelle: 192.0.2.5 --- 0x13\n\x81\xe4\n")
    mocker.patch.object(common.subprocess, "run", return_value=proc)
    assert "192.0.2.5" in common._get_arpexe_output()


PROC_NET_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.0.2.1        0x1         0x2         00:30:a7:00:00:01     *        eth0
192.0.2.10       0x1         0x2         00:30:a7:00:00:10     *        eth0
"""


def test_arpexe_lookups_fall_back_to_proc_net_arp(mocker):
    """WSL without Windows interop has no arp.exe."""
    mocker.patch.object(common.consts, "LINUX", True)
    mocker.patch.object(common.shutil, "which", return_value=None)
    mocker.patch.object(common.os.path, "exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data=PROC_NET_ARP))
    run = mocker.patch.object(common.subprocess, "run")
    assert common._get_mac_from_ip_arpexe("192.0.2.1") == "00:30:a7:00:00:01"
    assert common._get_ip_from_mac_arpexe("00:30:a7:00:00:10") == "192.0.2.10"
    run.assert_not_called()


def test_arpexe_lookups_fall_back_when_arpexe_fails(mocker):
    """WSL with interop disabled, but with arp.exe still on the PATH."""
    mocker.patch.object(common.consts, "LINUX", True)
    mocker.patch.object(common.shutil, "which", return_value="/mnt/c/Windows/system32/arp.exe")
    mocker.patch.object(common.subprocess, "run", side_effect=OSError(8, "Exec format error"))
    mocker.patch.object(common.os.path, "exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data=PROC_NET_ARP))
    assert common._get_mac_from_ip_arpexe("192.0.2.1") == "00:30:a7:00:00:01"
    assert common._get_ip_from_mac_arpexe("00:30:a7:00:00:10") == "192.0.2.10"


def test_get_arpexe_output_fails_on_windows(mocker):
    mocker.patch.object(common.consts, "LINUX", False)
    mocker.patch.object(common.subprocess, "run", side_effect=FileNotFoundError("arp.exe"))
    assert common._get_arpexe_output() == ""


# 192.0.2.10 is listed before 192.0.2.1, so a lookup of 192.0.2.1 that doesn't
# anchor the end of the IP address would wrongly match 192.0.2.10's line.
PROC_NET_ARP_UNORDERED = """\
IP address       HW type     Flags       HW address            Mask     Device
192.0.2.10       0x1         0x2         00:30:a7:00:00:10     *        eth0
192.0.2.1        0x1         0x2         00:30:a7:00:00:01     *        eth0
"""

ARPEXE_OUTPUT_UNORDERED = """
Interface: 192.0.2.5 --- 0x13
  Internet Address      Physical Address      Type
  192.0.2.10            00-30-a7-00-00-10     dynamic
  192.0.2.1             00-30-a7-00-00-01     dynamic
"""


@pytest.fixture(autouse=True)
def clear_arp_caches():
    """ip_to_mac and mac_to_ip are cached, so clear them to isolate tests."""
    common.ip_to_mac.cache_clear()
    common.mac_to_ip.cache_clear()
    yield
    common.ip_to_mac.cache_clear()
    common.mac_to_ip.cache_clear()


@pytest.fixture
def mock_linux_arp(mocker):
    """Linux host, with /proc/net/arp contents mocked."""
    for flag, value in [("LINUX", True), ("POSIX", True), ("WINDOWS", False), ("WSL", False)]:
        mocker.patch.object(common.consts, flag, value)
    mocker.patch.object(common.os.path, "exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data=PROC_NET_ARP_UNORDERED))


@pytest.fixture
def mock_windows_arp(mocker):
    """Windows host, with arp.exe output mocked (RESOLVE_MAC is disabled in conftest.py)."""
    for flag, value in [("LINUX", False), ("POSIX", False), ("WINDOWS", True), ("WSL", False)]:
        mocker.patch.object(common.consts, flag, value)
    mocker.patch.object(common.shutil, "which", return_value="arp.exe")
    proc = mocker.Mock(returncode=0, stdout=ARPEXE_OUTPUT_UNORDERED.encode())
    mocker.patch.object(common.subprocess, "run", return_value=proc)


@pytest.mark.parametrize(
    ("regex", "expected"),
    [
        (r"(\d+\.\d+\.\d+\.\d+)\s.*00:30:a7:00:00:01", "192.0.2.1"),
        (r"192\.0\.2\.10\s.*([0-9a-f]{2}(?::[0-9a-f]{2}){5})", "00:30:a7:00:00:10"),
        (r"192\.0\.2\.99\s.*([0-9a-f]{2}(?::[0-9a-f]{2}){5})", ""),
    ],
)
@pytest.mark.usefixtures("mock_linux_arp")
def test_search_arptable(regex, expected):
    assert common._search_arptable(regex) == expected


def test_search_arptable_missing_file(mocker):
    mocker.patch.object(common.os.path, "exists", return_value=False)
    assert common._search_arptable(r"(.*)") == ""


def test_search_arptable_empty_file(mocker):
    mocker.patch.object(common.os.path, "exists", return_value=True)
    mocker.patch("builtins.open", mocker.mock_open(read_data=""))
    assert common._search_arptable(r"(.*)") == ""


@pytest.mark.usefixtures("mock_linux_arp")
def test_ip_to_mac_linux():
    assert common.ip_to_mac("192.0.2.1") == "00:30:A7:00:00:01"
    assert common.ip_to_mac("192.0.2.10") == "00:30:A7:00:00:10"
    assert common.ip_to_mac("192.0.2.99") == ""


@pytest.mark.usefixtures("mock_linux_arp")
def test_mac_to_ip_linux():
    assert common.mac_to_ip("00:30:a7:00:00:01") == "192.0.2.1"
    assert common.mac_to_ip("00:30:A7:00:00:10") == "192.0.2.10"
    assert common.mac_to_ip("00:30:a7:00:00:99") == ""


@pytest.mark.usefixtures("mock_windows_arp")
def test_ip_to_mac_windows_arpexe():
    assert common.ip_to_mac("192.0.2.1") == "00:30:A7:00:00:01"
    assert common.ip_to_mac("192.0.2.10") == "00:30:A7:00:00:10"
    assert common.ip_to_mac("192.0.2.99") == ""


@pytest.mark.usefixtures("mock_windows_arp")
def test_mac_to_ip_windows_arpexe():
    assert common.mac_to_ip("00:30:a7:00:00:01") == "192.0.2.1"
    assert common.mac_to_ip("00:30:A7:00:00:10") == "192.0.2.10"
    assert common.mac_to_ip("00:30:a7:00:00:99") == ""


@pytest.mark.usefixtures("mock_windows_arp")
def test_ip_to_mac_wsl_arpexe(mocker):
    """WSL with Windows interop uses the Windows host's arp.exe."""
    for flag, value in [("LINUX", True), ("POSIX", True), ("WINDOWS", False), ("WSL", True)]:
        mocker.patch.object(common.consts, flag, value)
    assert common.ip_to_mac("192.0.2.1") == "00:30:A7:00:00:01"
    assert common.mac_to_ip("00:30:a7:00:00:10") == "192.0.2.10"
