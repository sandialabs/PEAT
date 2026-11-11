from ipaddress import IPv4Address, IPv4Network

from peat import state
from peat.protocols.interfaces import (
    get_in_scope_interfaces,
    is_promiscuous,
    parse_ifconfig_promisc,
)


def test_get_in_scope_interfaces(mocker):
    assert get_in_scope_interfaces([]) == []
    mocker.patch.dict(
        state["CONFIG"],
        {
            "local_interface_networks": {
                "eth0": [IPv4Network("10.0.0.0/24")],
                "eth1": [IPv4Network("192.0.2.0/24")],
            }
        },
    )
    inputs_1 = [IPv4Address("10.0.0.20"), IPv4Address("192.168.0.1")]
    assert get_in_scope_interfaces(inputs_1) == ["eth0"]
    inputs_2 = [IPv4Address("10.0.0.45"), IPv4Address("192.0.2.22")]
    assert get_in_scope_interfaces(inputs_2) == ["eth0", "eth1"]
    inputs_3 = [IPv4Network("10.0.0.0/24"), IPv4Address("192.0.2.22")]
    assert get_in_scope_interfaces(inputs_3) == ["eth0", "eth1"]


def test_parse_ifconfig_promisc():
    promisc = (
        "en0: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tether 00:00:5e:00:53:01\n"
    )
    normal = (
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tether 00:00:5e:00:53:01\n"
    )
    assert parse_ifconfig_promisc("en0", promisc) is True
    assert parse_ifconfig_promisc("en0", normal) is False
    assert parse_ifconfig_promisc("en0", "") is False
    assert parse_ifconfig_promisc("en0", "ifconfig: interface en9 does not exist") is False


def test_is_promiscuous_macos(mocker):
    mocker.patch("peat.consts.MACOS", True)
    proc = mocker.MagicMock(
        returncode=0,
        stdout=b"en0: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500\n",
    )
    run = mocker.patch("peat.protocols.interfaces.subprocess.run", return_value=proc)
    assert is_promiscuous("en0") is True
    assert run.call_args[0][0][-1] == "en0"

    proc.returncode = 1
    assert is_promiscuous("en9") is False
    assert is_promiscuous("") is False
