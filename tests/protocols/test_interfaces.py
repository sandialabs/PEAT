from ipaddress import IPv4Address, IPv4Network

from peat import state
from peat.protocols.interfaces import get_in_scope_interfaces


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
