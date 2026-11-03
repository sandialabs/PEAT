import pytest

from peat.modules.sandia.sceptre_fcd import _parse_endpoint


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("tcp://192.0.2.2:20000", {"transport": "tcp", "ip": "192.0.2.2", "port": 20000}),
        (
            "udp://172.16.1.2;239.0.0.1:40000",
            {"transport": "udp", "ip": "172.16.1.2", "multicast_ip": "239.0.0.1", "port": 40000},
        ),
        (
            "udp://239.0.0.1:40000",
            {"transport": "udp", "multicast_ip": "239.0.0.1", "port": 40000},
        ),
        ("tcp://*:5555", {"transport": "tcp", "port": 5555}),
        ("tcp://[2001:0db8::2]:20000", {"transport": "tcp", "ip": "2001:db8::2", "port": 20000}),
        ("tcp://2001:db8::5", {"transport": "tcp", "ip": "2001:db8::5"}),
        ("tcp://localhost:20000", {"transport": "tcp", "hostname": "localhost", "port": 20000}),
        ("tcp://192.0.2.2", {"transport": "tcp", "ip": "192.0.2.2"}),
        ("tcp://192.0.2.2:99999", {"transport": "tcp", "ip": "192.0.2.2"}),
        ("ipc:///tmp/bennu", {"transport": "ipc"}),
        ("/dev/ttyS0", {"serial_port": "/dev/ttyS0", "type": "serial"}),
        ("192.0.2.2:20000", {"ip": "192.0.2.2", "port": 20000}),
        ("172.16.254.254", {"ip": "172.16.254.254"}),
        ("", {}),
        (None, {}),
    ],
)
def test_parse_endpoint(endpoint, expected):
    assert _parse_endpoint(endpoint) == expected
