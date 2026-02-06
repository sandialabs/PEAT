import unittest
from ipaddress import AddressValueError, IPv4Address, IPv4Network

import pytest

from peat import PeatError
from peat.protocols import (
    clean_ipv4,
    clean_mac,
    expand_commas_and_clean_strings,
    expand_filenames_to_hosts,
    host_string_to_objs,
    hosts_to_ips,
    hosts_to_objs,
    ip_in_local_subnet,
    ip_is_local_interface,
    ip_objs_to_ips,
    network_is_local,
    resolve_hostname_to_ip,
    resolve_ip_to_hostname,
    split_ipv4_cidr,
)


def test_resolve_hostname_to_ip():
    assert resolve_hostname_to_ip("") == ""
    assert resolve_hostname_to_ip("localhost") == "127.0.0.1"


def test_resolve_ip_to_hostname():
    assert resolve_ip_to_hostname("") == ""
    assert resolve_ip_to_hostname("127.0.0.1") == "localhost"
    assert resolve_ip_to_hostname("0.0.0.0") == ""


def test_expand_commas_to_hosts():
    assert expand_commas_and_clean_strings([]) == []
    assert expand_commas_and_clean_strings(["host1"]) == ["host1"]
    assert expand_commas_and_clean_strings(["192.168.0.20,192.168.0.30"]) == [
        "192.168.0.20",
        "192.168.0.30",
    ]
    assert expand_commas_and_clean_strings(
        ["192.168.0.20,192.168.0.30", "10.0.0.1, 10.0.0.2", "172.16.0.1", ",  "]
    ) == ["192.168.0.20", "192.168.0.30", "10.0.0.1", "10.0.0.2", "172.16.0.1"]


def test_expand_filenames_to_hosts(examples_path):
    json_path = examples_path("target_hosts.json")
    text_path = examples_path("target_hosts.txt")
    expected = [
        "192.0.2.200",
        "192.0.2.201",
        "192.0.2.100-105",
        "192.0.2.200",
        "192.0.2.201",
        "192.0.2.100-105",
    ]
    assert expand_filenames_to_hosts([json_path, text_path]) == expected
    assert expand_filenames_to_hosts([json_path.as_posix(), text_path.as_posix()]) == expected
    cmp = [
        "10.0.0.1",
        b"172.16.0.1",
        IPv4Network("172.16.0.0/24"),
        IPv4Address("192.0.2.2"),
    ]
    assert expand_filenames_to_hosts(cmp) == cmp
    assert expand_filenames_to_hosts([]) == []


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ([], []),
        ([b"127.0.0.1"], [IPv4Address("127.0.0.1")]),
        (["127.0.0.1"], [IPv4Address("127.0.0.1")]),
        # dedupe localhost
        (["localhost", "127.0.0.1"], [IPv4Address("127.0.0.1")]),
    ],
)
def test_hosts_to_objs(data, expected):
    assert hosts_to_objs(data) == expected


def test_hosts_to_objs_subnets():
    data = [
        "localhost",
        "127.0.0.1",
        "10.0.0.0",
        b"10.0.0.0",
        "192.0.2.0/24",
        "192.168.0.0/16",
    ]

    results = hosts_to_objs(data)
    assert isinstance(results, list)

    expected = [
        IPv4Network("192.0.2.0/24"),
        IPv4Network("192.168.0.0/16"),
        IPv4Address("10.0.0.0"),
        IPv4Address("127.0.0.1"),
    ]

    # https://stackoverflow.com/a/45946306
    # Compares objects in list without regard for order
    case = unittest.TestCase()
    case.assertCountEqual(results, expected)  # noqa: PT009


def test_host_string_to_objs():
    assert host_string_to_objs("   172.16.0.5  ") == IPv4Address("172.16.0.5")

    assert host_string_to_objs("192.168.2-3.142-144") == {
        IPv4Address("192.168.2.142"),
        IPv4Address("192.168.2.143"),
        IPv4Address("192.168.2.144"),
        IPv4Address("192.168.3.142"),
        IPv4Address("192.168.3.143"),
        IPv4Address("192.168.3.144"),
    }

    assert host_string_to_objs("192.168.3.140-142") == {
        IPv4Address("192.168.3.140"),
        IPv4Address("192.168.3.141"),
        IPv4Address("192.168.3.142"),
    }

    assert host_string_to_objs("172.16.0.0/30") == IPv4Network("172.16.0.0/30")
    assert host_string_to_objs("localhost") == IPv4Address("127.0.0.1")
    assert host_string_to_objs(b"13.14.15.16") == IPv4Address("13.14.15.16")
    assert len(host_string_to_objs("172.16-30.80-90.12-14")) == 495
    assert len(host_string_to_objs("172-192.16-30.80-90.12-14")) == 10395

    netres = sorted(host_string_to_objs("192.168.2-3.0"))
    assert len(netres) == 506
    assert netres[0] == IPv4Address("192.168.2.1")
    assert netres[-1] == IPv4Address("192.168.3.253")


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (None, []),
        ("localhost", []),
        ([], []),
        (["127.0.0.1"], ["127.0.0.1"]),
        # dedupe localhost
        (["localhost", "127.0.0.1"], ["127.0.0.1"]),
        # nmap-style args
        (
            ["192.0.2.200-203"],
            ["192.0.2.200", "192.0.2.201", "192.0.2.202", "192.0.2.203"],
        ),
    ],
)
def test_hosts_to_ips(data, expected):
    assert hosts_to_ips(data) == expected


def test_hosts_to_ips_subnets_filtered():
    data = [
        b"localhost",
        "localhost",
        "127.0.0.1",
        "172.16.0.0",
        "10.0.0.0",
        "10.0.0.1",
        "10.0.0.0/24",
        "192.0.2.0/24",
    ]

    results = hosts_to_ips(data)

    assert len(results) == 511
    assert "127.0.0.1" in results
    assert "10.0.0.1" in results
    assert "10.0.0.205" in results
    assert "192.0.2.205" in results


@pytest.mark.slow
def test_hosts_to_ips_subnets_disambiguation():
    data = ["192.168.2.0/24", "192.168.0.0/16"]

    results = hosts_to_ips(data)

    assert len(results) == 65534
    assert "192.168.0.1" in results
    assert "192.168.0.205" in results
    assert "192.168.1.1" in results
    assert "192.168.2.205" in results
    assert "192.168.200.205" in results


def test_hosts_to_ips_crazy_combination():
    hosts = [
        "172.16-30.80-90.12-14",
        "192.168.0.19-23",
        "localhost",
        " 10.0.9.0/24",
        " ",
        ",  ",
        "",
        "10.0.9.1,10.0.9.2",
        " ",
        ",",
    ]

    results = hosts_to_ips(hosts)

    assert len(results) == 755
    assert "127.0.0.1" in results
    assert "10.0.9.3" in results
    assert "" not in results
    assert "," not in results


def test_hosts_to_ips_ipaddress_objects():
    addrs = [
        IPv4Address("127.0.0.1"),
        IPv4Address("192.0.2.1"),
        IPv4Address("192.0.2.9"),
        IPv4Network("192.168.1.2/31"),
        "127.0.0.1",
        "localhost",
        "192.0.2.9",
    ]

    results = hosts_to_ips(addrs)

    assert sorted(results) == [
        "127.0.0.1",
        "192.0.2.1",
        "192.0.2.9",
        "192.168.1.2",
        "192.168.1.3",
    ]


def test_ip_objs_to_ips_normal():
    addrs = [
        IPv4Address("127.0.0.1"),
        IPv4Address("192.0.2.1"),
        IPv4Address("192.0.2.9"),
        IPv4Network("192.168.1.2/31"),
    ]

    results = ip_objs_to_ips(addrs)

    assert sorted(results) == [
        "127.0.0.1",
        "192.0.2.1",
        "192.0.2.9",
        "192.168.1.2",
        "192.168.1.3",
    ]


def test_ip_objs_to_ips_dedupe():
    dupes = [
        IPv4Address("127.0.0.1"),
        IPv4Address("127.0.0.1"),
        IPv4Address("192.0.2.1"),
        IPv4Address("192.0.2.9"),
        IPv4Network("192.168.1.2/31"),
        IPv4Network("192.168.1.2/31"),
    ]

    results = ip_objs_to_ips(dupes)

    assert sorted(results) == [
        "127.0.0.1",
        "192.0.2.1",
        "192.0.2.9",
        "192.168.1.2",
        "192.168.1.3",
    ]


def test_ip_objs_to_ips_invalid_arguments():
    with pytest.raises(PeatError):
        ip_objs_to_ips(["192.0.2.1", "127.0.0.1"])


def test_ip_is_local_interface():
    assert ip_is_local_interface("127.0.0.1") is True
    assert ip_is_local_interface("0.0.0.0") is False


def test_ip_in_local_subnet():
    assert ip_in_local_subnet("127.0.0.1") is True
    assert ip_in_local_subnet("1.1.1.1") is False
    assert ip_in_local_subnet("192.0.2.1") is False

    with pytest.raises(AddressValueError):
        ip_in_local_subnet("localhost")


def test_network_is_local():
    assert network_is_local(IPv4Network("127.0.0.0/24")) is True
    assert network_is_local(IPv4Network("127.0.0.0/8")) is True
    assert network_is_local(IPv4Network("1.0.0.0/8")) is False

    with pytest.raises(AttributeError):
        network_is_local(IPv4Address("127.0.0.1"))


def test_split_ipv4_cidr():
    assert split_ipv4_cidr("172.16.0.20/24") == ("172.16.0.20", "255.255.255.0")


def test_clean_ipv4():
    assert clean_ipv4("192.0.2.4") == "192.0.2.4"
    assert clean_ipv4("192.000.002.004") == "192.0.2.4"
    assert clean_ipv4("10.048.007.001") == "10.48.7.1"
    assert clean_ipv4("") == ""


def test_clean_mac():
    assert clean_mac("") == ""
    assert clean_mac("   ") == ""
    assert clean_mac(None) == ""
    assert clean_mac("0:a0:a9:a8:12:a1") == "00:A0:A9:A8:12:A1"
    assert clean_mac("00:A0:A9:A8:12:A1") == "00:A0:A9:A8:12:A1"
    assert clean_mac("00:A0:A9:8:12:1") == "00:A0:A9:08:12:01"
    assert clean_mac("00-A0-A9-8-12-1") == "00:A0:A9:08:12:01"
    assert clean_mac("  00-A0-A9-8-12-1   ") == "00:A0:A9:08:12:01"
    assert clean_mac("00:b0:b9:08:12:01") == "00:B0:B9:08:12:01"
