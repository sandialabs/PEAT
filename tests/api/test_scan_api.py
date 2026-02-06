from peat import (
    ControlLogix,
    DeviceData,
    MicroNet,
    config,
    datastore,
    state,
)
from peat.api import scan_api


def test_portscan(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
        },
    )
    mocker.patch.object(datastore, "objects")

    assert scan_api.portscan(DeviceData(), []) is None


def test_unicast_ip_scan(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
            "DEFAULT_TIMEOUT": 0.01,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    datastore.device_options["cip"]["timeout"] = 0.01

    assert scan_api.unicast_ip_scan([], []) is None
    assert scan_api.unicast_ip_scan([], [ControlLogix]) is None

    results = scan_api.unicast_ip_scan(["127.0.0.1", "127.0.0.0/24"], [ControlLogix])

    assert results
    assert isinstance(results, tuple)
    assert results[1] == [ControlLogix]
    assert len(results[2]) == 254
    assert results[0]
    assert isinstance(results[0], dict)
    assert "127.0.0.1" in results[0]


def test_check_host_unicast_ip(mocker):
    mocker.patch.dict(config["CONFIG"], {"VERBOSE": True, "DEBUG": 3})
    mocker.patch.object(datastore, "objects", [])

    datastore.device_options["cip"]["timeout"] = 0.01

    assert scan_api.check_host_unicast_ip("", []) is False
    assert scan_api.check_host_unicast_ip("127.0.0.1", []) is False
    assert scan_api.check_host_unicast_ip("127.0.0.1", None) is False
    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix]) is False


def test_check_host_unicast_ip_module_edge_case(mocker):
    """
    Test Edge case: PEAT module for a host is set in config file,
    but not in the list of modules that are available to scan.
    """
    mocker.patch.dict(config["CONFIG"], {"VERBOSE": True, "DEBUG": 3})
    mocker.patch.dict(
        state["CONFIG"],
        {
            "error": False,
        },
    )

    dev = DeviceData(ip="127.0.0.1")
    dev._module = ControlLogix
    mocker.patch.object(datastore, "objects", [dev])

    assert state.error is False

    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix]) is False
    assert state.error is False

    assert scan_api.check_host_unicast_ip("127.0.0.1", [MicroNet]) is False
    assert state.error is True


def test_check_host_unicast_ip_force_module(mocker, caplog):
    """
    test dev._module only uses methods for that module.
    """
    mocker.patch.dict(config["CONFIG"], {"VERBOSE": True, "DEBUG": 3})
    mocker.patch.dict(
        state["CONFIG"],
        {
            "error": False,
        },
    )

    dev = DeviceData(ip="127.0.0.1")
    dev._module = ControlLogix
    mocker.patch.object(datastore, "objects", [dev])

    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix, MicroNet]) is False
    assert state.error is False
    assert "Forcing usage of module 'ControlLogix'" in caplog.text


def test_broadcast_scan(mocker, examples_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    datastore.device_options["cip"]["timeout"] = 0.01

    assert not scan_api.broadcast_scan([], [])

    assert scan_api.broadcast_scan(["127.0.0.1"], [ControlLogix]) == (
        {"127.0.0.1": False},
        [ControlLogix],
        ["127.0.0.1"],
    )

    assert scan_api.broadcast_scan(["127.0.0.0/24"], [ControlLogix]) == (
        {"127.0.0.255": False},
        [ControlLogix],
        ["127.0.0.255"],
    )

    assert scan_api.broadcast_scan([examples_path("broadcast_targets.txt")], [ControlLogix]) == (
        {"127.0.0.255": False, "127.0.1.255": False, "127.0.3.255": False},
        [ControlLogix],
        ["127.0.0.255", "127.0.1.255", "127.0.3.255"],
    )


def test_serial_scan(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    assert not scan_api.serial_scan([])
    assert not scan_api.serial_scan(["bogusportlist"])

    results = scan_api.serial_scan(["0"], [])

    assert results
    assert results[0]
    assert results[1] == []
    assert results[2]


def test_check_host_serial():
    assert scan_api.check_host_serial("0", []) is False


def test_run_identify():
    assert scan_api.run_identify(lambda x: x, [], []) == {}


def test_scan_static(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 3,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    assert scan_api.scan(None, "unicast_ip") is None
    assert scan_api.scan([], "unicast_ip") is None
    assert scan_api.scan([], "broadcast_ip") is None
    assert scan_api.scan(None, "broadcast_ip") is None
    assert scan_api.scan([], "serial") is None
    assert scan_api.scan(None, "broadcast_ip") is None
    assert scan_api.scan([], "some bogus scan type lol") is None
