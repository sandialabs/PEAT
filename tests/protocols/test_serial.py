import pytest

from peat.protocols import serial


def test_port_nums_to_addresses(mocker):
    mocker.patch("peat.consts.POSIX", True)

    assert not serial.port_nums_to_addresses(None)
    assert not serial.port_nums_to_addresses([])
    assert not serial.port_nums_to_addresses(["xyz", "a"])

    # non-zero result, length depends on platform
    result = serial.port_nums_to_addresses(["0-2", "0", "1-2"])
    assert result == [
        "/dev/ttyACM0",
        "/dev/ttyACM1",
        "/dev/ttyACM2",
        "/dev/ttyS0",
        "/dev/ttyS1",
        "/dev/ttyS2",
        "/dev/ttyUSB0",
        "/dev/ttyUSB1",
        "/dev/ttyUSB2",
    ]


def test_platform_port_fmt(mocker):
    mocker.patch("peat.consts.POSIX", True)
    linux_res = serial.platform_port_fmt(0)
    assert "/dev/ttyS0" in linux_res
    assert "/dev/ttyUSB0" in linux_res
    assert "/dev/ttyACM0" in linux_res
    assert len(linux_res) == 3

    mocker.patch("peat.consts.POSIX", False)
    mocker.patch("peat.consts.WINDOWS", True)
    assert "COM10" in serial.platform_port_fmt(10)
    assert len(serial.platform_port_fmt(10)) == 1

    mocker.patch("peat.consts.POSIX", False)
    mocker.patch("peat.consts.WINDOWS", False)
    with pytest.raises(OSError):
        serial.platform_port_fmt(6)


def test_isint():
    assert serial.isint("12")
    assert not serial.isint("9.5")
    assert not serial.isint("x")
    assert not serial.isint("-")


def test_parse_baudrates():
    assert not serial.parse_baudrates(None)
    assert not serial.parse_baudrates([])
    assert not serial.parse_baudrates(["xyz", "a"])
    assert serial.parse_baudrates(["9600-115200", "57600"]) == [
        9600,
        19200,
        38400,
        57600,
        115200,
    ]


def test_pretty_hex_bytes():
    assert serial.pretty_hex_bytes(None) == "0x None"
    assert serial.pretty_hex_bytes(bytearray([0, 1, 2])) == "0x 00 01 02"
