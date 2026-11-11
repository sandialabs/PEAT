import pytest

from peat.protocols import serial


def test_port_nums_to_addresses(mocker):
    mocker.patch("peat.consts.MACOS", False)
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

    # Paths are used as-is, including paths with dashes in them
    assert serial.port_nums_to_addresses(
        ["/dev/serial/by-id/usb-FTDI_FT232R-if00-port0", " COM3 ", "/dev/ttyS0"]
    ) == ["/dev/serial/by-id/usb-FTDI_FT232R-if00-port0", "/dev/ttyS0", "COM3"]


MACOS_PORTS = [
    "/dev/cu.debug-console",
    "/dev/tty.debug-console",
    "/dev/cu.Bluetooth-Incoming-Port",
    "/dev/tty.Bluetooth-Incoming-Port",
    "/dev/cu.usbserial-A10KJ3XB",
    "/dev/tty.usbserial-A10KJ3XB",
    "/dev/cu.usbserial-1410",
    "/dev/tty.usbserial-1410",
]


def _mock_comports(mocker, devices):
    mocker.patch.object(
        serial.list_ports,
        "comports",
        return_value=[mocker.MagicMock(device=d) for d in devices],
    )


def test_macos_serial_ports(mocker):
    _mock_comports(mocker, MACOS_PORTS)
    assert serial.macos_serial_ports() == [
        "/dev/cu.usbserial-1410",
        "/dev/cu.usbserial-A10KJ3XB",
    ]

    _mock_comports(mocker, [])
    assert serial.macos_serial_ports() == []


def test_port_nums_to_addresses_macos(mocker):
    mocker.patch("peat.consts.MACOS", True)
    mocker.patch("peat.consts.POSIX", True)
    _mock_comports(mocker, MACOS_PORTS)

    # device name, with or without the "cu." prefix, or the path
    for name in [
        "usbserial-1410",
        "cu.usbserial-1410",
        "USBSERIAL-1410",
        "/dev/cu.usbserial-1410",
    ]:
        assert serial.port_nums_to_addresses([name]) == ["/dev/cu.usbserial-1410"]
    assert serial.port_nums_to_addresses(["usbserial-9999", "xyz"]) == []
    assert serial.macos_ports_by_name("usbserial") == []

    # devices are enumerated once per call, not once per value
    serial.list_ports.comports.reset_mock()
    assert serial.port_nums_to_addresses(["usbserial-1410", "usbserial-A10KJ3XB"]) == [
        "/dev/cu.usbserial-1410",
        "/dev/cu.usbserial-A10KJ3XB",
    ]
    assert serial.list_ports.comports.call_count == 1


def test_port_nums_to_addresses_macos_indexes(mocker):
    mocker.patch("peat.consts.MACOS", True)
    mocker.patch("peat.consts.POSIX", True)
    _mock_comports(mocker, MACOS_PORTS)

    # numbers are an index into the sorted list of devices
    assert serial.platform_port_fmt(0) == ["/dev/cu.usbserial-1410"]
    assert serial.platform_port_fmt(1) == ["/dev/cu.usbserial-A10KJ3XB"]
    assert serial.platform_port_fmt(2) == []
    assert serial.port_nums_to_addresses(["0"]) == ["/dev/cu.usbserial-1410"]
    assert serial.port_nums_to_addresses(["0-4"]) == [
        "/dev/cu.usbserial-1410",
        "/dev/cu.usbserial-A10KJ3XB",
    ]
    assert serial.port_nums_to_addresses(["5", "2-4"]) == []
    # the number at the end of a device name isn't an index
    assert serial.port_nums_to_addresses(["1410"]) == []

    # numbers, ranges, and names can be mixed
    serial.list_ports.comports.reset_mock()
    assert serial.port_nums_to_addresses(["0-100", "usbserial-A10KJ3XB"]) == [
        "/dev/cu.usbserial-1410",
        "/dev/cu.usbserial-A10KJ3XB",
    ]
    # devices are enumerated once per call, not once per number
    assert serial.list_ports.comports.call_count == 1


def test_port_nums_to_addresses_macos_name_with_com(mocker):
    mocker.patch("peat.consts.MACOS", True)
    mocker.patch("peat.consts.POSIX", True)
    _mock_comports(mocker, ["/dev/cu.usbserial-Telecom1", "/dev/cu.usbserial-0001"])
    for name in ["usbserial-Telecom1", "cu.usbserial-telecom1"]:
        assert serial.port_nums_to_addresses([name]) == ["/dev/cu.usbserial-Telecom1"]


def test_port_nums_to_addresses_macos_path_skips_enumeration(mocker):
    mocker.patch("peat.consts.MACOS", True)
    mocker.patch("peat.consts.POSIX", True)
    _mock_comports(mocker, MACOS_PORTS)
    assert serial.port_nums_to_addresses(["/dev/cu.usbserial-0001"]) == ["/dev/cu.usbserial-0001"]
    assert serial.list_ports.comports.call_count == 0


def test_port_nums_to_addresses_windows_device_path(mocker):
    mocker.patch("peat.consts.MACOS", False)
    mocker.patch("peat.consts.POSIX", False)
    mocker.patch("peat.consts.WINDOWS", True)
    assert serial.port_nums_to_addresses(["\\\\.\\COM10", "COM3"]) == [
        "COM3",
        "\\\\.\\COM10",
    ]
    # unchanged from before macOS support: lowercase and dashed COM values are rejected
    assert serial.port_nums_to_addresses(["com3", "0-COM3"]) == []


def test_platform_port_fmt(mocker):
    mocker.patch("peat.consts.MACOS", False)
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
