"""Tests for the easYgen data model mapping (peat/modules/woodward/easygen_data.py)."""

import gzip
from pathlib import Path
from typing import Final

import pytest

from peat import DeviceData
from peat.modules.woodward.easygen_data import (
    add_identity,
    add_interfaces_and_services,
    add_io,
    add_registers,
    add_tags,
    add_users,
    canopen_address,
    measurement_type,
    populate_data_model_from_sid,
    populate_data_model_from_wset,
    register_data_type,
)
from peat.modules.woodward.parse_sid import parse_sid
from peat.modules.woodward.parse_wset import parse_wset

from .nrbf_builder import build_sid_file

REAL_WSET_GZ: Final[Path] = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "devices"
    / "woodward"
    / "easygen-3500"
    / "4_MVA_Diesel_20161116.wset.gz"
)


def record(**overrides) -> dict:
    base = {
        "name": "Config_Admin.1702 Device number",
        "group": "Config_Admin",
        "id": 1702,
        "label": "Device number",
        "kind": "basic",
        "type": "integer",
        "value": 1,
        "initial": 1,
        "units": "",
        "size": 16,
        "signed": False,
        "servlink_handle": 2215642790,
        "canopen_multiplexor": 2532865,
        "read_security_level": 0,
        "write_security_level": 2,
    }
    base.update(overrides)
    return base


def test_canopen_address():
    assert canopen_address(2532865) == "0x26A6:01"  # 1702 Device number, EDS object 26A6sub1
    assert canopen_address(6195457) == "0x5E89:01"
    assert canopen_address(0) == "0x0000:00"


@pytest.mark.parametrize(
    ("fields", "data_type", "measurement"),
    [
        ({"type": "integer", "size": 16, "signed": False}, "uint_16", "analog"),
        ({"type": "integer", "size": 32, "signed": True}, "int_32", "analog"),
        ({"type": "integer", "size": None}, "uint", "analog"),
        ({"type": "enumerated", "size": 16}, "uint_16", "analog"),
        ({"type": "boolean"}, "bool", "binary"),
        ({"type": "float"}, "float_32", "analog"),
        ({"type": "string"}, "string", ""),
        ({"type": "bit_field"}, "bool", "binary"),
        ({"type": "bit_fields", "size": 16}, "uint_16", "analog"),
        ({"type": "logics_manager"}, "logics_manager", "binary"),
        ({"type": "array"}, "array", "analog"),
        ({"type": "time"}, "datetime", ""),
        ({"type": "other"}, "other", ""),
    ],
)
def test_register_types(fields, data_type, measurement):
    assert register_data_type(fields) == data_type
    assert measurement_type(fields) == measurement


def test_add_registers():
    dev = DeviceData()
    records = [
        record(),
        record(
            name="Th2GenOverFreq",
            group="",
            id=None,
            label="Th2GenOverFreq",
            servlink_handle=2215642998,
            canopen_multiplexor=None,
        ),
        record(
            name="x.1910 Limit", id=1910, kind="computed", servlink_handle=0, canopen_multiplexor=0
        ),
        record(
            name="x.12110 Relay 2",
            id=12110,
            kind="logics_manager",
            type="logics_manager",
            value={"input_1": {}},
            expression="[x] And [y]",
            servlink_handle=2215653288,
            canopen_multiplexor=None,
        ),
    ]
    assert add_registers(dev, records) == 4
    by_key = {(r.protocol, r.address): r for r in dev.registers}
    servlink = by_key[("servlink", "2215642790")]
    assert servlink.name == "Config_Admin.1702 Device number"
    assert servlink.tag == "Device number"
    assert servlink.description == "Device number (Config_Admin)"
    assert servlink.group == "Config_Admin"
    assert servlink.data_type == "uint_16"
    assert servlink.measurement_type == "analog"
    assert servlink.read_write == "read_write"
    assert servlink.enabled is True
    assert servlink.extra == {
        "parameter": 1702,
        "value": 1,
        "initial": 1,
        "kind": "basic",
        "write_security_level": 2,
        "read_security_level": 0,
    }
    canopen = by_key[("canopen", "0x26A6:01")]
    assert canopen.name == servlink.name
    assert canopen.extra == servlink.extra
    internal = by_key[("servlink", "2215642998")]
    assert internal.name == "Th2GenOverFreq"
    assert internal.group == ""
    assert not [r for r in dev.registers if "1910" in r.name]  # computed values have no handle
    relay = next(r for r in dev.registers if "12110" in r.name)
    assert relay.extra["value"] == "[x] And [y]"
    assert relay.data_type == "logics_manager"
    assert relay.measurement_type == "binary"


def test_add_registers_from_sid_defaults():
    dev = DeviceData()
    records = [
        record(access="ReadWrite", path="PARAMETER.System"),
        record(
            name="12791 Device name",
            id=12791,
            access="",
            type="string",
            servlink_handle=5,
            canopen_multiplexor=None,
        ),
        record(
            name="13714 Reset",
            id=13714,
            access="DeviceOnlyWrite",
            servlink_handle=6,
            canopen_multiplexor=None,
        ),
    ]
    del records[0]["group"]
    assert add_registers(dev, records, defaults_only=True) == 4
    by_name = {}
    for reg in dev.registers:
        by_name.setdefault(reg.name, reg)
    assert by_name["Config_Admin.1702 Device number"].read_write == "read_write"
    assert by_name["Config_Admin.1702 Device number"].group == "PARAMETER.System"
    assert "value" not in by_name["Config_Admin.1702 Device number"].extra
    assert by_name["12791 Device name"].read_write == "read"
    assert by_name["13714 Reset"].read_write == "write"


def test_add_tags():
    dev = DeviceData()
    count = add_tags(
        dev,
        {"0": "00.01 LM: Flag 1", "183": "03.05 Horn", "9": ""},
        {"101": "01.01 Gen.volt.L-N [%]"},
    )
    assert count == 3
    assert [(t.name, t.address, t.type, t.description) for t in dev.tag] == [
        ("00.01 LM: Flag 1", "0", "binary", "LogicsManager command variable"),
        ("03.05 Horn", "183", "binary", "LogicsManager command variable"),
        ("01.01 Gen.volt.L-N [%]", "101", "analog", "AnalogManager data source"),
    ]


def test_add_io():
    dev = DeviceData()
    records = [
        record(
            name="Config_IO.Discrete_In.01.1200 Delay",
            group="Config_IO.Discrete_In.01",
            id=1200,
            label="Delay",
            value=0.2,
        ),
        record(
            name="Config_IO.Discrete_In.01.1201 Operation",
            group="Config_IO.Discrete_In.01",
            id=1201,
            label="Operation",
            value="N.C.",
        ),
        record(
            name="Config_IO.Discrete_Out.02.12110 Relay 2",
            group="Config_IO.Discrete_Out.02",
            id=12110,
            label="Relay 2",
            kind="logics_manager",
            value={"input_1": {}},
            expression=(
                "[NoOperator 03.05 Horn] And [True 00.01 LM: Flag 1] "
                "And [True 00.01 LM: Flag 1], delay on 0 s, delay off 0 s"
            ),
        ),
        record(
            name="Config_IO.Analog_In.03.1100 Type",
            group="Config_IO.Analog_In.03",
            id=1100,
            label="Type",
            value="VDO 5 bar",
        ),
        record(
            name="Config_IO.External_DO.21.12335 External DO 21",
            group="Config_IO.External_DO.21",
            id=12335,
            label="External DO 21",
            kind="logics_manager",
            value={"input_1": {}},
            expression="[x]",
        ),
        record(
            name="PARAMETER.Configure inputs/outputs.Discrete inputs.Discrete input 12.1225 Delay",
            group="PARAMETER.Configure inputs/outputs.Discrete inputs.Discrete input 12",
            id=1225,
            label="Delay",
            value=0.2,
        ),
        record(
            name="Config_IO.Analog_In.Table_A.3550 Y-value 1",
            group="Config_IO.Analog_In.Table_A",
            id=3550,
            label="Y-value 1",
            value=0,
        ),
        record(),
    ]
    assert add_io(dev, records) == 5
    points = {p.id: p for p in dev.io}
    assert set(points) == {"DI 01", "DO 02", "AI 03", "External DO 21", "DI 12"}
    di = points["DI 01"]
    assert di.direction == "input"
    assert di.type == "binary"
    assert di.name == "DI 01"
    assert di.extra == {"group": "Config_IO.Discrete_In.01", "Delay": 0.2, "Operation": "N.C."}
    relay = points["DO 02"]
    assert relay.name == "Relay 2"
    assert relay.direction == "output"
    assert relay.description.startswith("[NoOperator 03.05 Horn]")
    assert relay.extra["Relay 2"].startswith("[NoOperator")
    assert points["AI 03"].type == "analog"
    assert points["AI 03"].description == "Type: VDO 5 bar"
    assert points["External DO 21"].slot == ["external"]
    assert points["External DO 21"].name == "External DO 21"
    assert points["DI 12"].extra["group"].endswith("Discrete input 12")


def test_add_interfaces_and_services():
    dev = DeviceData()
    records = [
        record(
            name="Config_Serial1.3161 Parity",
            group="Config_Serial1",
            id=3161,
            label="Parity",
            value="No",
        ),
        record(
            name="Config_Serial1.3162 Stop bits",
            group="Config_Serial1",
            id=3162,
            label="Stop bits",
            value="One",
        ),
        record(
            name="Config_Serial1.3163 Baudrate",
            group="Config_Serial1",
            id=3163,
            label="Baudrate",
            value="19.2 kBd",
        ),
        record(
            name="Config_Serial1.7900 Enable Modbus protocol",
            group="Config_Serial1",
            id=7900,
            label="Enable Modbus protocol",
            value="Yes",
        ),
        record(
            name="Config_Serial1.Modbus.3185 Modbus slave ID",
            group="Config_Serial1.Modbus",
            id=3185,
            label="Modbus slave ID",
            value=7,
        ),
        record(
            name="Config_Serial1.Modem.4660 Modem initialization string",
            group="Config_Serial1.Modem",
            id=4660,
            label="Modem initialization string",
            value="",
        ),
        record(
            name="Config_Serial2.3170 Baudrate",
            group="Config_Serial2",
            id=3170,
            label="Baudrate",
            value="9.6 kBd",
        ),
        record(
            name="Config_Serial2.3171 Parity",
            group="Config_Serial2",
            id=3171,
            label="Parity",
            value="Even",
        ),
        record(
            name="Config_Serial2.3172 Stop bits",
            group="Config_Serial2",
            id=3172,
            label="Stop bits",
            value="Two",
        ),
        record(
            name="Config_Serial2.3173 Full-, halfduplex mode",
            group="Config_Serial2",
            id=3173,
            label="Full-, halfduplex mode",
            value="Halfduplex",
        ),
        record(
            name="Config_Serial2.Modbus.3188 Modbus slave ID",
            group="Config_Serial2.Modbus",
            id=3188,
            label="Modbus slave ID",
            value=2,
        ),
        record(
            name="Config_CAN1.3156 Baudrate",
            group="Config_CAN1",
            id=3156,
            label="Baudrate",
            value="250 kBd",
        ),
        record(
            name="Config_CAN1.8950 Node-ID CAN bus 1",
            group="Config_CAN1",
            id=8950,
            label="Node-ID CAN bus 1",
            value=1,
        ),
        record(
            name="Config_CAN2.3157 Baudrate",
            group="Config_CAN2",
            id=3157,
            label="Baudrate",
            value="125 kBd",
        ),
        record(
            name="Config_CAN2.J1939.15102 Device type",
            group="Config_CAN2.J1939",
            id=15102,
            label="Device type",
            value="Standard",
        ),
        record(
            name="Modbus.3184 Modbus protocol number",
            group="Modbus",
            id=3184,
            label="Modbus protocol number",
            value=5010,
        ),
        # easYgen-3000XT style IP address parameters
        record(
            name="PARAMETER.Ethernet.5330 IP address",
            group="PARAMETER.Ethernet",
            id=5330,
            label="IP address",
            value=192,
        ),
        record(
            name="PARAMETER.Ethernet.5331 Ethernet A - IP address part 2",
            group="PARAMETER.Ethernet",
            id=5331,
            label="Ethernet A - IP address part 2",
            value=0,
        ),
        record(
            name="PARAMETER.Ethernet.5332 Ethernet A - IP address part 3",
            group="PARAMETER.Ethernet",
            id=5332,
            label="Ethernet A - IP address part 3",
            value=2,
        ),
        record(
            name="PARAMETER.Ethernet.5333 Ethernet A - IP address part 4",
            group="PARAMETER.Ethernet",
            id=5333,
            label="Ethernet A - IP address part 4",
            value=20,
        ),
        record(
            name="PARAMETER.Ethernet.5334 Subnet mask",
            group="PARAMETER.Ethernet",
            id=5334,
            label="Subnet mask",
            value=255,
        ),
        record(
            name="PARAMETER.Ethernet.5335 Ethernet A - subnet mask part 2",
            group="PARAMETER.Ethernet",
            id=5335,
            label="Ethernet A - subnet mask part 2",
            value=255,
        ),
        record(
            name="PARAMETER.Ethernet.5336 Ethernet A - subnet mask part 3",
            group="PARAMETER.Ethernet",
            id=5336,
            label="Ethernet A - subnet mask part 3",
            value=255,
        ),
        record(
            name="PARAMETER.Ethernet.5337 Ethernet A - subnet mask part 4",
            group="PARAMETER.Ethernet",
            id=5337,
            label="Ethernet A - subnet mask part 4",
            value=0,
        ),
        record(
            name="PARAMETER.Ethernet.5338 Gateway IP",
            group="PARAMETER.Ethernet",
            id=5338,
            label="Gateway IP",
            value=192,
        ),
        record(
            name="PARAMETER.Ethernet.5339 Gateway IP part 2",
            group="PARAMETER.Ethernet",
            id=5339,
            label="Gateway IP part 2",
            value=0,
        ),
        record(
            name="PARAMETER.Ethernet.5340 Gateway IP part 3",
            group="PARAMETER.Ethernet",
            id=5340,
            label="Gateway IP part 3",
            value=2,
        ),
        record(
            name="PARAMETER.Ethernet.5341 Gateway IP part 4",
            group="PARAMETER.Ethernet",
            id=5341,
            label="Gateway IP part 4",
            value=1,
        ),
        # A plain dotted address (no parts) on another port, named by the group
        record(
            name="PARAMETER.Ethernet B.5430 IP address",
            group="PARAMETER.Ethernet B",
            id=5430,
            label="IP address",
            value="10.1.1.5",
        ),
        record(),
    ]
    interfaces, services = add_interfaces_and_services(dev, records)
    assert interfaces == 6
    assert services == 4  # Modbus on both serial ports, CANopen on CAN 1, J1939 on CAN 2
    by_name = {i.name: i for i in dev.interface}
    assert set(by_name) == {"Serial 1", "Serial 2", "CAN 1", "CAN 2", "Ethernet A", "Ethernet B"}

    serial1 = by_name["Serial 1"]
    assert serial1.type == "rs_232"
    assert serial1.baudrate == 19200
    assert serial1.parity == "none"
    assert serial1.stop_bits == 1
    assert serial1.extra["modem"] is True
    assert serial1.extra["Baudrate"] == "19.2 kBd"
    assert [(s.protocol, s.enabled, s.extra) for s in serial1.services] == [
        ("modbus", True, {"slave_id": 7, "protocol_number": 5010, "baudrate": 19200})
    ]
    serial2 = by_name["Serial 2"]
    assert serial2.type == "rs_485"
    assert serial2.baudrate == 9600
    assert serial2.parity == "even"
    assert serial2.stop_bits == 2
    assert [(s.protocol, s.enabled, s.extra["slave_id"]) for s in serial2.services] == [
        ("modbus", None, 2)
    ]

    can1 = by_name["CAN 1"]
    assert can1.type == "can"
    assert can1.baudrate == 250000
    assert [(s.protocol, s.extra) for s in can1.services] == [
        ("canopen", {"node_id": 1, "baudrate": 250000})
    ]
    can2 = by_name["CAN 2"]
    assert can2.baudrate == 125000
    assert [s.protocol for s in can2.services] == ["j1939"]

    ethernet = by_name["Ethernet A"]
    assert ethernet.type == "ethernet"
    assert ethernet.ip == "192.0.2.20"
    assert ethernet.subnet_mask == "255.255.255.0"
    assert ethernet.gateway == "192.0.2.1"
    assert by_name["Ethernet B"].ip == "10.1.1.5"  # port from the group name
    assert dev.related.ip == {"192.0.2.20", "10.1.1.5", "192.0.2.1"}  # gateways are related IPs

    assert sorted((s.protocol, s.listen_interface) for s in dev.service) == [
        ("canopen", "CAN 1"),
        ("j1939", "CAN 2"),
        ("modbus", "Serial 1"),
        ("modbus", "Serial 2"),
    ]
    assert dev.related.protocols == {"modbus", "canopen", "j1939"}


def test_add_users_and_identity():
    dev = DeviceData()
    records = [
        record(
            name="P.10415 Password basic",
            group="P",
            id=10415,
            label="Password basic",
            type="string",
            value="1234",
        ),
        record(
            name="P.10430 Password for serial interface",
            group="P",
            id=10430,
            label="Password for serial interface",
            type="string",
            value="0042",
        ),
        record(name="P.10407 Code level", group="P", id=10407, label="Code level", value=2),
        record(
            name="P.2567 Code level for reset maint..",
            group="P",
            id=2567,
            label="Code level for reset maint..",
            value=3,
        ),
        record(
            name="P.1890 Device name",
            group="P",
            id=1890,
            label="Device name",
            type="string",
            value="Genset 7",
        ),
        record(name="P.1702 Device number", group="P", id=1702, label="Device number", value=7),
        record(
            name="P.4589 Time zone",
            group="P",
            id=4589,
            label="Time zone",
            type="enumerated",
            value="UTC+1",
        ),
        record(
            name="P.1700 Language",
            group="P",
            id=1700,
            label="Language",
            type="enumerated",
            value="English",
        ),
        record(
            name="P.12791 Device name",
            group="STATUS",
            id=12791,
            label="Device name",
            type="string",
            value="",
        ),
    ]
    assert add_users(dev, records) == 2
    assert [(u.name, u.extra["password"], u.extra["parameter"]) for u in dev.users] == [
        ("basic", "1234", 10415),
        ("serial interface", "0042", 10430),
    ]
    assert dev.users[0].description == "easYgen password parameter 10415: Password basic"
    assert dev.extra["code_levels"] == {"Code level": 2, "Code level for reset maint..": 3}

    add_identity(dev, records)
    assert dev.name == "Genset 7"
    assert dev.extra["device_number"] == 7
    assert dev.geo.timezone == "UTC+1"
    assert dev.extra["language"] == "English"


def test_populate_from_synthetic_sid():
    dev = DeviceData()
    parsed = parse_sid(build_sid_file())
    counts = populate_data_model_from_sid(dev, parsed)
    assert counts == {"registers": 8, "tags": 2}
    assert {(r.protocol, r.address) for r in dev.registers if "1702" in r.name} == {
        ("servlink", "2756708006"),
        ("canopen", "0x26A6:01"),
    }
    number = next(r for r in dev.registers if "1702" in r.name)
    assert number.read_write == "read_write"
    assert number.group == "PARAMETER.Configure system management"
    assert number.extra["initial"] == 1
    assert "value" not in number.extra
    assert [(t.name, t.type) for t in dev.tag] == [
        ("00.01 LM: Flag 1", "binary"),
        ("02.01 LM FALSE", "binary"),
    ]
    assert dev.related.protocols == {"servlink", "canopen"}


@pytest.fixture(scope="module")
def real_device() -> tuple[DeviceData, dict]:
    parsed = parse_wset(gzip.decompress(REAL_WSET_GZ.read_bytes()))
    dev = DeviceData()
    counts = populate_data_model_from_wset(dev, parsed)
    return dev, counts


def test_real_file_counts(real_device):
    dev, counts = real_device
    assert counts == {
        "registers": 4548,
        "tags": 919,
        "io": 112,
        "interfaces": 5,
        "services": 6,
        "users": 0,
    }
    assert len(dev.registers) == 4548
    assert sum(1 for r in dev.registers if r.protocol == "servlink") == 2274
    assert sum(1 for r in dev.registers if r.protocol == "canopen") == 2274
    assert sum(1 for t in dev.tag if t.type == "binary") == 677
    assert sum(1 for t in dev.tag if t.type == "analog") == 242
    assert dev.related.protocols == {"servlink", "canopen", "modbus", "j1939"}


def test_real_file_registers(real_device):
    dev, _ = real_device
    number = {r.protocol: r for r in dev.registers if r.name == "Config_Admin.1702 Device number"}
    assert number["servlink"].address == "2215642790"
    assert number["canopen"].address == "0x26A6:01"  # matches Woodward's EDS object 26A6sub1
    assert number["canopen"].data_type == "uint_16"
    assert number["canopen"].extra["value"] == 1
    assert number["canopen"].read_write == "read_write"


def test_real_file_io(real_device):
    dev, _ = real_device
    points = {p.id: p for p in dev.io}
    assert len(points) == 112
    assert {p.id.split(" ")[0] for p in dev.io} >= {"DI", "DO", "AI", "AO", "External"}
    relay = points["DO 03"]
    assert relay.name == "Relay 3"
    assert relay.direction == "output"
    assert "03.02" in relay.description
    assert relay.extra["group"] == "Config_IO.Discrete_Out.03"
    di = points["DI 01"]
    assert di.extra["Operation"] == "N.C."
    assert di.extra["Delay"] == 0.2
    assert points["External DO 21"].slot == ["external"]


def test_real_file_interfaces_and_services(real_device):
    dev, _ = real_device
    by_name = {i.name: i for i in dev.interface}
    assert set(by_name) == {"Serial 1", "Serial 2", "CAN 1", "CAN 2", "CAN 3"}
    assert by_name["Serial 1"].type == "rs_232"
    assert by_name["Serial 1"].baudrate == 19200
    assert by_name["Serial 2"].type == "rs_485"
    assert by_name["CAN 1"].baudrate == 250000
    assert sorted((s.protocol, s.listen_interface) for s in dev.service) == [
        ("canopen", "CAN 1"),
        ("canopen", "CAN 2"),
        ("canopen", "CAN 3"),
        ("j1939", "CAN 2"),
        ("modbus", "Serial 1"),
        ("modbus", "Serial 2"),
    ]
    modbus = next(
        s for s in dev.service if s.protocol == "modbus" and s.listen_interface == "Serial 1"
    )
    assert modbus.extra == {"slave_id": 1, "protocol_number": 5010, "baudrate": 19200}
    assert modbus.enabled is True


def test_real_file_identity(real_device):
    dev, _ = real_device
    assert dev.name == ""  # first generation easYgen-3000 settings don't hold a device name
    assert dev.extra["device_number"] == 1
    assert dev.extra["language"] == "English"
    assert dev.extra["code_levels"] == {
        "Code level for reset maint..": 3,
        "Codelevel set operation hours": 2,
    }
    assert dev.users == []


def test_settings_and_sid_registers_and_tags_combine():
    dev = DeviceData()
    assert add_registers(dev, [record(initial=None)]) == 2
    assert add_registers(dev, [record(name="1702 Device number", value=None)], True) == 2
    assert len(dev.registers) == 2
    number = next(r for r in dev.registers if r.protocol == "servlink")
    assert number.name == "Config_Admin.1702 Device number"  # the settings name is kept
    assert number.extra["value"] == 1  # from the settings file
    assert number.extra["initial"] == 1  # from the SID

    # A different parameter with the same address is a separate register
    other = record(name="Config_Admin.1703 Other", label="Other", canopen_multiplexor=None)
    assert add_registers(dev, [other], True) == 1
    assert len(dev.registers) == 3
    assert {r.name for r in dev.registers if r.address == number.address} == {
        number.name,
        "Config_Admin.1703 Other",
    }

    assert add_tags(dev, {"0": "00.01 LM: Flag 1"}, {}) == 1
    assert add_tags(dev, {"0": "00.01 LM: Flag 1", "1": "00.02 LM: Flag 2"}, {"0": "x"}) == 3
    assert sorted((t.type, t.address, t.name) for t in dev.tag) == [
        ("analog", "0", "x"),
        ("binary", "0", "00.01 LM: Flag 1"),
        ("binary", "1", "00.02 LM: Flag 2"),
    ]


def test_add_io_skips_unknown_kinds_and_unnamed_settings(monkeypatch):
    records = [
        record(name="", label="", group="Config_IO.Discrete_In.01", id=1200, value=0.2),
        record(name="x.1201 Operation", label="Operation", group="Config_IO.Discrete_In.01"),
        record(name="x.1300 Delay", label="Delay", group="Config_IO.Discrete_Out.02"),
    ]
    dev = DeviceData()
    assert add_io(dev, records) == 2
    assert dev.io[0].extra == {"group": "Config_IO.Discrete_In.01", "Operation": 1}

    # A kind the group pattern matches but that has no mapping is skipped
    from peat.modules.woodward import easygen_data

    monkeypatch.delitem(easygen_data._IO_KINDS, "discrete_in")
    dev = DeviceData()
    assert add_io(dev, records) == 1
    assert [p.id for p in dev.io] == ["DO 02"]


def test_interface_settings_fallbacks():
    dev = DeviceData()
    records = [
        record(name="S1.Baudrate", group="Config_Serial1", id=3163, label="Baudrate", value="?"),
        record(
            name="S1.Enable",
            group="Config_Serial1",
            id=7900,
            label="Enable Modbus protocol",
            value="Maybe",
        ),
        record(
            name="C1.Node", group="Config_CAN1", id=8950, label="Node-ID CAN bus 1", value=True
        ),
        record(
            name="C2.Node", group="Config_CAN2.CANopen", id=9940, label="This device", value="Off"
        ),
        record(name="C2.J1939", group="Config_CAN2.J1939", id=15166, label="J1939", value=0),
        record(
            name="C2.Type", group="Config_CAN2.J1939", id=15102, label="Device type", value="On"
        ),
        record(name="C3.Node", group="Config_CAN3", id=8952, label="Node-ID CAN bus 3", value=200),
        record(
            name="C3.Type", group="Config_CAN3.J1939", id=15102, label="Device type", value="Off"
        ),
        record(name="C4.Node", group="Config_CAN4", id=8953, label="Node-ID", value="Node-ID 9"),
        record(name="C4.J1939", group="Config_CAN4.J1939", id=15166, label="J1939", value="Yes"),
        record(
            name="C4.Addr", group="Config_CAN4.J1939", id=15106, label="J1939 own address", value=3
        ),
    ]
    assert add_interfaces_and_services(dev, records) == (5, 2)
    by_name = {i.name: i for i in dev.interface}
    assert by_name["Serial 1"].baudrate is None
    assert by_name["Serial 1"].services == []
    assert by_name["CAN 1"].services == []
    assert by_name["CAN 2"].services == []
    assert by_name["CAN 3"].services == []
    assert [(s.protocol, s.extra) for s in by_name["CAN 4"].services] == [
        ("canopen", {"node_id": 9, "baudrate": None}),
        ("j1939", {"address": 3, "device_type": None, "baudrate": None}),
    ]


def test_ethernet_address_fallbacks():
    def address(group: str, first_id: int, label: str, values: list) -> list[dict]:
        # easYgen-3000XT style: "IP address", "Ethernet A - IP address part 2", ...
        port, _, base = label.rpartition(" - ")
        prefix = f"{port} - " if port else ""
        labels = [base] + [f"{prefix}{base} part {n}" for n in range(2, len(values) + 1)]
        return [
            record(
                name=f"{group}.{first_id + i} {lbl}",
                group=group,
                id=first_id + i,
                label=lbl,
                value=v,
            )
            for i, (lbl, v) in enumerate(zip(labels, values, strict=True))
        ]

    records = [
        # Two ports in one group, and a gateway that doesn't name its port
        *address("E", 10, "Ethernet A - IP address", [10, 0, 0, 1]),
        *address("E", 20, "Ethernet B - IP address", [10, 0, 1, 1]),
        *address("E", 30, "Gateway IP", [10, 0, 0, 254]),
        # One port and a gateway conflicting with the port's own gateway
        *address("F", 40, "Ethernet C - IP address", [10, 1, 0, 1]),
        *address("F", 50, "Ethernet C - Gateway IP", [10, 1, 0, 254]),
        *address("F", 60, "Gateway IP", [10, 1, 0, 253]),
        # A port with a gateway but no IP address (not configured)
        *address("G", 70, "Ethernet D - IP address", [0, 0, 0, 0]),
        *address("G", 80, "Ethernet D - Gateway IP", [10, 2, 0, 254]),
        *address("G", 90, "Ethernet D - subnet mask", [255, 255, 255, 0]),
        # Incomplete and invalid addresses are skipped
        *address("H", 100, "Ethernet E - IP address", [10, 3]),
        record(name="H.110 IP address", group="Ethernet F", id=110, label="IP address", value="x"),
        record(name="H.120 IP address", group="Ethernet G", id=120, label="IP address", value=7),
        # A second address of a port, the first one is kept
        record(
            name="I.130 IP address",
            group="ethernet h",
            id=130,
            label="IP address",
            value="10.4.0.1",
        ),
        record(
            name="I.140 IP address",
            group="ethernet h",
            id=140,
            label="IP address",
            value="10.4.0.2",
        ),
        # The same gateway as the port's own one, and subnet masks alone
        *address("J", 150, "Ethernet I - IP address", [10, 5, 0, 1]),
        *address("J", 160, "Ethernet I - Gateway IP", [10, 5, 0, 254]),
        *address("J", 170, "Gateway IP", [10, 5, 0, 254]),
        *address("K", 180, "Ethernet J - subnet mask", [255, 255, 0, 0]),
        *address("L", 190, "subnet mask", [255, 255, 0, 0]),
    ]
    dev = DeviceData()
    assert add_interfaces_and_services(dev, records) == (5, 0)
    assert {(i.name, i.ip, i.gateway) for i in dev.interface} == {
        ("Ethernet A", "10.0.0.1", ""),
        ("Ethernet B", "10.0.1.1", ""),
        ("Ethernet C", "10.1.0.1", "10.1.0.254"),
        ("Ethernet H", "10.4.0.1", ""),
        ("Ethernet I", "10.5.0.1", "10.5.0.254"),
    }
    unassigned = [
        {"group": "ethernet h", "port": "H", "ip": "10.4.0.2"},
        {"group": "E", "gateway": "10.0.0.254"},
        {"group": "F", "gateway": "10.1.0.253"},
        {"group": "G", "port": "D", "subnet_mask": "255.255.255.0", "gateway": "10.2.0.254"},
    ]
    assert dev.extra["unassigned_ethernet_addresses"] == unassigned
    assert {"10.0.0.254", "10.1.0.253", "10.2.0.254", "10.4.0.2"} <= dev.related.ip

    add_interfaces_and_services(dev, records)
    assert dev.extra["unassigned_ethernet_addresses"] == unassigned


def test_minimal_records():
    # No parameter kind, no CANopen addresses, a baudrate in Bd, an Ethernet group without ports
    fields = [
        {},
        {
            "name": "S1.Baud",
            "group": "Config_Serial1",
            "id": 3163,
            "label": "Baudrate",
            "value": "9600 Bd",
        },
        {
            "name": "N.IP",
            "group": "PARAMETER.Network",
            "id": 4000,
            "label": "IP address",
            "value": "10.6.0.1",
        },
    ]
    records = [
        record(kind="", canopen_multiplexor=None, servlink_handle=handle, **overrides)
        for handle, overrides in enumerate(fields, start=1)
    ]
    dev = DeviceData()
    counts = populate_data_model_from_wset(dev, {"parameters": records})
    assert counts["registers"] == 3
    assert all("kind" not in r.extra for r in dev.registers)
    assert {r.protocol for r in dev.registers} == {"servlink"}
    assert dev.related.protocols == {"servlink"}
    assert {(i.name, i.ip, i.baudrate) for i in dev.interface} == {
        ("Serial 1", "", 9600),
        ("Ethernet", "10.6.0.1", None),
    }
    assert "code_levels" not in dev.extra

    dev = DeviceData()
    assert populate_data_model_from_sid(dev, {}) == {"registers": 0, "tags": 0}
    assert not dev.related.protocols
