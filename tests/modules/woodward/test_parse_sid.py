"""Tests for the Woodward ToolKit SID parser (peat/modules/woodward/parse_sid.py)."""

import gzip
import io
from typing import Final

import pytest

from peat import DeviceData
from peat.modules.woodward.parse_sid import (
    is_sid_data,
    parse_sid,
    populate_device_from_sid,
    read_sid_xml,
    sid_signature_check,
    split_item_name,
    summarize_sid,
)

from .nrbf_builder import SID_HEADER, build_generic_wset, build_sid_file, build_sid_xml

IDENTIFIER: Final[str] = "EG3200XTP1 2.12-0_50976"


@pytest.fixture(scope="module")
def sid_file() -> bytes:
    return build_sid_file(IDENTIFIER)


@pytest.fixture(scope="module")
def sid_xml() -> bytes:
    return build_sid_xml(IDENTIFIER)


@pytest.fixture(scope="module")
def parsed(sid_file) -> dict:
    return parse_sid(sid_file)


def test_is_sid_data(sid_file, sid_xml):
    assert is_sid_data(sid_file)
    assert is_sid_data(sid_file[:1024])  # partial gzip stream
    assert is_sid_data(sid_xml)
    assert is_sid_data(gzip.compress(sid_xml))  # bare gzip
    assert not is_sid_data(b"")
    assert not is_sid_data(b"<xml/>")
    assert not is_sid_data(SID_HEADER + b"\x1f\x8b\x08garbage")
    assert not is_sid_data(build_generic_wset())


def test_sid_signature_check(sid_file):
    assert sid_signature_check(io.BytesIO(sid_file))
    assert not sid_signature_check(io.BytesIO(b"nope"))


def test_read_sid_xml(sid_file, sid_xml):
    xml_data, info = read_sid_xml(sid_file)
    assert xml_data == sid_xml
    assert info["compressed"] is True
    assert info["header"]["type"] == "sid"

    xml_data, info = read_sid_xml(sid_xml)
    assert xml_data == sid_xml
    assert info == {"header": {}, "compressed": False}

    with pytest.raises(ValueError, match="Not a Service Interface Definition"):
        read_sid_xml(b"<other/>")
    with pytest.raises(ValueError, match="decompress"):
        read_sid_xml(SID_HEADER + b"\x1f\x8b\x08garbage")


def test_header_and_application(parsed):
    assert parsed["header"]["type"] == "sid"
    assert parsed["header"]["known"] is True
    assert parsed["compressed"] is True
    assert parsed["schema"] == "Sid21.xsd"
    assert parsed["identifier"] == IDENTIFIER
    assert parsed["specification"] == IDENTIFIER
    assert parsed["application_description"] == IDENTIFIER
    assert parsed["identifier_address"] == "974848"
    assert parsed["is_most_significant_byte_first"] is True
    assert parsed["application"]["model"] == "3200XT-P1"
    assert parsed["application"]["product"] == "easYgen-3200XT-P1"
    assert parsed["application"]["version"] == "2.12-0"
    assert parsed["nonvolatile_protocol"] == "ServlinkSaveValues"
    assert parsed["settings_policies"] == {"AllowPartial": "true"}
    assert parsed["namespaces"] == ["STATUS MENU", "PARAMETER"]


def test_security(parsed):
    assert parsed["security"] == {
        "servlink": {
            "accounts": [{"type": "Account", "Name": "service", "Level": "3"}],
            "command_security_levels": {"Browse": 2, "Save Values": 5},
        }
    }


def test_counts(parsed):
    assert parsed["num_parameters"] == 7
    assert parsed["parameter_kinds"] == {"data_item": 5, "logics_manager": 1, "structure_item": 1}
    assert parsed["parameter_types"] == {
        "string": 1,
        "float": 1,
        "integer": 1,
        "boolean": 1,
        "bit_fields": 1,
        "logics_manager": 1,
        "structure": 1,
    }
    assert parsed["parameter_namespaces"] == {"STATUS MENU": 2, "PARAMETER": 5}
    assert parsed["parameter_access"] == {"": 4, "ReadWrite": 3}
    assert parsed["num_enumerations"] == 2
    assert parsed["events"] == {"2112": "Overspeed 1"}
    assert parsed["structures"] == {
        "AnalogManagerType1": [
            {
                "name": "Analog1",
                "type": "integer",
                "size": 16,
                "signed": False,
                "enumeration": "ENUM_LOGLIST1.LOGICLIST1",
            },
            {"name": "Constant1", "type": "float", "precision": "Single"},
        ]
    }
    assert parsed["enumerations"]["ENUM_4104"] == {
        "else": "!!!",
        "options": {"0": "Off", "1": "On"},
    }


def test_data_item_records(parsed):
    records = {r["name"]: r for r in parsed["parameters"]}

    number = records["1702 Device number"]
    assert number == {
        "name": "1702 Device number",
        "id": 1702,
        "label": "Device number",
        "path": "PARAMETER.Configure system management",
        "kind": "data_item",
        "type": "integer",
        "size": 32,
        "access": "ReadWrite",
        "address": "960212",
        "servlink_handle": 2756708006,
        "canopen_multiplexor": 2532865,
        "initial": 1,
        "minimum": 1,
        "maximum": 32,
        "units": "",
        "description": "",
        "read_security_level": None,
        "write_security_level": 2,
    }

    monitoring = records["4104 Monitoring"]
    assert monitoring["type"] == "boolean"
    assert monitoring["enumeration"] == "ENUM_4104"
    assert monitoring["options"] == {"0": "Off", "1": "On"}
    assert monitoring["initial"] == 1
    assert monitoring["read_security_level"] == 1
    assert monitoring["write_security_level"] == 2
    assert monitoring["canopen_multiplexor"] is None

    name = records["12791 Device name"]
    assert name["path"] == "STATUS MENU.Diagnostic"
    assert name["type"] == "string"
    assert name["max_size"] == 39
    assert name["encoding"] == "UTF-8"
    assert name["initial"] is None

    temperature = records["10287 Diff.out/inlet temp."]
    assert temperature["type"] == "float"
    assert temperature["precision"] == "Single"
    assert temperature["units"] == "°C"
    assert temperature["minimum"] == -32768.0
    assert temperature["maximum"] == 32767.0

    lamps = records["15395 J1939 DM1 Lamp state"]
    assert lamps["type"] == "bit_fields"
    assert lamps["size"] == 32
    assert lamps["units"] == "hex"
    assert lamps["fields"] == [
        {"name": "DM1 Protection lamp", "position": 0, "size": 4, "enumeration": "ENUM_4104"},
        {"name": "DM1 Amber warning lamp", "position": 4, "size": 4, "enumeration": ""},
    ]


def test_logics_manager_record(parsed):
    record = next(r for r in parsed["parameters"] if r["kind"] == "logics_manager")
    assert record["name"] == "12922 Ext. mns.decoupl."
    assert record["id"] == 12922
    assert record["input_enumerations"] == ["ENUM_LOGLIST1.LOGICLIST1"] * 3
    assert record["delay_units"] == "s"
    assert record["delay_on_text"] == "Delay ON"
    assert record["servlink_handle"] == 2320511610
    assert record["write_security_level"] == 2
    assert record["initial_text"] == "0 0 False And True And True 201 201 0"
    assert record["initial"] == {
        "delay_on": 0.0,
        "delay_off": 0.0,
        "operator_1": "False",
        "binary_operator_1": "And",
        "operator_2": "True",
        "binary_operator_2": "And",
        "operator_3": "True",
        "input_1": {"value": 201, "name": "02.01 LM FALSE"},
        "input_2": {"value": 201, "name": "02.01 LM FALSE"},
        "input_3": {"value": 0, "name": "00.01 LM: Flag 1"},
    }


def test_structure_item_record(parsed):
    record = next(r for r in parsed["parameters"] if r["kind"] == "structure_item")
    assert record["name"] == "5780 AM Ext.mains act.pwr"
    assert record["structure"] == "AnalogManagerType1"
    assert record["type"] == "structure"
    assert record["access"] == "ReadWrite"
    assert record["initial"] == "601 1001 201 201 0 5 0"
    assert record["servlink_handle"] == 2320504468
    assert record["write_security_level"] == 2


def test_plain_xml_and_sources(parsed, sid_xml, tmp_path):
    from_xml = parse_sid(sid_xml)
    assert from_xml["header"] == {}
    assert from_xml["compressed"] is False
    assert from_xml["parameters"] == parsed["parameters"]

    path = tmp_path / "test.sid"
    path.write_bytes(build_sid_file(IDENTIFIER))
    assert parse_sid(path)["parameters"] == parsed["parameters"]
    with path.open("rb") as stream:
        assert parse_sid(stream)["parameters"] == parsed["parameters"]
    assert parse_sid(io.BytesIO(sid_xml))["identifier"] == IDENTIFIER


def test_without_enumerations(sid_file):
    parsed = parse_sid(sid_file, include_enumerations=False)
    assert "enumerations" not in parsed
    assert parsed["num_enumerations"] == 2
    # Options are still resolved for the records
    monitoring = next(r for r in parsed["parameters"] if r["name"] == "4104 Monitoring")
    assert monitoring["options"] == {"0": "Off", "1": "On"}


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"not xml at all", id="text"),
        pytest.param(b"<?xml version='1.0'?><Other/>", id="other xml"),
        pytest.param(b"<ServiceInterfaceDefinition><Unclosed>", id="broken xml"),
        pytest.param(SID_HEADER + b"\x1f\x8b\x08garbage", id="bad gzip"),
        pytest.param(build_sid_file(IDENTIFIER)[:-20], id="truncated gzip"),
        pytest.param(build_sid_file(IDENTIFIER) + b"trailing", id="trailing garbage"),
        pytest.param(b"<Wrapper><ServiceInterfaceDefinition/></Wrapper>", id="wrong root element"),
        pytest.param(build_generic_wset(), id="wset"),
    ],
)
def test_invalid_data(data):
    assert parse_sid(data) == {}


def test_unsupported_source():
    assert parse_sid(12345) == {}  # type: ignore[arg-type]
    assert parse_sid(io.StringIO("<ServiceInterfaceDefinition/>")) == {}  # type: ignore[arg-type]


def test_text_in_xml_elements():
    xml = (
        b'<ServiceInterfaceDefinition Identifier="X">'
        b'<Namespace Name="N"><DataItem Name="7 Seven"><Float/>'
        b"<Description>desc</Description><InitialValue>1.5</InitialValue>"
        b'<Minimum><DataItemReference Name="low"/></Minimum>'
        b"<Maximum>9</Maximum>"
        b'<Custom Flag="1"/>'
        b'</DataItem><DataItem Name="NoType"/></Namespace>'
        b"</ServiceInterfaceDefinition>"
    )
    parsed = parse_sid(xml)
    record = parsed["parameters"][0]
    assert record["description"] == "desc"
    assert record["initial"] == 1.5
    assert record["minimum"] == "DataItemReference Name=low"
    assert record["maximum"] == 9.0
    assert record["extra"] == {"Custom": {"Flag": "1"}}
    assert parsed["parameters"][1]["type"] == "unknown"
    assert parsed["parameters"][1]["id"] is None
    assert parsed["application"]["model"] == ""


def test_unusual_elements_and_attributes():
    xml = (
        b'<ServiceInterfaceDefinition Identifier="X" IsMostSignificantByteFirst="maybe">'
        b'<SecurityProtocols><Servlink><Accounts><Password Level="1">secret</Password>'
        b"</Accounts></Servlink><Other/></SecurityProtocols>"
        b'<Enumeration Else="!!!"><Element Name="Unnamed" Value="0"/></Enumeration>'
        b'<Structure Name="S"><Comment/><Field Name="F"><Integer Size="8"/></Field></Structure>'
        b'<Namespace Name="N">'
        b'<DataItem Name="100 Odd values" Access="ReadWrite">'
        b'<Float IsSigned="maybe" Precision="Single"/>'
        b'<CommunicationProperties><Servlink Handle="0x10"/><CANopen Multiplexor="12"/>'
        b'<Modbus Register="40001"/></CommunicationProperties>'
        b"<InitialValue>not a number</InitialValue>"
        b"<Minimum><Constant>low</Constant></Minimum>"
        b'<Security Operation="Write" Level="high"/><Security Operation="Execute" Level="1"/>'
        b"</DataItem>"
        b'<DataItem Name="101 Count"><Integer/><InitialValue>none</InitialValue></DataItem>'
        b'<LogicManager Name="200 LM short"><InitialValue>0 0 True</InitialValue></LogicManager>'
        b'<StructureItem Name="300 SI" Structure="S" Persist="yes"/>'
        b"</Namespace></ServiceInterfaceDefinition>"
    )
    parsed = parse_sid(xml)
    assert parsed["is_most_significant_byte_first"] is None
    assert parsed["security"] == {
        "servlink": {
            "accounts": [{"type": "Password", "Level": "1", "text": "secret"}],
            "command_security_levels": {},
        },
        "other": {"accounts": [], "command_security_levels": {}},
    }
    assert parsed["num_enumerations"] == 0
    assert parsed["structures"] == {"S": [{"name": "F", "type": "integer", "size": 8}]}

    item, count, logic, structure = parsed["parameters"]
    assert count["initial"] == "none"
    assert "signed" not in item
    assert item["servlink_handle"] is None
    assert item["canopen_multiplexor"] == 12
    assert item["modbus_properties"] == {"Register": "40001"}
    assert item["initial"] == "not a number"
    assert item["minimum"] == "low"
    assert item["maximum"] is None
    assert item["read_security_level"] is None
    assert item["write_security_level"] is None

    assert logic["initial"] == {"text": "0 0 True"}
    assert logic["servlink_handle"] is None
    assert structure["extra"] == {"Persist": "yes"}
    assert structure["initial"] is None


def test_no_data_items():
    parsed = parse_sid(b'<ServiceInterfaceDefinition Identifier="EG3500XTP2 2.17-0_54728"/>')
    assert parsed["num_parameters"] == 0
    assert parsed["parameters"] == []
    assert parsed["namespaces"] == []
    assert parsed["events"] == {}
    assert parsed["application"]["model"] == "3500XT-P2"
    assert parsed["header"] == {}


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("1702 Device number", (1702, "Device number")),
        ("  10287 Diff.out/inlet temp. ", (10287, "Diff.out/inlet temp.")),
        ("OUT_1", (None, "OUT_1")),
        ("12 ab", (12, "ab")),
        ("1 x", (None, "1 x")),
        ("", (None, "")),
    ],
)
def test_split_item_name(name, expected):
    assert split_item_name(name) == expected


def test_summarize_and_populate(parsed):
    summary = summarize_sid(parsed)
    assert "parameters" not in summary
    assert "enumerations" not in summary
    assert summary["num_parameters"] == 7
    assert summary["num_events"] == 1
    assert summary["num_structures"] == 1
    assert summary["application"]["model"] == "3200XT-P1"

    dev = DeviceData()
    populate_device_from_sid(dev, parsed)
    assert dev.description.brand == "easYgen"
    assert dev.description.model == "3200XT-P1"
    assert dev.description.product == "easYgen-3200XT-P1"
    assert dev.firmware.id == IDENTIFIER
    assert dev.firmware.version == "2.12-0"
    assert {k: v for k, v in dev.extra["sid"].items() if k in summary} == summary
    assert dev.extra["sid"]["data_model"] == {"registers": 8, "tags": 2}
    assert len(dev.registers) == 8
    assert [user.name for user in dev.users] == ["service"]
    assert dev.users[0].description == "servlink account"
    assert dev.users[0].extra["Level"] == "3"

    unknown = DeviceData()
    populate_device_from_sid(unknown, parse_sid(build_sid_xml("5418-9999-NEW")))
    assert unknown.description.model == "unknown"
    assert unknown.firmware.id == "5418-9999-NEW"

    empty = DeviceData()
    populate_device_from_sid(empty, {})
    assert not empty.extra
