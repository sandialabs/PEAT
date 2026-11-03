"""Tests for the Woodward ToolKit settings file parser (peat/modules/woodward/parse_wset.py)."""

import io
import json
from array import array
from collections import namedtuple
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Final

import pytest

from peat import DeviceData
from peat.modules.woodward import parse_wset as parse_wset_module
from peat.modules.woodward.parse_wset import (
    INTERNAL_GROUP,
    LOGICS_MANAGER_BINARY_OPERATORS,
    LOGICS_MANAGER_UNARY_OPERATORS,
    WSET_HEADER_LEN,
    WSET_SNIFF_LEN,
    _descriptor_type,
    _hashtable_items,
    _scale,
    _text_value,
    _to_bool,
    _to_float,
    _to_int,
    application_info,
    easygen_parameter_names,
    extract_generic_parameters,
    extract_settings,
    find_nrbf_offset,
    is_settings_table,
    is_wset_data,
    parameter_record,
    parse_wset,
    populate_device_from_wset,
    read_nrbf_streams,
    save_wset_logic,
    split_parameter_name,
    summarize_wset,
    to_plain,
    wset_head_application_info,
    wset_signature_check,
)

from .nrbf_builder import (
    DEFAULT_PARAMETERS,
    E3_APP_ID,
    E3_PARAMETERS,
    WSET_HEADER,
    build_e3_wset,
    build_generic_streams,
    build_generic_wset,
    build_woodward_wset,
    build_woodward_wtool,
)
from .real_files import (
    DIESEL_WSET,
    NG_WSET,
    REAL_WSET_PARAMS_SLOW,
    real_wset_bytes,
    real_wset_parsed,
)

#: Application identifier of the 2301E factory default settings file of revision G,
#: published by Woodward (https://support.woodward.com/kb/articles/factory-settings-files-for-2301e)
APP_ID_2301E: Final[str] = "5418-6350_G 2017-04-24 10.52.31"

#: Real easYgen-3500 settings files: the size of the parameter hashtable stream,
#: and values of parameters that differ between the files
REAL_FILE_SPECIFICS: Final[dict[str, dict]] = {
    DIESEL_WSET: {
        "end": 1955903,
        "values": {
            "Config_Application.Engine.3321 Start/Stop mode logic": "Diesel",
            "Config_Measurement.1752 Gen.. rated active power [kW]": 3400.0,
            "Config_Measurement.1754 Generator rated current": 300,
            "Config_Monitoring.Load_Share.4060 Monitoring": "Off",
        },
    },
    NG_WSET: {
        "end": 1955902,
        "values": {
            "Config_Application.Engine.3321 Start/Stop mode logic": "Gas",
            "Config_Measurement.1752 Gen.. rated active power [kW]": 3150.0,
            "Config_Measurement.1754 Generator rated current": 263,
            "Config_Monitoring.Load_Share.4060 Monitoring": "On",
        },
    },
}


@pytest.fixture(scope="module")
def real_wset_path(tmp_path_factory, real_wset_name) -> Path:
    """The example settings file, decompressed into a temporary directory."""
    path = tmp_path_factory.mktemp("woodward") / real_wset_name
    path.write_bytes(real_wset_bytes(real_wset_name))
    return path


@pytest.fixture(scope="module")
def real_parsed(real_wset_name) -> dict:
    return real_wset_parsed(real_wset_name)


@pytest.fixture(scope="module")
def synthetic_wset() -> bytes:
    return build_woodward_wset()


@pytest.fixture(scope="module")
def synthetic_parsed(synthetic_wset) -> dict:
    return parse_wset(synthetic_wset)


# ---------------------------------------------------------------------------
# Real easYgen-3500 files
# ---------------------------------------------------------------------------


def test_real_file_container(real_parsed, real_wset_name):
    assert real_parsed["header"] == {
        "hex": "143ab51fd46d59c21400",
        "length": 10,
        "type": "wset",
        "type_code": 0x14,
        "format_version": 0x14,
        "known": True,
    }
    nrbf = real_parsed["nrbf"]
    assert nrbf["offset"] == 10
    assert nrbf["errors"] == []
    assert nrbf["trailing_bytes"] == 0
    assert [(s["offset"], s["end"], s["class"]) for s in nrbf["streams"]] == [
        (10, 597, "Woodward_Settings_SettingsHeader"),
        (597, REAL_FILE_SPECIFICS[real_wset_name]["end"], "System_Collections_Hashtable"),
    ]


def test_real_file_settings_header(real_parsed):
    assert real_parsed["settings_header"] == {
        "sid_specification": "us_5418-6722-NEW",
        "sid_identifier": {"app_id_string": "5418-6722-NEW", "file_extension": ".sid"},
        "notes": "",
        "application_description": "5418-6722-NEW",
        "strict_specification_compatibility": False,
        "partial_settings_creation_allowed": True,
        "is_partial": False,
        "load_message": "",
        "show_load_message_as_warning": True,
    }
    assert real_parsed["application"] == {
        "id": "5418-6722-NEW",
        "part_number": "5418-6722",
        "revision": "NEW",
        "version": "",
        "build": "",
        "brand": "easYgen",
        "model": "3500",
        "product": "easYgen-3500",
        "sid": "us_5418-6722-NEW",
    }


def test_real_file_counts(real_parsed):
    assert real_parsed["num_parameters"] == 2756
    assert real_parsed["parameter_kinds"] == {
        "basic": 2144,
        "computed": 418,
        "logics_manager": 130,
        "bit_field": 64,
    }
    assert real_parsed["parameter_types"] == {
        "integer": 912,
        "enumerated": 1090,
        "float": 418,
        "string": 138,
        "logics_manager": 130,
        "bit_field": 64,
        "bit_fields": 4,
    }
    groups = real_parsed["groups"]
    assert groups["Config_Monitoring"] == 995
    assert groups["Config_IO"] == 658
    assert groups["Config_Admin"] == 36
    assert groups["Modbus"] == 4
    assert groups[INTERNAL_GROUP] == 418
    assert len(real_parsed["logics_manager_inputs"]) == 677
    assert len(real_parsed["analog_manager_inputs"]) == 242
    assert real_parsed["analog_manager_inputs"]["2"] == "00.03 Speed bias"
    assert real_parsed["logics_manager_inputs"]["0"] == "00.01 LM: Flag 1"
    assert real_parsed["logics_manager_inputs"]["1274"].startswith("28.06 Command 6 to LS5")
    # Every parameter has a value and a unique name
    assert all(record["value"] is not None for record in real_parsed["parameters"])
    assert all(record["kind"] != "error" for record in real_parsed["parameters"])
    names = [record["name"] for record in real_parsed["parameters"]]
    assert len(set(names)) == len(names)
    # Sorted by group, parameter number, name
    keys = [(r["group"], r["id"] or 0, r["name"]) for r in real_parsed["parameters"]]
    assert keys == sorted(keys)


def test_real_file_is_json_serializable(real_parsed):
    assert json.loads(json.dumps(real_parsed))["num_parameters"] == 2756


def test_real_file_specific_values(real_parsed, real_wset_name):
    values = {record["name"]: record["value"] for record in real_parsed["parameters"]}
    for name, value in REAL_FILE_SPECIFICS[real_wset_name]["values"].items():
        assert values[name] == value, name


def test_real_files_differ_only_in_values():
    diesel = real_wset_parsed(DIESEL_WSET)
    ng = real_wset_parsed(NG_WSET)
    assert diesel["application"] == ng["application"]
    assert [r["name"] for r in diesel["parameters"]] == [r["name"] for r in ng["parameters"]]
    differing = [
        a["name"]
        for a, b in zip(diesel["parameters"], ng["parameters"], strict=True)
        if a["value"] != b["value"]
    ]
    assert len(differing) == 23


@pytest.fixture(scope="module")
def real_records(real_parsed) -> dict[str, dict]:
    return {record["name"]: record for record in real_parsed["parameters"]}


def test_real_basic_integer(real_records):
    assert real_records["Config_Admin.1702 Device number"] == {
        "name": "Config_Admin.1702 Device number",
        "group": "Config_Admin",
        "id": 1702,
        "label": "Device number",
        "class": "Woodward_DataAccess_BasicParameter",
        "kind": "basic",
        "type": "integer",
        "value": 1,
        "value_text": "1",
        "initial": 1,
        "minimum": 1,
        "maximum": 32,
        "size": 16,
        "signed": False,
        "units": "",
        "description": "",
        "read_security_level": 0,
        "write_security_level": 2,
        "servlink_handle": 2215642790,
        "canopen_multiplexor": 2532865,
        "access_type": 1,
        "nonvolatile_group_id": 0,
    }


def test_real_computed_float(real_records):
    record = real_records["Config_Monitoring.Generator.Overfrequency level 2.1910 Limit"]
    assert record["kind"] == "computed"
    assert record["type"] == "float"
    assert record["value"] == 115.0
    assert record["source"] == "Th2GenOverFreq"
    assert record["source_value"] == 1150
    assert record["multiplier"] == 0.1
    assert record["offset"] == 0.0
    assert record["units"] == "%"
    assert record["minimum"] == 50.0
    assert record["maximum"] == 140.0
    assert record["initial"] == 115.0  # from the source's default of 1150
    # The source is an internal variable without a parameter number
    source = real_records["Th2GenOverFreq"]
    assert source["group"] == ""
    assert source["id"] is None
    assert source["value"] == 1150
    assert source["access_type"] == 3


def test_real_enumerated(real_records):
    record = real_records["Config_IO.External_DI.17.16009 Self acknowledge"]
    assert record["type"] == "enumerated"
    assert record["value"] == "No"
    assert record["enum_value"] == 0
    assert record["options"] == {"1": "Yes", "0": "No"}
    assert record["enum_name"] == "ENUM_16190"
    assert record["initial"] == "No"
    assert record["write_security_level"] == 2


def test_real_string(real_records):
    record = real_records["Config_Monitoring.FlexLimit.16.7196 Description"]
    assert record["type"] == "string"
    assert record["value"] == "Flex. limit 16"
    assert record["max_size"] == 49
    assert record["minimum"] is None


def test_real_bit_fields(real_records):
    base = real_records["Config_Application.Emergency_Run.2808 Emergency start Seg No 49-64"]
    assert base["type"] == "bit_fields"
    assert base["value"] == 0
    assert base["maximum"] == 65535
    assert len(base["bit_fields"]) == 16
    assert base["bit_fields"][0] == {"name": "Segment 49", "position": 0, "size": 1}

    bit = real_records[
        "Config_Application.Emergency_Run.2807 Emergency start Seg No 33-48-Segment 44"
    ]
    assert bit["kind"] == "bit_field"
    assert bit["value"] is False
    assert bit["bit_position"] == 11
    assert bit["bit_size"] == 1
    assert bit["base_value"] == 0
    assert (
        bit["base_parameter"]
        == "Config_Application.Emergency_Run.2807 Emergency start Seg No 33-48"
    )


def test_real_logics_manager(real_records):
    record = real_records["Config_Application.Emergency_Run.12200 Inhibit emerg..run"]
    assert record["kind"] == "logics_manager"
    assert record["id"] == 12200
    assert record["label"] == "Inhibit emerg..run"
    assert record["value"] == {
        "input_1": {"value": 0, "name": "00.01 LM: Flag 1"},
        "operator_1": "False",
        "binary_operator_1": "And",
        "input_2": {"value": 0, "name": "00.01 LM: Flag 1"},
        "operator_2": "True",
        "binary_operator_2": "And",
        "input_3": {"value": 0, "name": "00.01 LM: Flag 1"},
        "operator_3": "True",
        "delay_on": 0,
        "delay_off": 0,
        "delay_units": "s",
    }
    assert record["expression"] == (
        "[False 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1], "
        "delay on 0 s, delay off 0 s"
    )
    assert record["initial"]["operator_1"] == "False"
    assert record["initial"]["input_1"] == "00.01 LM: Flag 1"
    assert record["write_security_level"] == 2
    assert record["servlink_handle"] == 2215653288


def test_real_logics_manager_operators_are_known(real_parsed):
    for record in real_parsed["parameters"]:
        if record["kind"] != "logics_manager":
            continue
        for key in ("operator_1", "operator_2", "operator_3"):
            assert record["value"][key] in LOGICS_MANAGER_UNARY_OPERATORS.values()
        for key in ("binary_operator_1", "binary_operator_2"):
            assert record["value"][key] in LOGICS_MANAGER_BINARY_OPERATORS.values()


@pytest.mark.parametrize("real_wset_name", REAL_WSET_PARAMS_SLOW, indirect=True)
def test_real_file_from_bytes_and_stream(real_wset_path, real_parsed):
    data = real_wset_path.read_bytes()
    assert parse_wset(data)["num_parameters"] == real_parsed["num_parameters"]
    with real_wset_path.open("rb") as stream:
        assert parse_wset(stream)["application"] == real_parsed["application"]
    assert is_wset_data(data)
    assert is_wset_data(data[:64])
    with real_wset_path.open("rb") as stream:
        assert wset_signature_check(stream)
    # The head identifies the same application (from the SID specification)
    head_app = wset_head_application_info(data[:WSET_SNIFF_LEN])
    for key in ("part_number", "revision", "brand", "model", "product"):
        assert head_app[key] == real_parsed["application"][key], key


# ---------------------------------------------------------------------------
# Synthetic files
# ---------------------------------------------------------------------------


def test_synthetic_woodward_layout(synthetic_parsed):
    assert synthetic_parsed["header"]["type"] == "wset"
    assert len(synthetic_parsed["nrbf"]["streams"]) == 2
    assert synthetic_parsed["application"]["id"] == "EG3200XTP1 2.12-0_50976"
    assert synthetic_parsed["application"]["model"] == "3200XT-P1"
    assert synthetic_parsed["application"]["version"] == "2.12-0"
    assert synthetic_parsed["application"]["sid"] == "EG3200XTP1 2.12-0_50976"
    assert synthetic_parsed["num_parameters"] == len(DEFAULT_PARAMETERS)
    assert synthetic_parsed["parameter_kinds"] == {"basic": 4}
    assert synthetic_parsed["parameter_types"] == {"integer": 2, "enumerated": 1, "string": 1}
    assert synthetic_parsed["groups"] == {INTERNAL_GROUP: 1, "PARAMETER": 3}
    assert synthetic_parsed["logics_manager_inputs"] == {}
    assert synthetic_parsed["analog_manager_inputs"] == {}

    records = {record["name"]: record for record in synthetic_parsed["parameters"]}
    number = records["PARAMETER.Configure system management.1702 Device number"]
    assert number["group"] == "PARAMETER.Configure system management"
    assert number["id"] == 1702
    assert number["value"] == 7
    assert number["initial"] == 1
    assert number["minimum"] == 1
    assert number["maximum"] == 32
    assert number["write_security_level"] == 2
    assert number["servlink_handle"] == 2215642790

    monitoring = records["PARAMETER.Configure monitoring.Mains.4104 Monitoring"]
    assert monitoring["type"] == "enumerated"
    assert monitoring["value"] == "Off"
    assert monitoring["enum_value"] == 0
    assert monitoring["options"] == {"0": "Off", "1": "On"}
    assert monitoring["enum_name"] == "ENUM_SYNTHETIC"
    assert monitoring["initial"] == "On"

    name = records["PARAMETER.Configure system management.1700 Device name"]
    assert name["type"] == "string"
    assert name["value"] == "Genset 7"
    assert name["write_security_level"] == 1

    internal = records["Th2GenOverFreq"]
    assert internal["group"] == ""
    assert internal["value"] == 1150


def test_synthetic_include_raw(synthetic_wset):
    parsed = parse_wset(synthetic_wset, include_raw=True)
    assert len(parsed["raw_streams"]) == 2
    assert parsed["raw_streams"][0]["_class"] == "Woodward_Settings_SettingsHeader"
    assert parsed["raw_streams"][0]["sidIdentifier"]["appIdString"] == "EG3200XTP1 2.12-0_50976"
    assert parsed["raw_streams"][1]["_class"] == "System_Collections_Hashtable"
    assert "raw_streams" not in parse_wset(synthetic_wset)


def test_generic_layout_fallback():
    parsed = parse_wset(build_generic_wset())
    assert parsed["header"]["known"] is True
    assert parsed["settings_header"] == {}
    assert parsed["application"]["id"] == ""
    assert parsed["num_parameters"] == 5
    assert parsed["parameter_kinds"] == {"generic": 5}
    records = {record["id"]: record for record in parsed["parameters"]}
    assert records[1702]["name"] == "Device number"
    assert records[1702]["value"] == 7
    assert records[5518]["value"] == 50.0
    assert records[12200]["value"] is True
    assert records[7196]["value"] == "Flex. limit 16"
    assert records[9999]["value"] is None
    assert records[1702]["class"] == "Example_Setting"
    assert records[1702]["path"].startswith("Items[")


@pytest.mark.parametrize(
    ("header", "expected_length"),
    [
        pytest.param(b"\x00" * 10, 10, id="unknown 10-byte header"),
        pytest.param(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c", 12, id="12-byte header"),
        pytest.param(b"", 0, id="no header"),
    ],
)
def test_header_variants(header, expected_length):
    parsed = parse_wset(header + build_generic_streams())
    assert parsed["header"]["length"] == expected_length
    assert parsed["header"]["known"] is False
    assert parsed["header"]["type"] == ""
    assert parsed["nrbf"]["offset"] == expected_length
    assert parsed["num_parameters"] == 5


def test_trailing_bytes():
    parsed = parse_wset(build_generic_wset(trailing=b"\x00" * 7))
    assert parsed["nrbf"]["trailing_bytes"] == 7
    assert parsed["nrbf"]["errors"] == []
    assert parsed["num_parameters"] == 5


def test_truncated_stream():
    data = build_generic_wset()
    parsed = parse_wset(data[:-30])
    assert len(parsed["nrbf"]["streams"]) == 1
    assert len(parsed["nrbf"]["errors"]) == 1
    assert "offset" in parsed["nrbf"]["errors"][0]
    assert parsed["nrbf"]["trailing_bytes"] > 0
    assert parsed["num_parameters"] == 0


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x00" * 50, id="zeros"),
        pytest.param(WSET_HEADER, id="header only"),
        pytest.param(WSET_HEADER + b"\x00\x01\x00\x00\x00", id="truncated nrbf header"),
        pytest.param(b"File Version: 1.0\r\nMode\tCategory\r\n", id="tc text"),
    ],
)
def test_invalid_data(data):
    assert parse_wset(data) == {}
    assert not is_wset_data(data)


def test_unsupported_source():
    assert parse_wset(12345) == {}  # type: ignore[arg-type]
    assert parse_wset(io.StringIO("text")) == {}  # type: ignore[arg-type]


def test_read_nrbf_streams_and_offsets():
    streams = build_generic_streams()
    assert find_nrbf_offset(streams) == 0
    assert find_nrbf_offset(WSET_HEADER + streams) == WSET_HEADER_LEN
    assert find_nrbf_offset(b"\x00" * 300 + streams) is None
    assert find_nrbf_offset(b"") is None

    objects, info = read_nrbf_streams(streams)
    assert [type(o).__name__ for o in objects] == ["Example_FileInfo", "Example_SettingList"]
    assert info["streams"][1]["end"] == len(streams)
    assert objects[0].Name == "easYgen-3200XT-P1"
    assert list(objects[0].Tags) == ["alpha", "beta"]


def test_to_plain():
    objects, _ = read_nrbf_streams(build_generic_streams())
    plain = to_plain(objects[0])
    assert plain["_class"] == "Example_FileInfo"
    assert plain["Name"] == "easYgen-3200XT-P1"
    assert plain["Version"] == 3
    assert plain["Created"].startswith("2016-")
    assert plain["Tags"] == ["alpha", "beta"]

    assert to_plain(None) is None
    assert to_plain(Decimal("1.5")) == "1.5"
    assert to_plain(datetime(2020, 1, 2, 3, 4, 5)) == "2020-01-02T03:04:05"
    assert to_plain(timedelta(seconds=90)) == "0:01:30"
    assert to_plain(b"\x01\x02") == "0102"
    assert to_plain(array("i", [1, 2])) == [1, 2]
    assert to_plain({1: (1, 2)}) == {"1": [1, 2]}
    assert to_plain({"b", "a"}) == ["a", "b"]
    assert to_plain({1, "a"}) in ([1, "a"], ["a", 1])
    assert to_plain(object()).startswith("<object object")

    circular: list = [1]
    circular.append(circular)
    assert to_plain(circular) == [1, "<circular reference>"]


def test_extract_generic_parameters():
    plain = {
        "_class": "Root",
        "items": [
            {"_class": "A", "Id": 1, "Value": 2, "Name": "one"},
            {"_class": "B", "parameterId": "3", "currentValue": "x"},
            {"_class": "C", "Id": True, "Value": 1},  # bool ids aren't parameters
            {"_class": "D", "Id": 4},  # no value
            {"_class": "E", "Number": 5, "Data": None, "nested": {"id": 6, "value": 7}},
        ],
    }
    records = extract_generic_parameters(plain)
    assert [(r["id"], r["value"], r["name"], r["class"]) for r in records] == [
        (1, 2, "one", "A"),
        (3, "x", "", "B"),
        (5, None, "", "E"),
        (6, 7, "", ""),
    ]
    assert records[3]["path"] == "items[4].nested"
    assert extract_generic_parameters("text") == []


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "Config_Monitoring.Generator.Overfrequency level 2.1910 Limit",
            ("Config_Monitoring.Generator.Overfrequency level 2", 1910, "Limit"),
        ),
        (
            "Config_Application.Emergency_Run.12200 Inhibit emerg..run",
            ("Config_Application.Emergency_Run", 12200, "Inhibit emerg..run"),
        ),
        (
            "Config_Controller.Load.f depending derating of power.5784 f dep..derating",
            ("Config_Controller.Load.f depending derating of power", 5784, "f dep..derating"),
        ),
        ("Modbus.3183 Current [A] exponent 10^x", ("Modbus", 3183, "Current [A] exponent 10^x")),
        ("1702 Device number", ("", 1702, "Device number")),
        ("Th2GenOverFreq", ("", None, "Th2GenOverFreq")),
        ("PDO_9_2.BIT_0_HMI", ("PDO_9_2", None, "BIT_0_HMI")),
        ("", ("", None, "")),
    ],
)
def test_split_parameter_name(name, expected):
    assert split_parameter_name(name) == expected


def test_easygen_parameter_names():
    names = easygen_parameter_names()
    assert names[1795] == "startup in mode"
    assert names[12510] == "AUTO op. mode"
    assert names[5518] == "AM Frequency SP1[Hz]"
    assert len(names) > 400
    assert easygen_parameter_names() is names  # cached


def test_summarize_and_populate(real_parsed):
    summary = summarize_wset(real_parsed)
    assert "parameters" not in summary
    assert summary["num_parameters"] == 2756
    assert summary["num_logics_manager_inputs"] == 677
    assert summary["num_analog_manager_inputs"] == 242
    assert summary["application"]["model"] == "3500"

    dev = DeviceData()
    populate_device_from_wset(dev, real_parsed)
    assert dev.description.brand == "easYgen"
    assert dev.description.model == "3500"
    assert dev.description.product == "easYgen-3500"
    assert dev.firmware.id == "5418-6722-NEW"
    assert {k: v for k, v in dev.extra["wset"].items() if k in summary} == summary
    assert dev.extra["wset"]["data_model"]["registers"] == 4548
    assert dev.extra["wset"]["logic"] == {
        "num_equations": 130,
        "num_command_variables": 43,
        "num_linked_command_variables": 5,
        "num_constant_command_variables": 0,
        "unknown_operators": 0,
    }
    assert len(dev.registers) == 4548
    assert len(dev.io) == 112
    assert "PROGRAM main" in dev.logic.parsed
    assert "tc6" in dev.logic.formats
    parameters = dev.extra["parameters"]
    assert len(parameters) == 2756
    assert parameters["Config_Admin.1702 Device number"] == 1
    assert parameters["Config_Monitoring.Generator.Overfrequency level 2.1910 Limit"] == 115.0
    assert parameters["Config_Application.Emergency_Run.12200 Inhibit emerg..run"].startswith(
        "[False"
    )

    # Existing description values are kept
    existing = DeviceData()
    existing.description.model = "3500XT"
    populate_device_from_wset(existing, real_parsed)
    assert existing.description.model == "3500XT"

    unknown = DeviceData()
    populate_device_from_wset(unknown, parse_wset(build_woodward_wset(app_id="5418-9999-NEW")))
    assert unknown.description.model == "unknown"
    assert unknown.description.product == "ToolKit application 5418-9999-NEW"
    assert unknown.firmware.id == "5418-9999-NEW"

    empty = DeviceData()
    populate_device_from_wset(empty, {})
    assert not empty.extra


# ---------------------------------------------------------------------------
# Synthetic E3 engine control settings file
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def e3_parsed() -> dict:
    return parse_wset(build_e3_wset())


@pytest.fixture(scope="module")
def e3_records(e3_parsed) -> dict[str, dict]:
    return {record["name"]: record for record in e3_parsed["parameters"]}


def test_e3_file(e3_parsed):
    assert e3_parsed["nrbf"]["errors"] == []
    assert e3_parsed["application"]["id"] == E3_APP_ID
    assert e3_parsed["application"]["brand"] == "E3"
    assert e3_parsed["application"]["part_number"] == "5418-4091"
    assert e3_parsed["num_parameters"] == len(E3_PARAMETERS)
    assert e3_parsed["parameter_kinds"] == {"basic": 4, "lookup_table": 1, "array": 1}
    assert e3_parsed["parameter_types"] == {"boolean": 2, "array": 2, "float": 1, "string": 1}
    assert e3_parsed["groups"] == {"DIAG": 2, "EBP": 1, "FUEL": 1, "QGN": 1, "REV_INFO": 1}
    assert all(record["id"] is None for record in e3_parsed["parameters"])
    assert json.loads(json.dumps(e3_parsed))["num_parameters"] == len(E3_PARAMETERS)


def test_e3_float(e3_records):
    record = e3_records["QGN.CL_KP_"]
    assert (record["group"], record["id"], record["label"]) == ("QGN", None, "CL_KP_")
    assert record["kind"] == "basic"
    assert record["type"] == "float"
    assert record["value"] == 0.25
    assert record["value_text"] == "0.25"
    assert record["initial"] == 0.25
    assert record["minimum"] == 0.001
    assert record["maximum"] == 9.999
    assert record["units"] == ""
    assert record["servlink_handle"] == 2196768448


def test_e3_boolean(e3_records):
    on = e3_records["DIAG.AL_751.OVRD"]
    assert (on["group"], on["id"], on["label"]) == ("DIAG.AL_751", None, "OVRD")
    assert on["type"] == "boolean"
    assert on["value"] is True
    assert on["value_text"] == "True"
    assert on["initial"] is False
    assert on["minimum"] is None
    off = e3_records["DIAG.AL_752.OVRD"]
    assert off["value"] is False
    assert off["initial"] is True


def test_e3_string(e3_records):
    record = e3_records["REV_INFO.GAS_RUNNING_H"]
    assert record["type"] == "string"
    assert record["value"] == "Natural Gas"
    assert record["initial"] == "Natural Gas"
    assert record["max_size"] == 49


def test_e3_lookup_table(e3_records):
    record = e3_records["EBP.CURVE_H"]
    assert record["class"] == "Woodward_DataAccess_LookupTableParameter"
    assert record["kind"] == "lookup_table"
    assert record["type"] == "array"
    assert record["index_inputs"] == ["EBP.CURVE_H_XInput", "EBP.CURVE_H_YInput"]
    # Descriptor fields come from the output array's descriptor
    assert record["units"] == "kPa"
    assert record["write_security_level"] == 3
    assert record["servlink_handle"] == 3256877111
    assert record["arrays"] == [
        {
            "name": "EBP.CURVE_H",
            "type": "float",
            "size": 4,
            "values": [0.0, 0.5, 1.0, 1.5],
            "initial": [0.0, 0.0, 0.0, 0.0],
            "units": "kPa",
        },
        {
            "name": "EBP.CURVE_H_XTable",
            "type": "float",
            "size": 2,
            "values": [1000.0, 1800.0],
            "initial": [1000.0, 1800.0],
            "units": "RPM",
        },
        {
            "name": "EBP.CURVE_H_YTable",
            "type": "float",
            "size": 2,
            "values": [10.0, 220.0],
            "initial": [10.0, 220.0],
            "units": "kPa",
        },
    ]
    assert record["value"] == [[0.0, 0.5, 1.0, 1.5], [1000.0, 1800.0], [10.0, 220.0]]
    assert record["initial"] == [[0.0, 0.0, 0.0, 0.0], [1000.0, 1800.0], [10.0, 220.0]]


def test_e3_array(e3_records):
    record = e3_records["FUEL.TRIM_ARRAY"]
    assert record["class"] == "Woodward_DataAccess_ArrayParameter"
    assert record["kind"] == "array"
    assert record["type"] == "array"
    assert "index_inputs" not in record
    assert record["arrays"] == [
        {
            "name": "FUEL.TRIM_ARRAY",
            "type": "float",
            "size": 3,
            "values": [1.25, 2.5, -3.0],
            "initial": [0.0],  # a single initial value is used for every element
            "units": "%",
        }
    ]
    assert record["value"] == [1.25, 2.5, -3.0]
    assert record["initial"] == [0.0]
    assert record["units"] == "%"
    assert record["write_security_level"] == 2


def test_e3_populate():
    dev = DeviceData()
    parsed = parse_wset(build_e3_wset())
    populate_device_from_wset(dev, parsed)
    assert dev.description.brand == "E3"
    assert dev.firmware.id == E3_APP_ID
    parameters = dev.extra["parameters"]
    assert parameters["DIAG.AL_751.OVRD"] is True
    assert parameters["EBP.CURVE_H"][1] == [1000.0, 1800.0]
    assert len(parameters) == len(E3_PARAMETERS)


# ---------------------------------------------------------------------------
# Error paths and alternate object layouts
# ---------------------------------------------------------------------------


def _fake(class_name: str, **fields):
    """A fake decoded .NET object (``_is_record`` only needs ``_fields`` and ``_asdict``)."""
    return namedtuple(class_name, list(fields))(**fields)


def test_parameter_extraction_failure(monkeypatch, synthetic_wset):
    real_parameter_record = parse_wset_module.parameter_record

    def _parameter_record(name, parameter, by_name):
        if name == "Th2GenOverFreq":
            raise ValueError("bad parameter")
        return real_parameter_record(name, parameter, by_name)

    monkeypatch.setattr(parse_wset_module, "parameter_record", _parameter_record)
    parsed = parse_wset(synthetic_wset)
    assert parsed["num_parameters"] == len(DEFAULT_PARAMETERS)
    assert parsed["parameter_kinds"] == {"basic": 3, "error": 1}
    records = {record["name"]: record for record in parsed["parameters"]}
    assert records["Th2GenOverFreq"] == {
        "name": "Th2GenOverFreq",
        "kind": "error",
        "type": "unknown",
        "value": None,
        "error": "ValueError('bad parameter')",
    }


def test_undecodable_streams():
    # A valid NRBF header record followed by garbage
    data = WSET_HEADER + build_generic_streams()[:17] + b"\xfe" * 32
    assert is_wset_data(data)
    assert parse_wset(data) == {}


def test_hashtable_layouts():
    name = _fake("Woodward_Sid_Descriptors_ParameterName", delimitedName="A.1702 Device number")
    parameter = _fake(
        "Woodward_DataAccess_BasicParameter",
        parameterValueCache=_fake("Cache", value="7"),
        descriptor=None,
    )
    assert _hashtable_items({"key": "value"}) == [("key", "value")]
    pairs = _fake(
        "System_Collections_Generic_Dictionary",
        KeyValuePairs=[_fake("Pair", key=name, value=parameter)],
    )
    assert _hashtable_items(pairs) == [(name, parameter)]
    assert is_settings_table(pairs)
    records, inputs = extract_settings(pairs)
    assert inputs == {}
    assert [(r["name"], r["id"], r["kind"], r["value"]) for r in records] == [
        ("A.1702 Device number", 1702, "basic", "7")
    ]
    assert _hashtable_items(_fake("Other", Keys=None)) == []
    assert _hashtable_items(None) == []
    assert not is_settings_table({})
    assert not is_settings_table({"plain string key": parameter})


def test_text_and_number_conversion():
    assert _text_value(None) is None
    assert _text_value("text") == "text"
    assert _text_value(_fake("Woodward_Sid_TextValue", value=[])) is None
    assert _text_value(_fake("Woodward_Sid_TextValue", value=["a", "b"])) == ["a", "b"]
    assert _text_value(_fake("Woodward_Sid_TextValue", value=5)) == "5"
    assert _text_value(_fake("Woodward_Sid_TextValue", value=None)) is None
    assert _to_int(None) is None
    assert _to_int(" 12 ") == 12
    assert _to_int("twelve") == "twelve"
    assert _to_float(None) is None
    assert _to_float("1.5") == 1.5
    assert _to_float("n/a") == "n/a"
    assert _to_bool(None) is None
    assert _to_bool("maybe") == "maybe"


def test_computed_missing_source(caplog):
    caplog.set_level("DEBUG")
    descriptor = _fake(
        "Woodward_Sid_Descriptors_ParameterDescriptor",
        dataTypeDescriptor=_fake("Woodward_Sid_Descriptors_FloatDescriptor", precision=None),
        expressionDescriptor=_fake(
            "Woodward_Sid_Descriptors_ExpressionDescriptor",
            paramName="MissingSource",
            multiplier=0.1,
            offset=0.0,
        ),
        initialValue=None,
        minimum=None,
        maximum=None,
    )
    parameter = _fake("Woodward_DataAccess_ComputedParameter", descriptor=descriptor)
    record = parameter_record("Config.1910 Limit", parameter, {})
    assert record["kind"] == "computed"
    assert record["type"] == "float"
    assert record["source"] == "MissingSource"
    assert record["value"] is None
    assert record["source_value"] is None
    assert record["initial"] is None
    assert "Computed parameter source 'MissingSource' not found" in caplog.text


def test_unknown_parameter_class():
    parameter = _fake("Woodward_DataAccess_FutureParameter", something=1)
    record = parameter_record("FUTURE.PARAM", parameter, {})
    assert record["kind"] == "unknown"
    assert record["value"] == {"_class": "Woodward_DataAccess_FutureParameter", "something": 1}


def test_array_cache_value_layout():
    # A cache with a TextValue "value" instead of a "values" list
    descriptor = _fake(
        "Woodward_Sid_Descriptors_ParameterDescriptor",
        name="T.ARRAY",
        dataTypeDescriptor=_fake("Woodward_Sid_Descriptors_IntegerDescriptor", size=16),
        initialValue=None,
        units="s",
    )
    parameter = _fake(
        "Woodward_DataAccess_ArrayParameter",
        arrayParameterValueCache=_fake(
            "Woodward_Settings_ArrayParameterValueCache",
            descriptor=descriptor,
            value=_fake("Woodward_Sid_TextValue", value=["1", "2"]),
        ),
        descriptor=descriptor,
    )
    record = parameter_record("T.ARRAY", parameter, {})
    assert record["kind"] == "array"
    assert record["value"] == [1, 2]
    assert record["initial"] is None
    assert record["arrays"][0]["type"] == "integer"
    assert record["arrays"][0]["units"] == "s"


@pytest.mark.parametrize(
    ("class_name", "expected"),
    [
        ("Woodward_Sid_Descriptors_BitFieldBooleanDescriptor", "bit_field"),
        ("Woodward_Sid_Descriptors_BitFieldsDescriptor", "bit_fields"),
        ("Woodward_Sid_Descriptors_ArrayDescriptor", "array"),
        ("Woodward_Sid_Descriptors_FutureDescriptor", "Woodward_Sid_Descriptors_FutureDescriptor"),
    ],
)
def test_descriptor_type(class_name, expected):
    assert _descriptor_type(_fake(class_name)) == expected
    assert _descriptor_type(None) == "unknown"


def test_scale_invalid():
    assert _scale(10, "x", 0) is None
    assert _scale("10", 1, 0) is None
    assert _scale(True, 1, 0) is None


def test_application_info_variants():
    assert application_info({"sid_identifier": "5418-6722-NEW"})["model"] == "3500"
    info = application_info(
        {"sid_specification": "us_5418-6722-NEW", "application_description": "custom"}
    )
    assert info["id"] == "custom"
    assert info["part_number"] == "5418-6722"
    assert info["sid"] == "us_5418-6722-NEW"


def test_other_container_type_is_not_wset():
    assert not is_wset_data(build_woodward_wtool())
    assert parse_wset(build_woodward_wtool())["settings_header"] == {}


# ---------------------------------------------------------------------------
# Application identification from the start of the file (module routing)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(
            build_woodward_wset(app_id=APP_ID_2301E),
            {
                "id": APP_ID_2301E,
                "part_number": "5418-6350",
                "revision": "G",
                "brand": "WDW",
                "model": "2301E",
                "product": "2301E",
            },
            id="2301E",
        ),
        pytest.param(
            build_woodward_wset(app_id="5418-6350_New 2012-10-08 09.18.02"),
            {"part_number": "5418-6350", "revision": "New", "model": "2301E"},
            id="2301E revision New",
        ),
        pytest.param(
            build_woodward_wset(),
            {"brand": "easYgen", "model": "3200XT-P1", "version": "2.12-0", "build": "50976"},
            id="easYgen XT",
        ),
        pytest.param(
            build_woodward_wset(app_id="5418-6722-NEW", sid="us_5418-6722-NEW"),
            {"id": "us_5418-6722-NEW", "brand": "easYgen", "model": "3500"},
            id="easYgen-3500",
        ),
        pytest.param(
            build_e3_wset(), {"part_number": "5418-4091", "brand": "E3"}, id="E3 engine control"
        ),
        pytest.param(
            build_woodward_wset(app_id="5418-9999-NEW"),
            {"part_number": "5418-9999", "brand": "", "model": ""},
            id="unknown application",
        ),
        pytest.param(
            build_woodward_wset(app_id="custom", sid=""),
            {"id": "", "part_number": "", "model": ""},
            id="no application identifier",
        ),
        pytest.param(
            build_generic_wset(),
            {"id": "", "part_number": "", "model": ""},
            id="no settings header",
        ),
    ],
)
def test_wset_head_application_info(data, expected):
    app = wset_head_application_info(data[:WSET_SNIFF_LEN])
    assert {key: app[key] for key in expected} == expected
    # Only the settings header (the first stream) is needed
    header_end = read_nrbf_streams(data, WSET_HEADER_LEN)[1]["streams"][0]["end"]
    assert wset_head_application_info(data[:header_end]) == app


def test_wset_head_application_info_ignores_settings():
    # Identifiers in the parameters (the second stream) aren't used
    parameters = [{**DEFAULT_PARAMETERS[0], "type": "string", "value": APP_ID_2301E}]
    data = build_woodward_wset(app_id="custom", sid="", parameters=parameters)
    assert APP_ID_2301E.encode() in data
    assert wset_head_application_info(data)["model"] == ""


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"not a settings file" * 10, id="text"),
        pytest.param(build_woodward_wtool(), id="tool file"),
        pytest.param(WSET_HEADER + b"\x00" * 40, id="header only"),
    ],
)
def test_wset_head_application_info_not_wset(data):
    assert wset_head_application_info(data) is None


def test_save_wset_logic(tmp_path, mocker):
    source = tmp_path / "settings.wset"
    source.write_bytes(b"binary")

    # No LogicsManager equations: the binary settings file isn't a logic source
    dev = DeviceData()
    populate_device_from_wset(dev, parse_wset(build_woodward_wset()))
    write_file = mocker.patch.object(DeviceData, "write_file")
    save_wset_logic(dev, source)
    assert dev.logic.file.local_path is None
    write_file.assert_not_called()

    dev.extra["wset"]["logic"] = {"num_equations": 1}
    dev.logic.formats["structured_text"] = "PROGRAM main\nEND_PROGRAM\n"
    dev.logic.formats["tc6"] = "<project/>"
    save_wset_logic(dev, source)
    assert dev.logic.file.local_path == source
    assert [c.args[1] for c in write_file.call_args_list] == ["logic.st", "logic-tc6.xml"]

    save_wset_logic(DeviceData(), None)  # nothing parsed
