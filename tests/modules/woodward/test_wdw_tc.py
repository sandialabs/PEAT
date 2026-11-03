"""Tests for the Control Assistant tunable file parser (peat/modules/woodward/wdw_tc.py)."""

import io
from datetime import datetime
from typing import Final

import pytest

from peat import DeviceData
from peat.modules.woodward.wdw_tc import (
    TC_EXPECTED_COLUMNS,
    _parse_tc_file,
    convert_tc_value,
    decode_text,
    is_tc_data,
    parse_tc,
    populate_device_from_tc,
    tc_application_info,
    tc_parameter_values,
    tc_signature_check,
    unquote_tc_field,
)

from .nrbf_builder import build_generic_wset

FIXTURE: Final[str] = "tunables_synthetic.tc"
HEADER: Final[str] = "Mode\tCategory\tBlock Name\tField Name\tType\tCurrent\tInitial\tLow\tHigh\n"


@pytest.fixture(scope="module")
def tc_bytes(binary_data) -> bytes:
    return binary_data(FIXTURE)


@pytest.fixture(scope="module")
def parsed(tc_bytes) -> dict:
    return parse_tc(tc_bytes)


def test_fixture_uses_crlf(tc_bytes):
    # The fixture mimics a file written on Windows
    assert b"\r\n" in tc_bytes


def test_metadata(parsed):
    assert parsed["file_version"] == "File Version: 1.0"
    assert parsed["version"] == "1.0"
    assert parsed["firmware_prefix"] == "5418-1234 NEW"
    assert parsed["firmware_date"] == "2015-03-23 14:32:11 UTC"
    assert parsed["metadata_lines"] == [
        "File Version: 1.0",
        "5418-1234 NEW",
        "2015-03-23 14:32:11 UTC",
    ]
    assert parsed["columns"] == TC_EXPECTED_COLUMNS


def test_counts(parsed):
    assert parsed["num_parameters"] == 7
    assert len(parsed["parameters"]) == 7
    assert parsed["num_malformed_lines"] == 1  # the "BAD_LINE" row has too few columns
    assert parsed["modes"] == ["Configure", "Service"]
    assert parsed["categories"] == [
        "A**ENGINE PARAMETERS**",
        "B**DISCRETE INPUTS**",
        "CfgA",
        "CfgB",
    ]


def test_nested_config_keeps_raw_strings(parsed):
    config = parsed["config"]
    assert config["Service"]["A**ENGINE PARAMETERS**"]["SPEED_SETPOINT"]["RATED_SPEED"] == {
        "Type": "Float",
        "Current": "1800.0",
        "Initial": "1800.0",
        "Low": "500.0",
        "High": "4000.0",
    }
    assert config["Configure"]["CfgA"]["01"]["USE_RPM"]["Current"] == "TRUE"
    assert config["Configure"]["CfgB"]["01"]["DESCRIPTION"]["Current"] == "Genset 1"
    # Malformed row isn't added
    assert "02" not in config["Configure"]["CfgB"]


def test_flat_records_are_typed(parsed):
    by_path = {(r["mode"], r["path"]): r for r in parsed["parameters"]}
    speed = by_path[("Service", "A**ENGINE PARAMETERS**/SPEED_SETPOINT/RATED_SPEED")]
    assert speed == {
        "mode": "Service",
        "category": "A**ENGINE PARAMETERS**",
        "block": "SPEED_SETPOINT",
        "field": "RATED_SPEED",
        "path": "A**ENGINE PARAMETERS**/SPEED_SETPOINT/RATED_SPEED",
        "type": "Float",
        "current": 1800.0,
        "initial": 1800.0,
        "low": 500.0,
        "high": 4000.0,
    }
    use_rpm = by_path[("Configure", "CfgA/01/USE_RPM")]
    assert use_rpm["type"] == "Boolean"
    assert use_rpm["current"] is True
    assert use_rpm["initial"] is False
    teeth = by_path[("Configure", "CfgA/02/NUM_TEETH")]
    assert teeth["current"] == 60
    assert isinstance(teeth["current"], int)
    assert teeth["high"] == 500
    description = by_path[("Configure", "CfgB/01/DESCRIPTION")]
    assert description["current"] == "Genset 1"
    assert description["low"] == ""


def test_parse_accepts_path_and_text(datapath, tc_bytes, parsed):
    assert parse_tc(datapath(FIXTURE)) == parsed
    assert parse_tc(tc_bytes.decode("utf-8")) == parsed
    assert _parse_tc_file(tc_bytes) == parsed  # deprecated alias
    assert _parse_tc_file(None) == {}


def test_lf_line_endings_and_extra_columns():
    text = (
        "File Version: 2\n"
        "5418-5678 B\n"
        "2020-01-02 03:04:05 UTC\n"
        "Mode\tCategory\tBlock Name\tField Name\tType\tCurrent\tInitial\tLow\tHigh\tUnits\n"
        "Service\tCAT\tBLOCK\tFIELD\tInteger\t5\t4\t0\t10\trpm\n"
        "Service\tCAT\tBLOCK\tFIELD2\tInteger\t6\t4\t0\t10\trpm\textra\n"
        "\n"
    )
    parsed = parse_tc(text)
    assert parsed["version"] == "2"
    assert parsed["columns"][-1] == "Units"
    assert parsed["num_parameters"] == 2
    assert parsed["num_malformed_lines"] == 0
    record = parsed["parameters"][0]
    assert record["current"] == 5
    assert record["units"] == "rpm"
    assert parsed["config"]["Service"]["CAT"]["BLOCK"]["FIELD"]["Units"] == "rpm"
    assert parsed["config"]["Service"]["CAT"]["BLOCK"]["FIELD2"]["extra"] == ["extra"]


def test_short_rows_are_padded():
    text = (
        "File Version: 1.0\n"
        "Mode\tCategory\tBlock Name\tField Name\tType\tCurrent\tInitial\tLow\tHigh\n"
        "Service\tCAT\tBLOCK\tFIELD\tInteger\t5\n"
    )
    parsed = parse_tc(text)
    assert parsed["num_parameters"] == 1
    assert parsed["parameters"][0]["current"] == 5
    assert parsed["parameters"][0]["initial"] == ""
    assert parsed["firmware_prefix"] == ""
    assert parsed["firmware_date"] == ""


def test_metadata_order_is_detected_by_content():
    text = (
        "2015-03-23 14:32:11 UTC\n"
        "File Version 3.1\n"
        "5418-0000 NEW\n"
        "Mode\tCategory\tBlock Name\tField Name\tType\tCurrent\tInitial\tLow\tHigh\n"
        "Service\tCAT\tBLOCK\tFIELD\tInteger\t5\t4\t0\t10\n"
    )
    parsed = parse_tc(text)
    assert parsed["version"] == "3.1"
    assert parsed["firmware_date"] == "2015-03-23 14:32:11 UTC"
    assert parsed["firmware_prefix"] == "5418-0000 NEW"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("   \n", id="blank"),
        pytest.param("File Version: 1.0\nno header here\n", id="no header"),
        pytest.param("Mode\n", id="header without tabs"),
        pytest.param("Mode\tOnly\n", id="too few columns"),
    ],
)
def test_invalid_data(text):
    assert parse_tc(text) == {}


def test_unsupported_source_type(tmp_path):
    assert parse_tc(12345) == {}  # type: ignore[arg-type]
    assert parse_tc(tmp_path / "missing.tc") == {}


def test_bytearray_source(tc_bytes, parsed):
    assert parse_tc(bytearray(tc_bytes)) == parsed


def test_header_without_rows():
    parsed = parse_tc("File Version: 1.0\n" + HEADER)
    assert parsed["columns"] == TC_EXPECTED_COLUMNS
    assert parsed["num_parameters"] == 0
    assert parsed["parameters"] == []
    assert parsed["config"] == {}


def test_missing_type_column():
    text = (
        "File Version: 1.0\n"
        "Mode\tCategory\tBlock Name\tField Name\tCurrent\n"
        "Service\tCAT\tBLOCK\tFIELD\t5\n"
    )
    record = parse_tc(text)["parameters"][0]
    assert record["type"] == ""
    assert record["current"] == 5


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain", "plain"),
        (' "quoted" ', "quoted"),
        ('""', ""),
        ('"', '"'),
        ('"a""b"', 'a"b'),
        ('a"b', 'a"b'),
    ],
)
def test_unquote_tc_field(raw, expected):
    assert unquote_tc_field(raw) == expected


def test_is_tc_data(tc_bytes):
    assert is_tc_data(tc_bytes)
    assert is_tc_data(tc_bytes[:200])
    assert is_tc_data(tc_bytes.decode("utf-8"))
    assert not is_tc_data(b"")
    assert not is_tc_data(b"just some text\nwith lines\n")
    assert not is_tc_data(build_generic_wset())
    assert not is_tc_data("Mode\tCategory\n")  # no "File Version"
    assert not is_tc_data("File Version: 1\nMode Category\n")  # header isn't tab separated


def test_tc_signature_check(datapath):
    with datapath(FIXTURE).open("rb") as stream:
        assert tc_signature_check(stream)
    assert not tc_signature_check(io.BytesIO(b"nope"))


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(b"plain", "plain", id="ascii"),
        pytest.param("already str", "already str", id="str"),
        pytest.param("﻿bom".encode(), "bom", id="utf-8 bom stripped"),
        pytest.param("café".encode("utf-16"), "café", id="utf-16 with bom"),
        pytest.param(b"80 \x80 euro", "80 € euro", id="cp1252 euro sign"),
        pytest.param(b"\xff\xfe\x00", "\xff\xfe\x00", id="bad utf-16 falls back"),
        pytest.param("File Version".encode("utf-16-le"), "File Version", id="utf-16-le no bom"),
        pytest.param("File Version".encode("utf-16-be"), "File Version", id="utf-16-be no bom"),
        pytest.param(b"A\x00B\x00C\x00\x01\xd8", "A\x00B\x00C\x00\x01Ø", id="bad utf-16-le"),
        pytest.param(b"\x81", "\x81", id="latin-1 fallback"),
        pytest.param("\ufeffstr with bom", "str with bom", id="str bom stripped"),
    ],
)
def test_decode_text(data, expected):
    assert decode_text(data) == expected


@pytest.mark.parametrize(
    ("raw", "type_name", "expected"),
    [
        ("TRUE", "Boolean", True),
        ("false", "Boolean", False),
        ("1", "Boolean", True),
        ("0", "Bool", False),
        ("TRUE", "", True),
        ("no", "", False),
        ("enabled", "", True),
        ("1", "", 1),
        ("0", "Integer", 0),
        ("yes", "String", "yes"),
        ("60", "Integer", 60),
        ("-7", "", -7),
        ("1800.0", "Float", 1800.0),
        ("1e3", "", 1000.0),
        ("Genset 1", "String", "Genset 1"),
        ("  spaced  ", "", "spaced"),
        ("", "Float", ""),
        ("maybe", "Boolean", "maybe"),
        ("1", "Float", 1.0),
        ("2", "REAL", 2.0),
        ("x", "Double", "x"),
        ("60.0", "Integer", 60),
        ("1.5", "DINT", 1.5),
        ("auto", "Word", "auto"),
        ('"7"', '"Integer"', 7),
        ("nan", "", "nan"),
        ("-inf", "Float", "-inf"),
        ("1e999", "Integer", "1e999"),
    ],
)
def test_convert_tc_value(raw, type_name, expected):
    result = convert_tc_value(raw, type_name)
    assert result == expected
    assert type(result) is type(expected)


def test_populate_device_from_tc(parsed):
    dev = DeviceData()
    populate_device_from_tc(dev, parsed)
    assert dev.firmware.id == "5418-1234 NEW"
    assert dev.firmware.timestamp == datetime(2015, 3, 23, 14, 32, 11)
    assert dev.extra["tc"]["num_parameters"] == 7
    assert dev.extra["tc"]["modes"] == ["Configure", "Service"]
    assert "config" not in dev.extra["tc"]
    assert len(dev.extra["parameters"]) == 7
    assert dev.extra["parameters"]["A**ENGINE PARAMETERS**/SPEED_SETPOINT/RATED_SPEED"] == 1800.0
    assert dev.extra["parameters"]["CfgA/01/USE_RPM"] is True
    # Unknown application: generic brand, model is left for the module
    assert dev.description.brand == "Woodward"
    assert not dev.description.model

    # Parsing the same file again doesn't duplicate anything, other values are kept
    dev.extra["parameters"]["1750 Rated voltage"] = 400
    populate_device_from_tc(dev, parsed)
    assert len(dev.extra["parameters"]) == 8
    assert dev.extra["parameters"]["1750 Rated voltage"] == 400

    # Existing values aren't overwritten
    dev2 = DeviceData()
    dev2.firmware.id = "existing"
    populate_device_from_tc(dev2, parsed)
    assert dev2.firmware.id == "existing"

    dev3 = DeviceData()
    populate_device_from_tc(dev3, {})
    assert not dev3.extra


def test_populate_known_application():
    text = "File Version: 1.0\n5418-6722 NEW\nnot a date\n" + HEADER
    parsed = parse_tc(text)
    assert tc_application_info(parsed)["model"] == "3500"
    dev = DeviceData()
    populate_device_from_tc(dev, parsed)
    assert dev.description.brand == "easYgen"
    assert dev.description.model == "3500"
    assert dev.description.product == "easYgen-3500"
    assert dev.extra["parameters"] == {}
    assert not dev.firmware.timestamp
    # Values that are already set aren't overwritten
    dev2 = DeviceData()
    dev2.description.model = "3500XT"
    populate_device_from_tc(dev2, parsed)
    assert dev2.description.model == "3500XT"
    assert dev2.description.product == "easYgen-3500"


def test_tc_parameter_values_same_path_in_two_modes():
    records = [
        {"mode": "Service", "path": "CAT/BLOCK/FIELD", "current": 1},
        {"mode": "Configure", "path": "CAT/BLOCK/FIELD", "current": 2},
    ]
    assert tc_parameter_values(records) == {
        "CAT/BLOCK/FIELD": 1,
        "Configure/CAT/BLOCK/FIELD": 2,
    }
