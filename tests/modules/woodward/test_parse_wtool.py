"""Tests for the Woodward ToolKit tool file parser (peat/modules/woodward/parse_wtool.py)."""

import io

import pytest

from peat import DeviceData
from peat.modules.woodward.parse_wtool import (
    _device_names,
    find_sid_specifications,
    is_wtool_data,
    parse_wtool,
    populate_device_from_wtool,
    wtool_signature_check,
)

from .nrbf_builder import WTOOL_HEADER, build_generic_wset, build_woodward_wtool


@pytest.fixture(scope="module")
def wtool() -> bytes:
    return build_woodward_wtool()


@pytest.fixture(scope="module")
def parsed(wtool) -> dict:
    return parse_wtool(wtool)


def test_is_wtool_data(wtool):
    assert is_wtool_data(wtool)
    assert is_wtool_data(wtool[:64])
    assert not is_wtool_data(build_generic_wset())  # wset type code
    assert not is_wtool_data(WTOOL_HEADER + b"\x00" * 20)
    assert not is_wtool_data(b"")
    assert wtool_signature_check(io.BytesIO(wtool))
    assert not wtool_signature_check(io.BytesIO(b"nope"))


def test_parse_wtool(parsed):
    assert parsed["header"] == {
        "hex": "153ab51fd46d59c23100",
        "length": 10,
        "type": "wtool",
        "type_code": 0x15,
        "format_version": 0x31,
        "known": True,
    }
    assert [s["class"] for s in parsed["nrbf"]["streams"]] == [
        "Woodward_ToolKit_Tool_ToolProperties",
        "Woodward_ToolKit_Tool_ToolDocument",
    ]
    assert parsed["nrbf"]["errors"] == []
    assert parsed["name"] == "EG3000XT"
    assert parsed["version"] == "1.0"
    assert parsed["description"] == "Synthetic tool file"
    assert parsed["device_names"] == ["ToolConfigurator"]
    assert parsed["sid_specifications"] == ["EG3200XTP1 2.10-1_49670", "EG3200XTP1 2.12-0_50976"]
    assert parsed["application"]["id"] == "EG3200XTP1 2.12-0_50976"
    assert parsed["application"]["model"] == "3200XT-P1"
    assert parsed["application"]["version"] == "2.12-0"
    properties = parsed["tool_properties"]
    assert properties["name"]["default_text"] == "EG3000XT"
    assert properties["name"]["localization_index"] == "41875"
    assert properties["hide_home_page"] is True
    assert properties["localization_add_in_name"] == "ToolkitLocalization1.1_48925.dll"
    assert properties["help_file_name"] is None


def test_parse_sources(wtool, parsed, tmp_path):
    path = tmp_path / "tool.wtool"
    path.write_bytes(wtool)
    assert parse_wtool(path)["name"] == parsed["name"]
    with path.open("rb") as stream:
        assert parse_wtool(stream)["sid_specifications"] == parsed["sid_specifications"]
    assert parse_wtool(12345) == {}  # type: ignore[arg-type]


def test_part_number_tool():
    parsed = parse_wtool(
        build_woodward_wtool(
            name="E3 Full Authority and Fuel Blending Service Tool",
            sid_specifications=("5418-2955C", "5418-4091A"),
            device_names=("Device1",),
        )
    )
    assert parsed["sid_specifications"] == ["5418-2955C", "5418-4091A"]
    assert parsed["application"]["part_number"] == "5418-4091"
    assert parsed["application"]["brand"] == "E3"
    assert parsed["device_names"] == ["Device1"]


def test_unknown_application_falls_back_to_tool_name():
    parsed = parse_wtool(build_woodward_wtool(name="EG3100XT", sid_specifications=()))
    assert parsed["sid_specifications"] == []
    assert parsed["application"]["model"] == "3100XT"
    assert parsed["application"]["id"] == "EG3100XT"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(build_generic_wset(), id="wset"),
        pytest.param(WTOOL_HEADER + b"garbage", id="no nrbf stream"),
    ],
)
def test_invalid_data(data):
    assert parse_wtool(data) == {}


def test_device_names():
    plain = {
        "_class": "DeviceNamesList",
        "items": [
            {"name": {"defaultText": "Device1"}},
            {"name": "Device2"},
            {"name": {"defaultText": None}},
            "Device3",
            {"other": [{"name": ""}, 12]},
        ],
    }
    assert _device_names(plain) == ["Device1", "Device2", "Device3"]
    assert _device_names(None) == []
    assert _device_names([]) == []


def test_find_sid_specifications():
    data = (
        b"xx EG3500XTP2 2.17-0_54728 yy us_5418-6722-NEW zz 5418-4091A 2013 "
        b"EG3500XTP2 2.17-0_54728"
    )
    assert find_sid_specifications(data) == [
        "5418-4091A",
        "5418-6722-NEW",
        "EG3500XTP2 2.17-0_54728",
    ]
    assert find_sid_specifications(b"") == []


def test_populate_device(parsed):
    dev = DeviceData()
    populate_device_from_wtool(dev, parsed)
    assert dev.description.brand == "easYgen"
    assert dev.description.model == "3200XT-P1"
    assert dev.description.product == "easYgen-3200XT-P1"
    assert dev.firmware.version == "2.12-0"
    assert dev.extra["wtool"]["name"] == "EG3000XT"
    assert dev.extra["wtool"]["sid_specifications"] == parsed["sid_specifications"]
    assert "tool_image" not in dev.extra["wtool"]["tool_properties"]

    unknown = DeviceData()
    populate_device_from_wtool(
        unknown, parse_wtool(build_woodward_wtool(name="Mystery", sid_specifications=()))
    )
    assert unknown.description.model == "unknown"

    empty = DeviceData()
    populate_device_from_wtool(empty, {})
    assert not empty.extra
