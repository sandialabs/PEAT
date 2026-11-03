"""Tests for the shared Woodward ToolKit helpers (peat/modules/woodward/toolkit.py)."""

import pytest

from peat.modules.woodward.toolkit import (
    CONTAINER_HEADER_LEN,
    CONTAINER_MAGIC,
    container_type,
    describe_container_header,
    identify_application,
    is_2301e_application,
    is_toolkit_container,
)

from .nrbf_builder import SID_HEADER, WSET_HEADER, WTOOL_HEADER, container_header


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(WSET_HEADER, "wset", id="wset"),
        pytest.param(WTOOL_HEADER, "wtool", id="wtool"),
        pytest.param(SID_HEADER, "sid", id="sid"),
        pytest.param(bytes.fromhex("143ab51fd46d59c21400") + b"\x00\x01", "wset", id="real wset"),
        pytest.param(bytes.fromhex("153ab51fd46d59c24a00"), "wtool", id="real wtool 7.x"),
        pytest.param(bytes.fromhex("163ab51fd46d59c20100"), "sid", id="real sid"),
        pytest.param(container_header(0x17, 1), "unknown", id="unknown type code"),
        pytest.param(b"\x14" + b"\x00" * 9, None, id="wrong magic"),
        pytest.param(WSET_HEADER[:9], None, id="too short"),
        pytest.param(b"", None, id="empty"),
    ],
)
def test_container_type(data, expected):
    assert container_type(data) == expected
    assert is_toolkit_container(data) == (expected is not None)


def test_container_constants():
    assert CONTAINER_HEADER_LEN == 10
    assert WSET_HEADER[1:8] == CONTAINER_MAGIC
    assert len(WSET_HEADER) == CONTAINER_HEADER_LEN


def test_describe_container_header():
    described = describe_container_header(bytes.fromhex("143ab51fd46d59c21400"))
    assert described == {
        "hex": "143ab51fd46d59c21400",
        "length": 10,
        "type": "wset",
        "type_code": 0x14,
        "format_version": 0x14,
        "known": True,
    }

    unknown = describe_container_header(b"\x01\x02\x03")
    assert unknown["type"] == ""
    assert unknown["known"] is False
    assert unknown["format_version"] is None
    assert unknown["length"] == 3

    assert describe_container_header(b"")["type_code"] is None


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        pytest.param(
            "5418-6722-NEW",
            {
                "part_number": "5418-6722",
                "revision": "NEW",
                "brand": "easYgen",
                "model": "3500",
                "product": "easYgen-3500",
            },
            id="easYgen-3500 part number",
        ),
        pytest.param(
            "us_5418-6722-NEW",
            {"part_number": "5418-6722", "revision": "NEW", "model": "3500"},
            id="SID specification with language prefix",
        ),
        pytest.param(
            "5418-4091A 2013-10-24 11.14.58",
            {
                "part_number": "5418-4091",
                "revision": "A",
                "brand": "E3",
                "model": "Full Authority",
            },
            id="E3 part number with revision letter and timestamp",
        ),
        pytest.param(
            "5418-6350_G 2017-04-24 10.52.31",
            {
                "part_number": "5418-6350",
                "revision": "G",
                "brand": "WDW",
                "model": "2301E",
                "product": "2301E",
            },
            id="2301E application identifier",
        ),
        pytest.param(
            "5418-6350_New 2012-10-08 09.18.02",
            {"part_number": "5418-6350", "revision": "New", "model": "2301E"},
            id="2301E revision New",
        ),
        pytest.param(
            "#5418-6350_D 2014-11-17 18.21.21 UTC",
            {"part_number": "5418-6350", "revision": "D", "model": "2301E"},
            id="2301E SID specification",
        ),
        pytest.param(
            "5418-9999-NEW",
            {
                "part_number": "5418-9999",
                "revision": "NEW",
                "brand": "",
                "model": "",
                "product": "",
            },
            id="unknown part number",
        ),
        pytest.param(
            "EG3500XTP2 2.17-0_54728",
            {
                "part_number": "",
                "version": "2.17-0",
                "build": "54728",
                "brand": "easYgen",
                "model": "3500XT-P2",
                "product": "easYgen-3500XT-P2",
            },
            id="easYgen-3000XT identifier",
        ),
        pytest.param(
            "EG3200XTP1 2.12-0_50976",
            {"model": "3200XT-P1", "version": "2.12-0", "build": "50976"},
            id="easYgen-3200XT",
        ),
        pytest.param(
            "EG3500XTP2 2.17-0_54728.CAN",
            {"model": "3500XT-P2", "version": "2.17-0", "build": "54728"},
            id="CAN SID identifier",
        ),
        pytest.param(
            "EG3100XT", {"model": "3100XT", "version": "", "build": ""}, id="bare XT name"
        ),
        pytest.param("LS6XT 1.0-0_1", {"model": "6XT", "product": "LS-6XT"}, id="LS-6XT"),
        pytest.param("", {"id": "", "model": "", "part_number": ""}, id="empty"),
        pytest.param(
            "Something else", {"model": "", "part_number": "", "version": ""}, id="unknown"
        ),
    ],
)
def test_identify_application(identifier, expected):
    info = identify_application(identifier)
    assert info["id"] == identifier
    for key, value in expected.items():
        assert info[key] == value, key
    assert set(info) == {
        "id",
        "part_number",
        "revision",
        "version",
        "build",
        "brand",
        "model",
        "product",
    }


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        ("5418-6350_G 2017-04-24 10.52.31", True),
        ("5418-6350-NEW", True),
        ("5418-6722-NEW", False),
        ("EG3500XTP2 2.17-0_54728", False),
        ("5418-4091A", False),
        ("5418-9999-NEW", False),
        ("", False),
    ],
)
def test_is_2301e_application(identifier, expected):
    assert is_2301e_application(identify_application(identifier)) is expected
