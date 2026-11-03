"""
Woodward ToolKit tool file (``*.wtool``) parser.

A ToolKit *tool file* contains the display screens and pages ToolKit shows
for a control ("the tool"), and is associated with one or more Service
Interface Definitions (``.sid``). Woodward publishes a tool file per product
and firmware release, e.g. ``8440-2088-C_EG3500XTP2_1.16-0_42785.wtool``.

The file is a ToolKit container (type ``0x15``, see
:mod:`~peat.modules.woodward.toolkit`) holding two .NET binary serialization
streams: a ``Woodward.ToolKit.Tool.ToolProperties`` object (name, version,
description, and the localization add-in of the tool) followed by the
``Woodward.ToolKit.Tool.ToolDocument`` with the screen graph.

Tool files hold no device settings, so PEAT only extracts the tool
properties, the device names, and the SID specifications the tool refers
to. The screen graph is decoded (which takes several seconds for a large
tool file) but not exported.
"""

import re
from pathlib import Path
from typing import Any, BinaryIO, Final

from peat import DeviceData, log

from .parse_wset import _class_name, _get, _snake_keys, is_nrbf_at, read_nrbf_streams, to_plain
from .toolkit import (
    CONTAINER_HEADER_LEN,
    container_type,
    describe_container_header,
    identify_application,
)

_SID_SPEC_RES: Final[tuple[re.Pattern[bytes], ...]] = (
    # XT-style: EG3500XTP2 2.17-0_54728
    re.compile(rb"\b([A-Z]{2,4}\d{3,4}(?:XT)?(?:P\d|LT|LITE|RENTAL)?[ _]\d+\.\d+-\d+_\d+)\b"),
    # Part number style: 5418-6722-NEW, 5418-4091A. SIDs are published per
    # language, and the specification can have a language prefix, e.g.
    # us_5418-6722-NEW or DE_5418-6722-NEW, which isn't part of the identifier.
    re.compile(rb"(?<![A-Za-z0-9])(?:[A-Za-z]{2}_)?(\d{4}-\d{4}(?:-?[A-Z]{1,3}))(?![A-Za-z0-9])"),
)
_NATURAL_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"(\d+)")


def is_wtool_data(data: bytes) -> bool:
    """Check if data looks like a ToolKit tool file."""
    return container_type(data) == "wtool" and is_nrbf_at(data, CONTAINER_HEADER_LEN)


def wtool_signature_check(stream: BinaryIO) -> bool:
    """
    :class:`~peat.file_signature.FileSignature` custom check for ``.wtool`` files.
    """
    return is_wtool_data(stream.read(64))


def _natural_key(identifier: str) -> tuple[tuple[tuple[int, int, str], ...], str]:
    """Sort key that compares the numbers in an identifier numerically."""
    parts = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part.lower())
        for part in _NATURAL_SPLIT_RE.split(identifier)
        if part
    )
    return parts, identifier


def find_sid_specifications(data: bytes) -> list[str]:
    """
    Find SID specification identifiers mentioned in tool file data.

    Language prefixes of part number style specifications (e.g. ``us_`` in
    ``us_5418-6722-NEW``) are removed.

    Args:
        data: The raw file data

    Returns:
        List of unique identifiers, e.g. ``["EG3500XTP2 2.17-0_54728"]``, in
        natural order (numbers are compared numerically, so
        ``EG3200XTP1 2.9-0_1`` comes before ``EG3200XTP1 2.12-0_50976``).
        For identifiers of the same product, the newest release is last.
    """
    found: set[str] = set()
    for pattern in _SID_SPEC_RES:
        for match in pattern.findall(data):
            found.add(match.decode("utf-8", errors="replace"))
    return sorted(found, key=_natural_key)


def _device_names(plain: Any) -> list[str]:
    """Collect the device names from a decoded ``DeviceNamesList``."""
    names: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            name = node.get("name")
            if isinstance(name, dict) and "defaultText" in name:
                names.append(str(name.get("defaultText") or ""))
                return
            if isinstance(name, str):
                names.append(name)
                return
            for key, value in node.items():
                if key != "_class":
                    _walk(value)
        elif isinstance(node, list):
            for value in node:
                _walk(value)
        elif isinstance(node, str):
            names.append(node)

    _walk(plain)
    return [name for name in names if name]


def parse_wtool(source: Path | bytes | BinaryIO) -> dict[str, Any]:
    """
    Parse a Woodward ToolKit tool (``.wtool``) file.

    Args:
        source: Path to the file, the raw file bytes, or a binary file object

    Returns:
        A :class:`dict` with ``header``, ``nrbf`` (stream information),
        ``tool_properties`` (snake_case keys), ``name``, ``device_names``,
        ``sid_specifications``, and ``application``, or an empty
        :class:`dict` if the data isn't a tool file
    """
    if isinstance(source, Path):
        data = source.read_bytes()
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    elif hasattr(source, "read"):
        data = source.read()
    else:
        log.error(f"Unsupported source type for .wtool parsing: {type(source).__name__}")
        return {}

    if not is_wtool_data(data):
        log.warning(
            "Unknown Woodward .wtool format: expected a ToolKit container with a .NET stream"
        )
        return {}

    objects, nrbf_info = read_nrbf_streams(data, CONTAINER_HEADER_LEN)
    parsed: dict[str, Any] = {
        "header": describe_container_header(data[:CONTAINER_HEADER_LEN]),
        "nrbf": nrbf_info,
        "tool_properties": {},
        "name": "",
        "version": "",
        "description": "",
        "device_names": [],
        "sid_specifications": find_sid_specifications(data),
    }
    for obj in objects:
        class_name = _class_name(obj)
        if "ToolProperties" in class_name:
            properties = _snake_keys(to_plain(obj))
            parsed["tool_properties"] = properties
            for key in ("name", "version", "description"):
                value = properties.get(key)
                if isinstance(value, dict):
                    value = value.get("default_text", "")
                parsed[key] = str(value or "").strip()
        elif "ToolDocument" in class_name:
            parsed["device_names"] = _device_names(to_plain(_get(obj, "deviceNames")))

    identifier = (
        parsed["sid_specifications"][-1] if parsed["sid_specifications"] else parsed["name"]
    )
    parsed["application"] = identify_application(identifier)
    if (
        not parsed["application"]["part_number"]
        and not parsed["application"]["model"]
        and parsed["name"]
    ):
        parsed["application"] = {**identify_application(parsed["name"]), "id": identifier}
    return parsed


def populate_device_from_wtool(dev: DeviceData, parsed: dict[str, Any]) -> None:
    """
    Add the results of :func:`parse_wtool` to a device.

    Args:
        dev: The device to populate
        parsed: Output of :func:`parse_wtool`
    """
    if not parsed:
        return
    dev.extra["wtool"] = {key: value for key, value in parsed.items() if key != "tool_properties"}
    dev.extra["wtool"]["tool_properties"] = {
        key: value
        for key, value in parsed.get("tool_properties", {}).items()
        if key != "tool_image"
    }
    app = parsed.get("application", {})
    if app.get("brand") and not dev.description.brand:
        dev.description.brand = app["brand"]
    if app.get("model") and not dev.description.model:
        dev.description.model = app["model"]
    elif not dev.description.model:
        # Don't let the module's default model mislabel a file from another device
        dev.description.model = "unknown"
    if app.get("product") and not dev.description.product:
        dev.description.product = app["product"]
    if app.get("version") and not dev.firmware.version:
        dev.firmware.version = app["version"]


__all__ = [
    "find_sid_specifications",
    "is_wtool_data",
    "parse_wtool",
    "populate_device_from_wtool",
    "wtool_signature_check",
]
