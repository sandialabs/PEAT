"""
Helpers shared by the parsers of Woodward ToolKit file formats.

ToolKit is Woodward's PC service tool for the easYgen genset controllers and
related products (LS-5/LS-6 breaker controls, DTSC-200, DSLC-2, MSLC-2,
GC-3000XT, the 2301E speed control, and others). It works with three file
types that share a common 10-byte container header::

    <type> 3a b5 1f d4 6d 59 c2 <variant> 00

- ``0x14``: settings file (``*.wset``), payload is .NET binary serialization
- ``0x15``: tool file (``*.wtool``), payload is .NET binary serialization
- ``0x16``: Service Interface Definition (``*.sid``), payload is gzip'd XML

Bytes 1 to 7 are constant. Bytes 8 and 9 (a little-endian integer) vary by
file type and ToolKit version (``0x0014`` and ``0x0016`` for settings files,
``0x0031`` and ``0x004a`` for tool files, ``0x0001`` for SIDs have been
observed) and are assumed to be a format version.

This module also identifies the ToolKit *application* (the SID) a file
belongs to. Application identifiers come in two styles:

- easYgen-3000XT and newer: ``EG3500XTP2 2.17-0_54728`` (product short
  name, release, hotfix, and build number)
- easYgen-3000, easYgen-2000, LS-5, etc.: a Woodward software part number
  with revision, e.g. ``5418-6722-NEW``
"""

import re
from typing import Any, Final

#: Length of the ToolKit container header
CONTAINER_HEADER_LEN: Final[int] = 10

#: Constant bytes 1 to 7 of the ToolKit container header
CONTAINER_MAGIC: Final[bytes] = bytes.fromhex("3ab51fd46d59c2")

#: Container type codes (byte 0 of the header)
CONTAINER_TYPES: Final[dict[int, str]] = {
    0x14: "wset",
    0x15: "wtool",
    0x16: "sid",
}

#: Known ToolKit application part numbers (without revision) and their devices.
#: Woodward publishes a SID per product, firmware release, and language, so
#: this table is far from complete. Unknown part numbers are reported as-is.
TOOLKIT_APPLICATIONS: Final[dict[str, dict[str, str]]] = {
    # easYgen-3500 (first generation, non-XT). Source: EPHCC project files
    # (github.com/PowerSystemsHIL/EPHCC) saved from an easYgen-3500,
    # Operating System v1.2102.
    "5418-6722": {"brand": "easYgen", "model": "3500", "product": "easYgen-3500"},
    # easYgen-3000 series P1 (unit 8440-1831). Source: manual 37224A, which
    # uses "8440-1831-NEW_US_5418-2752-NEW_32.WTOOL" as the file naming example.
    "5418-2752": {"brand": "easYgen", "model": "3000-P1", "product": "easYgen-3000 P1"},
    # easYgen-2500-5/P1 (unit 8440-1884). Source: manual 37427, which uses
    # "8440-1884-NEW_US_5418-3090-NEW_32.WTOOL" as the file naming example.
    "5418-3090": {"brand": "easYgen", "model": "2500-5-P1", "product": "easYgen-2500-5/P1"},
    # 2301E digital speed/load control. Source: the factory default settings
    # files (5418-6350 revisions NEW to G) Woodward publishes for the 2301E,
    # https://support.woodward.com/kb/articles/factory-settings-files-for-2301e
    # Files of this application are parsed by the WDW2301E module.
    "5418-6350": {"brand": "WDW", "model": "2301E", "product": "2301E"},
    # Woodward E3 gas engine controls (ToolKit HMI packages published by Woodward)
    "5418-4091": {"brand": "E3", "model": "Full Authority", "product": "E3 Full Authority"},
    "5418-2955": {"brand": "E3", "model": "Fuel Blending", "product": "E3 Fuel Blending"},
    "5418-6528": {"brand": "E3", "model": "Lean Burn Trim", "product": "E3 Lean Burn Trim"},
}

#: ToolKit product short names (as used in XT-style identifiers) and their devices
TOOLKIT_PRODUCT_NAMES: Final[dict[str, dict[str, str]]] = {
    "EG": {"brand": "easYgen", "product": "easYgen"},
    "GC": {"brand": "easYgen", "product": "GC"},
    "LS": {"brand": "easYgen", "product": "LS"},
    "RP": {"brand": "easYgen", "product": "RP"},
    "DSLC": {"brand": "DSLC", "product": "DSLC"},
    "MSLC": {"brand": "MSLC", "product": "MSLC"},
}

# Woodward part numbers (NNNN-NNNN or NNNN-NNN) with an optional revision
# that is attached or follows a "-", "_", or space: 5418-6722-NEW, 5418-4091A,
# 9908-419A, 8440-2088_M, 5418-6722 NEW. A revision must end at a boundary,
# otherwise the part number has no revision (5418-6722-NEWS, 5418-6722_32).
_PART_NUMBER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(?<!\d-)(?P<part>\d{4}-\d{3,4})(?!\d)"
    r"(?:(?:[-_]?(?P<rev>[A-Za-z][A-Za-z0-9]{0,2})|\s(?P<spaced_rev>[A-Z]{1,3}))"
    r"(?![A-Za-z0-9]))?"
)
_XT_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<prefix>[A-Z]{2,4})(?P<number>\d{1,4})(?P<xt>XT)?(?P<variant>P\d|LT|LITE|RENTAL)?"
    r"(?:[\s_]+(?P<version>\d+\.\d+(?:-\d+)?))?(?:_(?P<build>\d+))?",
)


def is_2301e_application(app: dict[str, Any]) -> bool:
    """
    Check if an application is a recognized 2301E application.

    ToolKit files of 2301E applications are parsed by the
    :class:`~peat.modules.woodward.wdw_2301e.WDW2301E` module, all other
    ToolKit files by the :class:`~peat.modules.woodward.easygen_3500xt.Easygen3500XT`
    module.

    Args:
        app: The application, as identified by :func:`identify_application`

    Returns:
        If the application is a 2301E application
    """
    return app.get("brand") == "WDW" and app.get("model") == "2301E"


def container_type(data: bytes) -> str | None:
    """
    Identify the type of a ToolKit container file from its header.

    Args:
        data: The file data (at least the first 10 bytes)

    Returns:
        ``"wset"``, ``"wtool"``, ``"sid"``, ``"unknown"`` (valid header with an
        unknown type code), or :obj:`None` if the data isn't a ToolKit container
    """
    if len(data) < CONTAINER_HEADER_LEN or data[1:8] != CONTAINER_MAGIC:
        return None
    return CONTAINER_TYPES.get(data[0], "unknown")


def is_toolkit_container(data: bytes) -> bool:
    """
    Check if data starts with a ToolKit container header.
    """
    return container_type(data) is not None


def describe_container_header(header: bytes) -> dict[str, Any]:
    """
    Describe a ToolKit container header.

    Args:
        header: The header bytes (normally the first 10 bytes of the file)

    Returns:
        A :class:`dict` with the ``hex`` value, ``length``, ``type``
        (``wset``/``wtool``/``sid``/``unknown``/``""``), ``type_code``,
        ``variant`` byte, and whether the header is a ``known`` ToolKit header
    """
    kind = container_type(header)
    return {
        "hex": header.hex(),
        "length": len(header),
        "type": kind or "",
        "type_code": header[0] if header else None,
        # Bytes 8-9 (little-endian) differ by file type and ToolKit version,
        # so this is likely a format version. This is inferred, not documented.
        "format_version": int.from_bytes(header[8:10], "little") if len(header) >= 10 else None,
        "known": kind is not None and kind != "unknown",
    }


def identify_application(identifier: str) -> dict[str, Any]:
    """
    Identify the device a ToolKit application (SID) identifier belongs to.

    Args:
        identifier: The application identifier, e.g. ``5418-6722-NEW``
            or ``EG3500XTP2 2.17-0_54728``

    Returns:
        A :class:`dict` with ``id``, ``part_number``, ``revision``,
        ``version``, ``build``, ``brand``, ``model``, and ``product``.
        Values that can't be determined are empty strings.
    """
    info: dict[str, Any] = {
        "id": identifier or "",
        "part_number": "",
        "revision": "",
        "version": "",
        "build": "",
        "brand": "",
        "model": "",
        "product": "",
    }
    if not identifier:
        return info

    match = _PART_NUMBER_RE.search(identifier)
    if match:
        info["part_number"] = match.group("part")
        info["revision"] = match.group("rev") or match.group("spaced_rev") or ""
        info.update(TOOLKIT_APPLICATIONS.get(match.group("part"), {}))
        return info

    match = _XT_IDENTIFIER_RE.match(identifier.strip())
    if match and match.group("prefix") in TOOLKIT_PRODUCT_NAMES:
        names = TOOLKIT_PRODUCT_NAMES[match.group("prefix")]
        model = match.group("number") + (match.group("xt") or "")
        if match.group("variant"):
            model += f"-{match.group('variant')}"
        info["brand"] = names["brand"]
        info["model"] = model
        info["product"] = f"{names['product']}-{model}"
        info["version"] = match.group("version") or ""
        info["build"] = match.group("build") or ""
    return info


__all__ = [
    "CONTAINER_HEADER_LEN",
    "CONTAINER_MAGIC",
    "CONTAINER_TYPES",
    "TOOLKIT_APPLICATIONS",
    "TOOLKIT_PRODUCT_NAMES",
    "container_type",
    "describe_container_header",
    "identify_application",
    "is_2301e_application",
    "is_toolkit_container",
]
