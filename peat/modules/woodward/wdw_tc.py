"""
Woodward Control Assistant tunable file (``*.tc``) parser.

Woodward's *Control Assistant* service tool has a "Tunable Maintenance"
feature that retrieves the tunable (adjustable) values of a control over the
ServLink protocol and saves them to a tab-separated text file with a ``.tc``
extension. The same file can later be compared against, or loaded back into,
a control. Tunable files are produced for GAP-based controls (e.g. the 2301E,
505, Atlas, and MicroNet families) and for other ServLink-capable controls
such as the easYgen genset controllers.

File layout (tab-separated text, CRLF or LF line endings, ``|`` marks a tab)::

    File Version: 1.0
    5418-6766 NEW
    2015-03-23 14:32:11 UTC
    Mode|Category|Block Name|Field Name|Type|Current|Initial|Low|High
    Service|A**ENGINE**|SPEED_SP|IN_1|Float|1800.0|1800.0|500.0|4000.0
    ...

The lines before the column header are metadata: the file version, the
application (firmware) identifier of the control, and the timestamp of when
the tunables were retrieved. The column header line always starts with
``Mode``. Every following line is one tunable field, identified by its
``Mode``, ``Category``, ``Block Name``, and ``Field Name``.

The parser is tolerant of extra or missing columns, blank lines, and the
common text encodings used by Windows tools (UTF-8, UTF-16, and Windows-1252).
"""

import re
from pathlib import Path
from typing import Any, BinaryIO, Final

from peat import DeviceData, log, utils

#: Name of the first column of the header line. Used to detect the header.
TC_HEADER_FIRST_COLUMN: Final[str] = "Mode"

#: The columns Control Assistant writes to a tunable file, in order.
TC_EXPECTED_COLUMNS: Final[list[str]] = [
    "Mode",
    "Category",
    "Block Name",
    "Field Name",
    "Type",
    "Current",
    "Initial",
    "Low",
    "High",
]

#: Columns that identify a tunable (used to build the nested ``config`` tree).
TC_HIERARCHY_COLUMNS: Final[list[str]] = TC_EXPECTED_COLUMNS[:4]

#: Columns holding values that are converted to Python types in ``parameters``.
TC_NUMERIC_COLUMNS: Final[tuple[str, ...]] = ("Current", "Initial", "Low", "High")

#: Maximum number of lines searched for the column header.
TC_MAX_HEADER_SEARCH_LINES: Final[int] = 20

_FILE_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"File\s*Version\s*[:=]?\s*([0-9][0-9A-Za-z._-]*)", re.IGNORECASE
)
_INT_RE: Final[re.Pattern[str]] = re.compile(r"^[+-]?\d+$")
_BOOL_TRUE: Final[frozenset[str]] = frozenset({"true", "t", "yes", "y", "on"})
_BOOL_FALSE: Final[frozenset[str]] = frozenset({"false", "f", "no", "n", "off"})
_BOOL_TYPES: Final[frozenset[str]] = frozenset({"bool", "boolean", "logical", "bit"})


def decode_text(data: bytes | str) -> str:
    """
    Decode text written by a Windows tool, trying the common encodings.

    UTF-16 (with a byte order mark), UTF-8 (optionally with a byte order mark),
    Windows-1252, and finally Latin-1 (which never fails) are tried, in order.

    Args:
        data: Raw bytes to decode, or a string (returned as-is)

    Returns:
        The decoded text
    """
    if isinstance(data, str):
        return data
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            log.debug("Text has a UTF-16 byte order mark but isn't valid UTF-16")
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def is_tc_data(data: bytes | str) -> bool:
    """
    Check if data looks like a Control Assistant tunable (``.tc``) file.

    The check is cheap and only looks at the start of the data:
    a ``File Version`` line followed by a tab-separated column header line
    starting with ``Mode``.

    Args:
        data: The raw file data (or the beginning of it)

    Returns:
        :obj:`True` if the data appears to be a tunable file
    """
    if not data:
        return False
    if isinstance(data, bytes):
        data = data[:4096]
    text = decode_text(data)
    lines = text.splitlines()[: TC_MAX_HEADER_SEARCH_LINES + 1]
    has_version = any("file version" in line.lower() for line in lines)
    has_header = any(
        line.split("\t", 1)[0].strip().lower() == TC_HEADER_FIRST_COLUMN.lower() and "\t" in line
        for line in lines
    )
    return has_version and has_header


def tc_signature_check(stream: BinaryIO) -> bool:
    """
    :class:`~peat.file_signature.FileSignature` custom check for ``.tc`` files.
    """
    return is_tc_data(stream.read(4096))


def _read_source(source: Path | bytes | str) -> str:
    if isinstance(source, Path):
        return decode_text(source.read_bytes())
    if isinstance(source, (bytes, bytearray)):
        return decode_text(bytes(source))
    if isinstance(source, str):
        return source
    raise TypeError(f"Unsupported source type for .tc parsing: {type(source).__name__}")


def convert_tc_value(raw: str, type_name: str = "") -> Any:
    """
    Convert a tunable value string to a Python value.

    Booleans are recognized by the ``Type`` column (``Boolean``, ``Bool``,
    ``Logical``) or by ``TRUE``/``FALSE`` text, integers and floats by their
    text, and anything else is returned as a stripped string.

    Args:
        raw: The value text from the file
        type_name: The ``Type`` column value, if known

    Returns:
        A :class:`bool`, :class:`int`, :class:`float`, or :class:`str`
    """
    value = raw.strip()
    lowered = value.lower()
    if type_name.strip().lower() in _BOOL_TYPES:
        if lowered in _BOOL_TRUE or lowered == "1":
            return True
        if lowered in _BOOL_FALSE or lowered == "0":
            return False
    if lowered in _BOOL_TRUE:
        return True
    if lowered in _BOOL_FALSE:
        return False
    if _INT_RE.match(value):
        return int(value)
    try:
        return float(value)
    except ValueError:
        return value


def _find_header(lines: list[str]) -> int | None:
    for index, line in enumerate(lines[:TC_MAX_HEADER_SEARCH_LINES]):
        if "\t" not in line:
            continue
        first_column = line.split("\t", 1)[0].strip()
        if first_column.lower() == TC_HEADER_FIRST_COLUMN.lower():
            return index
    return None


def _parse_metadata(meta_lines: list[str]) -> dict[str, Any]:
    """Interpret the lines that precede the column header."""
    metadata: dict[str, Any] = {
        "file_version": "",
        "version": "",
        "firmware_prefix": "",
        "firmware_date": "",
        "metadata_lines": list(meta_lines),
    }
    remaining = []
    for line in meta_lines:
        match = _FILE_VERSION_RE.search(line)
        if match and not metadata["file_version"]:
            metadata["file_version"] = line
            metadata["version"] = match.group(1)
        elif "utc" in line.lower() and not metadata["firmware_date"]:
            metadata["firmware_date"] = line
        elif utils.parse_date(line) and not metadata["firmware_date"]:
            metadata["firmware_date"] = line
        else:
            remaining.append(line)
    if remaining:
        # The application/firmware identifier, e.g. "5418-6766 NEW"
        metadata["firmware_prefix"] = remaining[0]
    return metadata


def parse_tc(source: Path | bytes | str) -> dict[str, Any]:
    """
    Parse a Woodward Control Assistant tunable (``.tc``) file.

    Args:
        source: Path to the file, the raw file bytes, or the decoded text

    Returns:
        A :class:`dict` with the file metadata and the tunables, or an empty
        :class:`dict` if the data isn't a tunable file. Keys:

        - ``file_version``: the raw "File Version" line
        - ``version``: the file version number, e.g. ``"1.0"``
        - ``firmware_prefix``: the application/firmware identifier line
        - ``firmware_date``: the timestamp line
        - ``metadata_lines``: all lines before the column header
        - ``columns``: the column names from the header line
        - ``config``: nested :class:`dict` of ``Mode -> Category -> Block Name
          -> Field Name -> {Type, Current, Initial, Low, High}`` with the raw
          string values
        - ``parameters``: flat :class:`list` of tunables with typed values
        - ``modes``, ``categories``: sorted lists of the unique values seen
        - ``num_parameters``: number of tunables parsed
        - ``num_malformed_lines``: number of lines that couldn't be parsed
    """
    try:
        text = _read_source(source)
    except (OSError, TypeError) as ex:
        log.error(f"Failed to read .tc data: {ex}")
        return {}

    if not text or not text.strip():
        log.error("No data to parse as a Woodward .tc file")
        return {}

    lines = text.splitlines()
    header_index = _find_header(lines)
    if header_index is None:
        log.warning(
            f"Unknown Woodward .tc format: no tab-separated column header line "
            f"starting with '{TC_HEADER_FIRST_COLUMN}' in the first "
            f"{TC_MAX_HEADER_SEARCH_LINES} lines"
        )
        return {}

    meta_lines = [line.strip() for line in lines[:header_index] if line.strip()]
    parsed: dict[str, Any] = _parse_metadata(meta_lines)
    if not parsed["file_version"]:
        log.warning("Woodward .tc file is missing the 'File Version' line")

    columns = [column.strip() for column in lines[header_index].split("\t")]
    parsed["columns"] = columns
    if columns != TC_EXPECTED_COLUMNS:
        log.debug(f"Non-standard .tc columns: {columns} (expected {TC_EXPECTED_COLUMNS})")

    # Indices of the four hierarchy columns and of the "Type" column
    num_hierarchy = len(TC_HIERARCHY_COLUMNS)
    if len(columns) <= num_hierarchy:
        log.warning(f"Woodward .tc file has too few columns to parse: {columns}")
        return {}
    value_columns = columns[num_hierarchy:]
    type_index = _column_index(columns, "Type")

    config: dict[str, Any] = {}
    parameters: list[dict[str, Any]] = []
    modes: set[str] = set()
    categories: set[str] = set()
    malformed = 0

    for line in lines[header_index + 1 :]:
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) <= num_hierarchy:
            log.debug(f"Malformed .tc line: '{line}'")
            malformed += 1
            continue
        # Tolerate short rows by padding, keep extra fields on long rows
        if len(fields) < len(columns):
            fields.extend([""] * (len(columns) - len(fields)))
        hierarchy = [field.strip() for field in fields[:num_hierarchy]]
        values = [field.strip() for field in fields[num_hierarchy:]]

        # Nested tree of raw strings (Mode -> Category -> Block -> Field -> values)
        ref = config
        for key in hierarchy:
            ref = ref.setdefault(key, {})
        for name, value in zip(value_columns, values, strict=False):
            ref[name] = value
        if len(values) > len(value_columns):
            ref["extra"] = values[len(value_columns) :]

        # Flat, typed record
        type_name = fields[type_index].strip() if type_index is not None else ""
        record: dict[str, Any] = dict(
            zip(("mode", "category", "block", "field"), hierarchy, strict=False)
        )
        record["path"] = "/".join(hierarchy[1:]) if len(hierarchy) > 1 else hierarchy[0]
        record["type"] = type_name
        for name, value in zip(value_columns, values, strict=False):
            if name == "Type":
                continue
            key = name.lower().replace(" ", "_")
            record[key] = (
                convert_tc_value(value, type_name) if name in TC_NUMERIC_COLUMNS else value
            )
        parameters.append(record)
        if hierarchy:
            modes.add(hierarchy[0])
        if len(hierarchy) > 1:
            categories.add(hierarchy[1])

    if malformed:
        log.warning(f"Skipped {malformed} malformed lines in Woodward .tc file")
    if not parameters:
        log.warning("No tunables found in Woodward .tc file")

    parsed["config"] = config
    parsed["parameters"] = parameters
    parsed["modes"] = sorted(modes)
    parsed["categories"] = sorted(categories)
    parsed["num_parameters"] = len(parameters)
    parsed["num_malformed_lines"] = malformed
    return parsed


def _column_index(columns: list[str], name: str) -> int | None:
    for index, column in enumerate(columns):
        if column.lower() == name.lower():
            return index
    return None


def populate_device_from_tc(dev: DeviceData, parsed: dict[str, Any]) -> None:
    """
    Add the results of :func:`parse_tc` to a device.

    The firmware identifier and timestamp are stored in ``dev.firmware``,
    the flat list of tunables in ``dev.extra["parameters"]``, and a summary
    of the file in ``dev.extra["tc"]``.

    Args:
        dev: The device to populate
        parsed: Output of :func:`parse_tc`
    """
    if not parsed:
        return

    summary = {
        key: parsed.get(key)
        for key in (
            "file_version",
            "version",
            "firmware_prefix",
            "firmware_date",
            "metadata_lines",
            "columns",
            "modes",
            "categories",
            "num_parameters",
            "num_malformed_lines",
        )
    }
    dev.extra["tc"] = summary
    dev.extra["parameters"] = parsed.get("parameters", [])

    prefix = parsed.get("firmware_prefix", "")
    if prefix and not dev.firmware.id:
        dev.firmware.id = prefix

    date_line = parsed.get("firmware_date", "")
    if date_line and not dev.firmware.timestamp:
        timestamp = utils.parse_date(date_line.replace("UTC", "").strip())
        if timestamp:
            dev.firmware.timestamp = timestamp


def _parse_tc_file(project: str | bytes | None) -> dict[str, Any]:
    """
    Parse a ``*.tc`` device config file.

    Deprecated alias of :func:`parse_tc` kept for backwards compatibility.

    Args:
        project: The .tc file contents

    Returns:
        A dictionary containing the device config
    """
    if project is None:
        log.error("No project specified")
        return {}
    return parse_tc(project)


__all__ = [
    "TC_EXPECTED_COLUMNS",
    "convert_tc_value",
    "decode_text",
    "is_tc_data",
    "parse_tc",
    "populate_device_from_tc",
    "tc_signature_check",
]
