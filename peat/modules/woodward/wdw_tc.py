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

import math
import re
from pathlib import Path
from typing import Any, BinaryIO, Final

from peat import DeviceData, consts, log, utils

from .toolkit import identify_application

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

#: Maximum number of lines searched for the column header
#: (used by both :func:`is_tc_data` and :func:`parse_tc`).
TC_MAX_HEADER_SEARCH_LINES: Final[int] = 21

#: Number of bytes read to identify the application of a ``.tc`` file
TC_SNIFF_LEN: Final[int] = 4096

#: Brand used for tunable files from controls that aren't identified.
TC_DEFAULT_BRAND: Final[str] = "Woodward"

_FILE_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"File\s*Version\s*[:=]?\s*([0-9][0-9A-Za-z._-]*)", re.IGNORECASE
)
_INT_RE: Final[re.Pattern[str]] = re.compile(r"^[+-]?\d+$")
_BOOL_TYPES: Final[frozenset[str]] = frozenset({"bool", "boolean", "logical", "bit"})
_FLOAT_TYPES: Final[frozenset[str]] = frozenset(
    {"float", "real", "lreal", "double", "single", "float32", "float64"}
)
_INT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "int",
        "integer",
        "sint",
        "dint",
        "lint",
        "usint",
        "uint",
        "udint",
        "ulint",
        "short",
        "long",
        "byte",
        "word",
        "dword",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
    }
)
#: Number of bytes checked for the NUL byte pattern of UTF-16 text without a BOM
_UTF16_SNIFF_LEN: Final[int] = 64


def decode_text(data: bytes | str) -> str:
    """
    Decode text written by a Windows tool, trying the common encodings.

    UTF-16 (with a byte order mark, or without one if the NUL bytes of the
    first characters show it's UTF-16), UTF-8 (optionally with a byte order
    mark), Windows-1252, and finally Latin-1 (which never fails) are tried,
    in order.

    Args:
        data: Raw bytes to decode, or a string (returned without a leading
            byte order mark)

    Returns:
        The decoded text
    """
    if isinstance(data, str):
        return data.removeprefix("\ufeff")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            log.debug("Text has a UTF-16 byte order mark but isn't valid UTF-16")
    utf16 = _sniff_utf16(data)
    if utf16:
        try:
            return data.decode(utf16)
        except UnicodeDecodeError:
            log.debug(f"Text looks like {utf16} without a byte order mark but isn't valid")
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def _sniff_utf16(data: bytes) -> str | None:
    """
    Detect UTF-16 text without a byte order mark.

    Mostly-ASCII UTF-16 text has a NUL byte in every other position
    (the high byte of each character), which doesn't happen in UTF-8 or
    Windows-1252 text.

    Returns:
        ``"utf-16-le"``, ``"utf-16-be"``, or :obj:`None`
    """
    sample = data[:_UTF16_SNIFF_LEN]
    sample = sample[: len(sample) - len(sample) % 2]
    half = len(sample) // 2
    if half < 2:
        return None
    even_nuls = sample[0::2].count(0)
    odd_nuls = sample[1::2].count(0)
    if not even_nuls and odd_nuls * 2 > half:
        return "utf-16-le"
    if not odd_nuls and even_nuls * 2 > half:
        return "utf-16-be"
    return None


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
        data = data[:TC_SNIFF_LEN]
    text = decode_text(data)
    lines = text.splitlines()[:TC_MAX_HEADER_SEARCH_LINES]
    has_version = any("file version" in line.lower() for line in lines)
    return has_version and _find_header(lines) is not None


def tc_signature_check(stream: BinaryIO) -> bool:
    """
    :class:`~peat.file_signature.FileSignature` custom check for ``.tc`` files.
    """
    return is_tc_data(stream.read(TC_SNIFF_LEN))


def _read_source(source: Path | bytes | str) -> str:
    if isinstance(source, Path):
        return decode_text(source.read_bytes())
    if isinstance(source, (bytes, bytearray)):
        return decode_text(bytes(source))
    if isinstance(source, str):
        return decode_text(source)
    raise TypeError(f"Unsupported source type for .tc parsing: {type(source).__name__}")


def unquote_tc_field(raw: str) -> str:
    """
    Remove the double quotes a spreadsheet adds around a field.

    One level of matching surrounding double quotes is removed and embedded
    doubled quotes are un-doubled, the way spreadsheets write them when a
    tab-separated file is saved. Fields that aren't quoted are returned
    stripped.
    """
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1].replace('""', '"')
    return value


def _to_float(value: str) -> float | str:
    """
    Convert to a finite float, or return the text (NaN/inf aren't valid JSON).
    """
    try:
        number = float(value)
    except ValueError:
        return value
    return number if math.isfinite(number) else value


def convert_tc_value(raw: str, type_name: str = "") -> Any:
    """
    Convert a tunable value string to a Python value.

    The value is unquoted first (see :func:`unquote_tc_field`). The
    ``Type`` column is respected when it's known: boolean types
    (``Boolean``, ``Bool``, ``Logical``) are converted with
    :func:`peat.consts.str_to_bool`, float types (``Float``, ``Real``,
    ``Double``, ...) to :class:`float`, and integer types (``Integer``,
    ``DINT``, ``Word``, ...) to :class:`int`. Untyped values are
    converted by their text (boolean words such as ``TRUE``, ``no``, ``on``,
    integers, and floats). Values that can't be converted, and non-finite
    numbers (``nan``, ``inf``), are returned as a stripped string.

    Args:
        raw: The value text from the file
        type_name: The ``Type`` column value, if known

    Returns:
        A :class:`bool`, :class:`int`, :class:`float`, or :class:`str`
    """
    value = unquote_tc_field(raw)
    kind = unquote_tc_field(type_name).lower()
    if kind in _BOOL_TYPES:
        try:
            return consts.str_to_bool(value)
        except ValueError:
            return value
    if kind in _FLOAT_TYPES:
        return _to_float(value)
    if kind in _INT_TYPES:
        if _INT_RE.match(value):
            return int(value)
        number = _to_float(value)
        # e.g. "60.0" for an integer, or a value that isn't a number at all
        return int(number) if isinstance(number, float) and number.is_integer() else number
    if _INT_RE.match(value):
        return int(value)
    if not kind:
        try:
            return consts.str_to_bool(value)
        except ValueError:
            pass
    return _to_float(value)


def _find_header(lines: list[str]) -> int | None:
    """
    Index of the column header line, if it's in the first lines.
    """
    for index, line in enumerate(lines[:TC_MAX_HEADER_SEARCH_LINES]):
        if "\t" not in line:
            continue
        first_column = line.split("\t", 1)[0].strip()
        if unquote_tc_field(first_column).lower() == TC_HEADER_FIRST_COLUMN.lower():
            return index
    return None


def _parse_metadata(meta_lines: list[str]) -> dict[str, Any]:
    """
    Interpret the lines that precede the column header.
    """
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
        elif not metadata["firmware_date"] and _is_date_line(line):
            metadata["firmware_date"] = line
        else:
            remaining.append(line)
    if remaining:
        # The application/firmware identifier, e.g. "5418-6766 NEW"
        metadata["firmware_prefix"] = remaining[0]
    return metadata


def _is_date_line(line: str) -> bool:
    """
    Check if a metadata line is the timestamp line, e.g. ``2015-03-23 14:32:11 UTC``.

    The check is strict, so application identifiers such as ``5418-1234 NEW``
    or ``5418-12 A`` aren't mistaken for dates.
    """
    return utils.is_date(line) or utils.is_date(_strip_utc(line))


def _strip_utc(line: str) -> str:
    return re.sub(r"\bUTC\b", "", line, flags=re.IGNORECASE).strip()


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
          (every row and column, see :func:`tc_parameter_values` for the
          ``{path: value}`` form stored in ``dev.extra["parameters"]``)
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

    columns = [unquote_tc_field(column) for column in lines[header_index].split("\t")]
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
        hierarchy = [unquote_tc_field(field) for field in fields[:num_hierarchy]]
        raw_values = fields[num_hierarchy:]
        values = [unquote_tc_field(field) for field in raw_values]

        # Nested tree of raw strings (Mode -> Category -> Block -> Field -> values)
        ref = config
        for key in hierarchy:
            ref = ref.setdefault(key, {})
        for name, value in zip(value_columns, values, strict=False):
            ref[name] = value
        if len(values) > len(value_columns):
            ref["extra"] = values[len(value_columns) :]

        # Flat, typed record
        type_name = unquote_tc_field(fields[type_index]) if type_index is not None else ""
        record: dict[str, Any] = dict(
            zip(("mode", "category", "block", "field"), hierarchy, strict=False)
        )
        record["path"] = "/".join(hierarchy[1:]) if len(hierarchy) > 1 else hierarchy[0]
        record["type"] = type_name
        for name, raw, value in zip(value_columns, raw_values, values, strict=False):
            if name == "Type":
                continue
            key = name.lower().replace(" ", "_")
            # Conversion does its own unquoting, so pass the raw text
            record[key] = convert_tc_value(raw, type_name) if name in TC_NUMERIC_COLUMNS else value
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


def tc_parameter_values(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Current values of the tunables, by path.

    The keys are the ``Category/Block Name/Field Name`` paths of the tunables.
    If the same path appears in more than one mode, the mode is added to the
    key of the later ones (``Mode/Category/Block Name/Field Name``).

    Args:
        records: The ``parameters`` list from :func:`parse_tc`

    Returns:
        :class:`dict` of ``{path: current value}``
    """
    values: dict[str, Any] = {}
    for record in records:
        key = str(record.get("path", ""))
        if key in values:
            key = f"{record.get('mode', '')}/{key}"
        values[key] = record.get("current")
    return values


def tc_application_info(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Identify the control a tunable file was retrieved from.

    The application (firmware) identifier line of the file, e.g.
    ``5418-6722 NEW``, is looked up with
    :func:`~peat.modules.woodward.toolkit.identify_application`. Modules can
    use this to decide whether a ``.tc`` file belongs to them: ``model`` is
    empty if the application isn't known (e.g. most GAP-based controls such
    as the 2301E).

    Args:
        parsed: Output of :func:`parse_tc`

    Returns:
        The :func:`~peat.modules.woodward.toolkit.identify_application`
        :class:`dict` (``id``, ``part_number``, ``revision``, ``version``,
        ``build``, ``brand``, ``model``, and ``product``)
    """
    return identify_application(str(parsed.get("firmware_prefix") or ""))


def tc_head_application_info(data: bytes) -> dict[str, Any] | None:
    """
    Identify the application of a Control Assistant tunable (``.tc``) file from its start.

    Only the metadata lines at the top of the file are needed, so the data
    can be the first few kilobytes of the file (see :data:`TC_SNIFF_LEN`).
    The tunables aren't parsed, so nothing is logged about them (this runs
    for every candidate file when searching for files to parse).

    Args:
        data: The start of the file

    Returns:
        The :func:`tc_application_info` :class:`dict`, or :obj:`None` if
        the data isn't a tunable file
    """
    if not is_tc_data(data):
        return None
    lines = decode_text(data).splitlines()
    # is_tc_data() found the column header, the metadata lines are before it
    header_index = _find_header(lines)
    meta_lines = [line.strip() for line in lines[:header_index] if line.strip()]
    return tc_application_info(_parse_metadata(meta_lines))


def populate_device_from_tc(dev: DeviceData, parsed: dict[str, Any]) -> None:
    """
    Add the results of :func:`parse_tc` to a device.

    The firmware identifier and timestamp are stored in ``dev.firmware``,
    the current tunable values are merged into ``dev.extra["parameters"]``
    (``{path: value}``, see :func:`tc_parameter_values`), and a summary of
    the file in ``dev.extra["tc"]``. The full list of tunables (with the
    initial, low, and high values) is in the output of :func:`parse_tc`.

    The brand is set to the brand of the application if it's known (see
    :func:`tc_application_info`), otherwise ``Woodward``. The model and
    product are only set if the application is known, otherwise they're left
    for the calling module.

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
    parameters = dev.extra.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {}
        dev.extra["parameters"] = parameters
    parameters.update(tc_parameter_values(parsed.get("parameters", [])))

    prefix = parsed.get("firmware_prefix", "")
    if prefix and not dev.firmware.id:
        dev.firmware.id = prefix

    app = tc_application_info(parsed)
    if not dev.description.brand:
        dev.description.brand = app["brand"] if app["model"] else TC_DEFAULT_BRAND
    if app["model"]:
        if not dev.description.model:
            dev.description.model = app["model"]
        if app["product"] and not dev.description.product:
            dev.description.product = app["product"]

    date_line = parsed.get("firmware_date", "")
    if date_line and not dev.firmware.timestamp:
        for candidate in (_strip_utc(date_line), date_line):
            if utils.is_date(candidate):
                # Without "UTC", so the timestamp is naive like other PEAT timestamps
                dev.firmware.timestamp = utils.parse_date(candidate)
                break


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
    "TC_MAX_HEADER_SEARCH_LINES",
    "TC_SNIFF_LEN",
    "convert_tc_value",
    "decode_text",
    "is_tc_data",
    "parse_tc",
    "populate_device_from_tc",
    "tc_application_info",
    "tc_head_application_info",
    "tc_parameter_values",
    "tc_signature_check",
    "unquote_tc_field",
]
