"""
Woodward ToolKit settings file (``*.wset``) parser.

Woodward's *ToolKit* service tool is used to configure controls such as the
easYgen genset controllers (easYgen-1000/2000/3000/3000XT series), the LS-5
and LS-6 circuit breaker controls, the DTSC-200 transfer switch controller,
and others. ToolKit saves the complete settings of a control to a binary
"settings file" with a ``.wset`` extension, which can later be loaded back
into a control of the same type or compared against another file.

File format
-----------
A ``.wset`` file is a 10-byte proprietary header followed by two (or more)
concatenated `.NET Remoting Binary Format
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/>`__
(:term:`NRBF`, a.k.a. ``BinaryFormatter``) serialization streams:

1. A ``Woodward.Settings.SettingsHeader`` object, which identifies the
   Service Interface Definition (:term:`SID`) application the settings
   belong to (e.g. ``5418-6722-NEW``), along with notes and load flags.
2. A ``System.Collections.Hashtable`` of every parameter of the control,
   keyed by a ``Woodward.Sid.Descriptors.ParameterName`` (the delimited
   path of the parameter, e.g.
   ``Config_Monitoring.Generator.Overfrequency level 2.1910 Limit``).
   The values are ``Woodward.DataAccess.*Parameter`` objects which bundle
   the parameter's SID descriptor (data type, range, units, enumeration,
   security levels, communication handles) with its cached value.

The parameter objects come in four kinds:

- ``BasicParameter``: a value stored directly (integer, enumeration, string,
  or a bit field container).
- ``ComputedParameter``: a scaled view of a basic parameter
  (``value = base * multiplier + offset``), used for most floating point
  parameters with units.
- ``BitFieldParameter``: a single bit of a basic parameter.
- ``LogicManagerParameter``: a LogicsManager equation (three command
  variable inputs, unary and binary operators, and on/off delays).
- ``LookupTableParameter``/``ArrayParameter``: arrays of values, e.g. the
  axes and columns of a lookup table (seen in Woodward E3 engine control files).

The low-level NRBF decoding is done by :mod:`~peat.modules.woodward.csharp_reader`.
This module turns the decoded object graph into plain, JSON-serializable
Python data with a flat list of parameter records.

.. note::
   The format was reverse engineered from easYgen-3500 settings files saved
   by ToolKit 4.x/5.x (``Settings`` assembly 1.0.186.0). Files saved by newer
   ToolKit versions, or for other ToolKit devices, are expected to use the
   same container, but may use different class names. Unknown object layouts
   are still decoded and are returned using a generic, best-effort parameter
   extraction.
"""

import io
import re
from array import array
from collections import Counter
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import cache
from pathlib import Path
from typing import Any, BinaryIO, Final

from peat import DeviceData, consts, log

from . import easygen_enums
from .csharp_reader import serialization
from .easygen_data import populate_data_model_from_wset
from .easygen_logic import add_logics_manager_logic
from .easygen_svl import svl_dat_prms
from .toolkit import (
    CONTAINER_HEADER_LEN,
    TOOLKIT_APPLICATIONS,
    container_type,
    describe_container_header,
    identify_application,
)

#: Length of the proprietary header that precedes the first NRBF stream.
WSET_HEADER_LEN: Final[int] = CONTAINER_HEADER_LEN

#: Length of a NRBF SerializationHeaderRecord
NRBF_HEADER_LEN: Final[int] = 17

#: How far into a file to search for the first NRBF stream
WSET_MAX_HEADER_SEARCH: Final[int] = 256

# NRBF SerializationHeaderRecord: RecordType 0, RootId (any), HeaderId -1,
# MajorVersion 1, MinorVersion 0
_NRBF_SIGNATURE_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"\x00.{4}\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00", re.DOTALL
)

#: LogicsManager unary (per-input) operators, indexed by the enum value in the file.
#: ``NoOperator`` passes the command variable through unchanged.
LOGICS_MANAGER_UNARY_OPERATORS: Final[dict[int, str]] = {
    0: "Not",
    1: "NoOperator",
    2: "True",
    3: "False",
}

#: LogicsManager binary operators, indexed by the enum value in the file.
#: Only ``And`` (0) and ``Or`` (2) have been observed in files; the remaining
#: values follow the operator order in the easYgen manuals and are unverified.
LOGICS_MANAGER_BINARY_OPERATORS: Final[dict[int, str]] = {
    0: "And",
    1: "Nand",
    2: "Or",
    3: "Nor",
    4: "Xor",
    5: "Nxor",
}

#: Group name used for internal variables that have no group or parameter number
INTERNAL_GROUP: Final[str] = "(internal)"

_PARAMETER_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<group>.*?)\.)?(?P<id>\d{3,6})\s+(?P<label>.*)$"
)
_CAMEL_RE: Final[re.Pattern[str]] = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Heuristics for the generic (unknown object layout) parameter extraction
_GENERIC_ID_KEYS: Final[frozenset[str]] = frozenset(
    {"id", "parameterid", "parameter_id", "paramid", "number", "parameternumber"}
)
_GENERIC_VALUE_KEYS: Final[tuple[str, ...]] = (
    "value",
    "currentvalue",
    "current_value",
    "current",
    "settingvalue",
    "data",
)
_GENERIC_NAME_KEYS: Final[tuple[str, ...]] = (
    "name",
    "parametername",
    "parameter_name",
    "label",
    "displayname",
    "text",
)


# ---------------------------------------------------------------------------
# Container handling
# ---------------------------------------------------------------------------


def find_nrbf_offset(data: bytes, limit: int = WSET_MAX_HEADER_SEARCH) -> int | None:
    """
    Find the offset of the first NRBF serialization stream in ``data``.

    Args:
        data: The file data
        limit: How many leading bytes to search

    Returns:
        The offset of the NRBF ``SerializationHeaderRecord``, or :obj:`None`
    """
    match = _NRBF_SIGNATURE_RE.search(data, 0, limit + NRBF_HEADER_LEN)
    return match.start() if match else None


def is_nrbf_at(data: bytes, offset: int) -> bool:
    """Check if a NRBF ``SerializationHeaderRecord`` starts at ``offset``."""
    return _NRBF_SIGNATURE_RE.match(data, offset) is not None


def is_wset_data(data: bytes) -> bool:
    """
    Check if data looks like a ToolKit settings file.

    A settings file is a 10-byte header immediately followed by a NRBF
    stream. Unknown header values are accepted (so files from other ToolKit
    versions are still recognized), but ToolKit containers of another type
    (e.g. ``.wtool`` tool files) are rejected.

    Args:
        data: The file data (at least the first 27 bytes)

    Returns:
        :obj:`True` if the data appears to be a ``.wset`` file
    """
    if len(data) < WSET_HEADER_LEN + NRBF_HEADER_LEN:
        return False
    kind = container_type(data)
    if kind is not None and kind != "wset":
        return False
    return is_nrbf_at(data, WSET_HEADER_LEN)


def wset_signature_check(stream: BinaryIO) -> bool:
    """
    :class:`~peat.file_signature.FileSignature` custom check for ``.wset`` files.
    """
    return is_wset_data(stream.read(WSET_HEADER_LEN + NRBF_HEADER_LEN))


def read_nrbf_streams(data: bytes, offset: int = 0) -> tuple[list[Any], dict[str, Any]]:
    """
    Decode all of the concatenated NRBF streams in ``data``.

    Decoding stops at the first stream that fails to decode or at the first
    bytes that aren't a NRBF stream. Partial results are returned.

    Args:
        data: The data containing the streams
        offset: Where the first stream starts

    Returns:
        A tuple of the decoded root objects and a :class:`dict` describing
        the streams (``offset``, ``streams``, ``errors``, ``trailing_bytes``)
    """
    stream = io.BytesIO(data)
    stream.seek(offset)
    objects: list[Any] = []
    info: dict[str, Any] = {
        "offset": offset,
        "streams": [],
        "errors": [],
        "trailing_bytes": 0,
    }

    while stream.tell() < len(data):
        start = stream.tell()
        if not is_nrbf_at(data, start):
            info["trailing_bytes"] = len(data) - start
            log.debug(
                f"{info['trailing_bytes']} trailing bytes after NRBF streams (offset {start})"
            )
            break
        try:
            obj = serialization(stream).read_stream()
        except Exception as ex:
            message = f"Failed to decode NRBF stream at offset {start}: {ex!r}"
            log.warning(message)
            info["errors"].append(message)
            info["trailing_bytes"] = len(data) - start
            break
        objects.append(obj)
        info["streams"].append(
            {
                "offset": start,
                "end": stream.tell(),
                "class": _class_name(obj),
            }
        )

    return objects, info


# ---------------------------------------------------------------------------
# Object graph helpers
# ---------------------------------------------------------------------------


def _class_name(obj: Any) -> str:
    if hasattr(obj, "_fields") and hasattr(obj, "_asdict"):
        return type(obj).__name__
    return type(obj).__name__


def _is_record(obj: Any) -> bool:
    """Check if ``obj`` is a decoded .NET object (a ``namedlist`` instance)."""
    return hasattr(obj, "_fields") and hasattr(obj, "_asdict")


def _get(obj: Any, field: str, default: Any = None) -> Any:
    """Get a field of a decoded .NET object (or key of a dict), if present."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(field, default)
    if _is_record(obj) and field in obj._fields:
        return getattr(obj, field)
    return default


def snake_case(name: str) -> str:
    """Convert a .NET member name (``sidSpecification``, ``_isPartial``) to ``snake_case``."""
    name = name.strip("_")
    name = name.removesuffix("_k__BackingField")  # auto-property backing field
    return _CAMEL_RE.sub("_", name).lower()


def to_plain(obj: Any, _active: set[int] | None = None) -> Any:
    """
    Convert a decoded NRBF object graph into plain JSON-serializable Python data.

    .NET objects become :class:`dict` with a ``_class`` key, arrays become
    lists, and dates, decimals, and bytes become strings. Circular references
    are replaced with the string ``<circular reference>``.

    Args:
        obj: Object returned by the NRBF reader

    Returns:
        The plain representation
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    if isinstance(obj, array):
        return obj.tolist()

    active = _active if _active is not None else set()
    obj_id = id(obj)
    if obj_id in active:
        return "<circular reference>"
    active.add(obj_id)
    try:
        if isinstance(obj, dict):
            return {str(k): to_plain(v, active) for k, v in obj.items()}
        if _is_record(obj):
            plain: dict[str, Any] = {"_class": type(obj).__name__}
            for field in obj._fields:
                plain[field] = to_plain(getattr(obj, field), active)
            return plain
        if isinstance(obj, (set, frozenset)):
            items = [to_plain(x, active) for x in obj]
            try:
                return sorted(items)
            except TypeError:
                return items
        if isinstance(obj, (list, tuple)):
            return [to_plain(x, active) for x in obj]
    finally:
        active.discard(obj_id)
    return repr(obj)


def _snake_keys(plain: Any) -> Any:
    """Recursively convert the keys of a plain object to snake_case, dropping ``_class``."""
    if isinstance(plain, dict):
        return {
            snake_case(key): _snake_keys(value) for key, value in plain.items() if key != "_class"
        }
    if isinstance(plain, list):
        return [_snake_keys(x) for x in plain]
    return plain


def _hashtable_items(table: Any) -> list[tuple[Any, Any]]:
    """Get the (key, value) pairs of a decoded ``Hashtable``/``Dictionary``."""
    if isinstance(table, dict):
        return list(table.items())
    keys = _get(table, "Keys")
    values = _get(table, "Values")
    if isinstance(keys, (list, array)) and isinstance(values, (list, array)):
        return list(zip(keys, values, strict=False))
    pairs = _get(table, "KeyValuePairs")
    if isinstance(pairs, list):
        return [(_get(p, "key"), _get(p, "value")) for p in pairs]
    return []


def _text_value(text_value: Any) -> str | None:
    """Get the text of a ``Woodward.Sid.TextValue`` (a list of strings)."""
    if text_value is None:
        return None
    if isinstance(text_value, str):
        return text_value
    values = _get(text_value, "value")
    if isinstance(values, (list, array)):
        if not values:
            return None
        if len(values) == 1:
            return str(values[0])
        return [str(v) for v in values]  # type: ignore[return-value]
    return str(values) if values is not None else None


def _delimited_name(name_obj: Any) -> str:
    if isinstance(name_obj, str):
        return name_obj
    return str(_get(name_obj, "delimitedName", "") or "")


def split_parameter_name(name: str) -> tuple[str, int | None, str]:
    """
    Split a delimited parameter name into its group, parameter number, and label.

    Example: ``Config_Monitoring.Generator.Overfrequency level 2.1910 Limit``
    is split into ``("Config_Monitoring.Generator.Overfrequency level 2", 1910, "Limit")``.
    Names without a parameter number are split at their last dot
    (``PDO_9_2.BIT_0_HMI`` becomes ``("PDO_9_2", None, "BIT_0_HMI")``), and
    names of internal variables (e.g. ``Th2GenOverFreq``) return ``("", None, name)``.

    Args:
        name: The delimited parameter name

    Returns:
        A tuple of ``(group, parameter id or None, label)``
    """
    match = _PARAMETER_NAME_RE.match(name)
    if match:
        return match.group("group") or "", int(match.group("id")), match.group("label").strip()
    if "." in name:
        group, _, label = name.rpartition(".")
        return group, None, label.strip()
    return "", None, name


# ---------------------------------------------------------------------------
# Parameter value conversion
# ---------------------------------------------------------------------------


def _to_int(text: str | None) -> int | str | None:
    if text is None:
        return None
    try:
        return int(text.strip())
    except (ValueError, AttributeError):
        return text


def _to_float(text: str | None) -> float | str | None:
    if text is None:
        return None
    try:
        return float(text.strip())
    except (ValueError, AttributeError):
        return text


def _descriptor_type(data_type: Any) -> str:
    """Map a ``Woodward.Sid.Descriptors.*Descriptor`` class to a short type name."""
    class_name = _class_name(data_type) if data_type is not None else ""
    if "EnumeratedInteger" in class_name:
        return "enumerated"
    if "BitFieldBoolean" in class_name:
        return "bit_field"
    if "BitFields" in class_name:
        return "bit_fields"
    if "Boolean" in class_name:
        return "boolean"
    if "Array" in class_name:
        return "array"
    if "Integer" in class_name:
        return "integer"
    if "Float" in class_name:
        return "float"
    if "String" in class_name:
        return "string"
    return class_name or "unknown"


def _to_bool(text: str | None) -> bool | str | None:
    if text is None:
        return None
    try:
        return consts.str_to_bool(text)
    except ValueError:
        return text


def _convert(text: str | list[str] | None, type_name: str) -> Any:
    """Convert a parameter's text value based on its descriptor type."""
    if text is None:
        return None
    if isinstance(text, list):
        return [_convert(item, type_name) for item in text]
    if type_name in ("integer", "bit_fields"):
        return _to_int(text)
    if type_name == "float":
        return _to_float(text)
    if type_name == "boolean":
        return _to_bool(text)
    return text


def _scale(base: Any, multiplier: Any, offset: Any) -> Any:
    """Compute ``base * multiplier + offset`` without floating point noise."""
    if base is None or not isinstance(base, (int, float)) or isinstance(base, bool):
        return None
    try:
        result = Decimal(str(base)) * Decimal(str(multiplier or 1)) + Decimal(str(offset or 0))
    except (InvalidOperation, ValueError):
        return None
    if result == result.to_integral_value():
        return float(result) if (multiplier not in (None, 1) or offset) else int(result)
    return float(result)


def _enumeration_options(enumeration: Any) -> dict[str, str]:
    options: dict[str, str] = {}
    for element in _get(enumeration, "elements", None) or []:
        value = _get(element, "value")
        name = _get(element, "name")
        if value is not None:
            options[str(value)] = str(name)
    return options


def _enumeration_element(element: Any) -> dict[str, Any] | None:
    if element is None:
        return None
    return {"value": _get(element, "value"), "name": _get(element, "name")}


# ---------------------------------------------------------------------------
# Woodward.DataAccess parameter records
# ---------------------------------------------------------------------------


def _descriptor_fields(descriptor: Any) -> dict[str, Any]:
    """Common fields of a ``ParameterDescriptor`` or ``LogicManagerDescriptor``."""
    comms = _get(descriptor, "communicationProperties")
    access = _get(descriptor, "access")
    fields: dict[str, Any] = {
        "units": _get(descriptor, "units") or "",
        "description": _get(descriptor, "description") or "",
        "read_security_level": _get(descriptor, "readSecurityLevel"),
        "write_security_level": _get(descriptor, "writeSecurityLevel"),
        "servlink_handle": _get(comms, "servlinkHandle"),
        "canopen_multiplexor": _get(comms, "canOpenMultiplexor"),
    }
    if access is not None:
        fields["access_type"] = _get(access, "value__", access)
    nv_group = _get(descriptor, "nonVolatileGroupId")
    if nv_group is not None:
        fields["nonvolatile_group_id"] = nv_group
    return fields


def _basic_value(parameter: Any) -> str | None:
    """Cached text value of a ``BasicParameter``."""
    cache_obj = _get(parameter, "parameterValueCache")
    value = _get(cache_obj, "value")
    return None if value is None else str(value)


def _basic_record(parameter: Any, descriptor: Any) -> dict[str, Any]:
    data_type = _get(descriptor, "dataTypeDescriptor")
    type_name = _descriptor_type(data_type)
    text = _basic_value(parameter)
    record: dict[str, Any] = {
        "kind": "basic",
        "type": type_name,
        "value": _convert(text, type_name),
        "value_text": text,
        "initial": _convert(_text_value(_get(descriptor, "initialValue")), type_name),
        "minimum": _convert(_text_value(_get(_get(descriptor, "minimum"), "value")), type_name),
        "maximum": _convert(_text_value(_get(_get(descriptor, "maximum"), "value")), type_name),
    }
    if type_name == "enumerated":
        options = _enumeration_options(_get(data_type, "enumeration"))
        record["options"] = options
        record["enum_name"] = _delimited_name(_get(_get(data_type, "enumeration"), "name"))
        for enum_value, name in options.items():
            if name == text:
                record["enum_value"] = (
                    int(enum_value) if enum_value.lstrip("-").isdigit() else enum_value
                )
                break
    elif type_name == "string":
        record["max_size"] = _get(data_type, "maxSize")
    elif type_name in ("integer", "bit_fields"):
        record["size"] = _get(data_type, "size")
        record["signed"] = _get(data_type, "isSigned")
    if type_name == "bit_fields":
        record["bit_fields"] = [
            {
                "name": _get(bit, "name"),
                "position": _get(bit, "position"),
                "size": _get(bit, "size"),
            }
            for bit in _get(data_type, "bitFieldDescriptors", None) or []
        ]
    return record


def _computed_record(descriptor: Any, by_name: dict[str, Any]) -> dict[str, Any]:
    data_type = _get(descriptor, "dataTypeDescriptor")
    type_name = _descriptor_type(data_type)
    expression = _get(descriptor, "expressionDescriptor")
    source_name = _delimited_name(_get(expression, "paramName"))
    multiplier = _get(expression, "multiplier", 1)
    offset = _get(expression, "offset", 0)
    source = by_name.get(source_name)
    source_value = _to_int(_basic_value(source)) if source is not None else None
    initial = _convert(_text_value(_get(descriptor, "initialValue")), type_name)
    if initial is None and source is not None:
        source_initial = _to_int(_text_value(_get(_get(source, "descriptor"), "initialValue")))
        initial = _scale(source_initial, multiplier, offset)
    record: dict[str, Any] = {
        "kind": "computed",
        "type": type_name,
        "value": _scale(source_value, multiplier, offset),
        "source": source_name,
        "source_value": source_value,
        "multiplier": multiplier,
        "offset": offset,
        "initial": initial,
        "minimum": _convert(_text_value(_get(_get(descriptor, "minimum"), "value")), type_name),
        "maximum": _convert(_text_value(_get(_get(descriptor, "maximum"), "value")), type_name),
    }
    if source is None and source_name:
        log.debug(f"Computed parameter source '{source_name}' not found in settings")
    return record


def _bit_field_record(parameter: Any, descriptor: Any) -> dict[str, Any]:
    data_type = _get(descriptor, "dataTypeDescriptor")
    bit_descriptor = _get(data_type, "bitFieldIntegerDescriptor", data_type)
    position = _get(bit_descriptor, "position")
    size = _get(bit_descriptor, "size", 1) or 1
    base = _get(parameter, "baseParameter")
    base_value = _to_int(_basic_value(base))
    value: Any = None
    if isinstance(base_value, int) and isinstance(position, int):
        bits = (base_value >> position) & ((1 << size) - 1)
        value = bool(bits) if size == 1 else bits
    return {
        "kind": "bit_field",
        "type": "bit_field",
        "value": value,
        "base_parameter": _delimited_name(_get(_get(base, "descriptor"), "name"))
        or _delimited_name(_get(bit_descriptor, "baseParameterName")),
        "base_value": base_value,
        "bit_position": position,
        "bit_size": size,
    }


def _array_record(array_parameter: Any) -> dict[str, Any]:
    """Describe an ``ArrayParameter`` (one axis or column of a lookup table)."""
    cache_obj = _get(array_parameter, "arrayParameterValueCache")
    descriptor = _get(cache_obj, "descriptor") or _get(array_parameter, "descriptor")
    data_type = _get(descriptor, "dataTypeDescriptor")
    element_type = _descriptor_type(_get(data_type, "dataTypeDesc") or data_type)
    raw_values = _get(cache_obj, "values")
    if raw_values is None:
        raw_values = _get(cache_obj, "value")
    values = to_plain(raw_values)
    if isinstance(values, dict):
        values = values.get("value", values)
    if isinstance(values, list):
        values = [_convert(str(v), element_type) if v is not None else None for v in values]
    initial = _text_value(_get(descriptor, "initialValue"))
    if isinstance(initial, str):
        initial = [initial]
    return {
        "name": _delimited_name(_get(descriptor, "name")),
        "type": element_type,
        "size": _get(data_type, "size"),
        "values": values,
        "initial": _convert(initial, element_type),
        "units": _get(descriptor, "units") or "",
    }


def _lookup_table_record(parameter: Any) -> dict[str, Any]:
    """Record for a ``LookupTableParameter`` (a set of arrays) or an ``ArrayParameter``."""
    value = _get(parameter, "value")
    arrays = [_array_record(a) for a in (_get(value, "arrays") or []) if a is not None]
    if not arrays and _get(parameter, "arrayParameterValueCache") is not None:
        arrays = [_array_record(parameter)]
    descriptor = _get(parameter, "descriptor") or _get(parameter, "Descriptor")
    record: dict[str, Any] = {
        "kind": "lookup_table" if "LookupTable" in _class_name(parameter) else "array",
        "type": "array",
        "arrays": arrays,
    }
    index_inputs = _get(descriptor, "indexInputParameterNames")
    if index_inputs:
        record["index_inputs"] = [_delimited_name(n) for n in index_inputs if n is not None]
    output_descriptor = _get(descriptor, "outputArrayDescriptor")
    if output_descriptor is not None:
        record.update(_descriptor_fields(output_descriptor))
    if len(arrays) == 1:
        record["value"] = arrays[0]["values"]
        record["initial"] = arrays[0]["initial"]
    else:
        record["value"] = [a["values"] for a in arrays]
        record["initial"] = [a["initial"] for a in arrays]
    return record


def _logics_manager_record(parameter: Any, descriptor: Any) -> dict[str, Any]:
    cache_obj = _get(parameter, "logicManagerParameterValueCache")
    value = _get(cache_obj, "value")
    delay_units = _get(descriptor, "delayUnits") or ""

    def _unary(number: int) -> str:
        op = _get(_get(value, f"unaryOperator{number}"), "value__")
        return LOGICS_MANAGER_UNARY_OPERATORS.get(op, f"unknown({op})")

    def _binary(number: int) -> str:
        op = _get(_get(value, f"binaryOperator{number}"), "value__")
        return LOGICS_MANAGER_BINARY_OPERATORS.get(op, f"unknown({op})")

    inputs = [_enumeration_element(_get(value, f"inputSelector{n}")) for n in (1, 2, 3)]
    equation = {
        "input_1": inputs[0],
        "operator_1": _unary(1),
        "binary_operator_1": _binary(1),
        "input_2": inputs[1],
        "operator_2": _unary(2),
        "binary_operator_2": _binary(2),
        "input_3": inputs[2],
        "operator_3": _unary(3),
        "delay_on": _get(value, "delayOn"),
        "delay_off": _get(value, "delayOff"),
        "delay_units": delay_units,
    }

    def _term(number: int) -> str:
        name = (inputs[number - 1] or {}).get("name", "?")
        return f"[{_unary(number)} {name}]"

    expression = (
        f"{_term(1)} {_binary(1)} {_term(2)} {_binary(2)} {_term(3)}, "
        f"delay on {equation['delay_on']} {delay_units}, "
        f"delay off {equation['delay_off']} {delay_units}"
    )
    initial = {
        "input_1": _get(descriptor, "inputSelector1InitalValue"),
        "operator_1": _get(descriptor, "unaryOperator1InitalValue"),
        "binary_operator_1": _get(descriptor, "binaryOperator1InitalValue"),
        "input_2": _get(descriptor, "inputSelector2InitalValue"),
        "operator_2": _get(descriptor, "unaryOperator2InitalValue"),
        "binary_operator_2": _get(descriptor, "binaryOperator2InitalValue"),
        "input_3": _get(descriptor, "inputSelector3InitalValue"),
        "operator_3": _get(descriptor, "unaryOperator3InitalValue"),
        "delay_on": _get(descriptor, "delayOnInitalValue"),
        "delay_off": _get(descriptor, "delayOffInitalValue"),
    }
    return {
        "kind": "logics_manager",
        "type": "logics_manager",
        "value": equation,
        "expression": expression,
        "initial": initial,
        "units": delay_units,
    }


def _analog_manager_inputs(records: list[dict[str, Any]]) -> dict[str, str]:
    """
    The AnalogManager data source list: the enumeration used by the
    ``Data source`` parameters (analog outputs, external power measurement, ...).
    """
    best: dict[str, str] = {}
    for record in records:
        if (
            record.get("type") != "enumerated"
            or "data source" not in str(record.get("label", "")).lower()
        ):
            continue
        options = record.get("options") or {}
        if len(options) > len(best):
            best = options
    return best


def _logics_manager_inputs(descriptor: Any) -> dict[str, str]:
    """The LogicsManager command variable list from a ``LogicManagerDescriptor``."""
    for enumeration in _get(descriptor, "inputEnumerations", None) or []:
        options = _enumeration_options(enumeration)
        if options:
            return options
    return {}


def parameter_record(name: str, parameter: Any, by_name: dict[str, Any]) -> dict[str, Any]:
    """
    Build a flat record for a ``Woodward.DataAccess.*Parameter`` object.

    Args:
        name: The delimited parameter name (the hashtable key)
        parameter: The decoded parameter object
        by_name: All parameters indexed by delimited name (for computed values)

    Returns:
        The parameter record
    """
    class_name = _class_name(parameter)
    descriptor = _get(parameter, "descriptor") or _get(parameter, "Descriptor")
    group, param_id, label = split_parameter_name(name)
    record: dict[str, Any] = {
        "name": name,
        "group": group,
        "id": param_id,
        "label": label,
        "class": class_name,
    }

    if "LogicManager" in class_name:
        record.update(_logics_manager_record(parameter, descriptor))
    elif "Computed" in class_name:
        record.update(_computed_record(descriptor, by_name))
    elif "BitField" in class_name:
        record.update(_bit_field_record(parameter, descriptor))
    elif "LookupTable" in class_name or "Array" in class_name:
        record.update(_lookup_table_record(parameter))
    elif _get(parameter, "parameterValueCache") is not None or "Basic" in class_name:
        record.update(_basic_record(parameter, descriptor))
    else:
        record.update({"kind": "unknown", "type": "unknown", "value": to_plain(parameter)})

    if descriptor is not None:
        for key, value in _descriptor_fields(descriptor).items():
            record.setdefault(key, value)
    return record


def extract_settings(table: Any) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """
    Extract parameter records from the settings ``Hashtable`` of a ``.wset`` file.

    Args:
        table: The decoded hashtable (second NRBF stream)

    Returns:
        A tuple of the parameter records (sorted by name) and the
        LogicsManager command variable list (``{value: name}``)
    """
    items = _hashtable_items(table)
    by_name: dict[str, Any] = {}
    for key, value in items:
        name = _delimited_name(key)
        if name:
            by_name[name] = value

    records = []
    logic_inputs: dict[str, str] = {}
    for name, parameter in by_name.items():
        try:
            record = parameter_record(name, parameter, by_name)
        except Exception as ex:
            log.warning(f"Failed to extract parameter '{name}': {ex!r}")
            record = {
                "name": name,
                "kind": "error",
                "type": "unknown",
                "value": None,
                "error": repr(ex),
            }
        records.append(record)
        if not logic_inputs and record.get("kind") == "logics_manager":
            logic_inputs = _logics_manager_inputs(_get(parameter, "descriptor"))

    records.sort(key=lambda r: (r.get("group") or "", r.get("id") or 0, r["name"]))
    return records, logic_inputs


def is_settings_table(obj: Any) -> bool:
    """Check if a decoded object is a settings hashtable keyed by ``ParameterName``."""
    items = _hashtable_items(obj)
    if not items:
        return False
    key, _ = items[0]
    return bool(_delimited_name(key)) and "ParameterName" in _class_name(key)


# ---------------------------------------------------------------------------
# Generic fallback extraction
# ---------------------------------------------------------------------------


def extract_generic_parameters(plain: Any) -> list[dict[str, Any]]:
    """
    Best-effort extraction of parameter-like records from an unknown object graph.

    Any object with an integer ``Id``-like member and a ``Value``-like member
    is treated as a parameter.

    Args:
        plain: Output of :func:`to_plain`

    Returns:
        A list of ``{"id", "name", "value", "class", "path"}`` records
    """
    found: list[dict[str, Any]] = []

    def _record(node: dict[str, Any], path: str) -> dict[str, Any] | None:
        normalized = {key.strip("_").lower(): key for key in node if key != "_class"}
        id_key = next((normalized[k] for k in normalized if k in _GENERIC_ID_KEYS), None)
        if id_key is None:
            return None
        param_id = node[id_key]
        if isinstance(param_id, str) and param_id.isdigit():
            param_id = int(param_id)
        if isinstance(param_id, bool) or not isinstance(param_id, int):
            return None
        value_key = next((normalized[k] for k in _GENERIC_VALUE_KEYS if k in normalized), None)
        if value_key is None:
            return None
        name_key = next((normalized[k] for k in _GENERIC_NAME_KEYS if k in normalized), None)
        return {
            "id": param_id,
            "name": str(node[name_key]) if name_key else "",
            "label": str(node[name_key]) if name_key else "",
            "group": "",
            "kind": "generic",
            "type": "unknown",
            "value": node[value_key],
            "class": node.get("_class", ""),
            "path": path,
        }

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            record = _record(node, path)
            if record:
                found.append(record)
            for key, value in node.items():
                if key != "_class":
                    _walk(value, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                _walk(value, f"{path}[{index}]")

    _walk(plain, "")
    return found


@cache
def easygen_parameter_names() -> dict[int, str]:
    """
    Names of easYgen parameters by parameter number, from PEAT's ServLink tables.

    Returns:
        A :class:`dict` of ``{parameter number: name}``
    """
    names: dict[int, str] = {}
    for key in svl_dat_prms:
        number, _, name = key.partition(" ")
        if number.isdigit() and name.strip():
            names.setdefault(int(number), name.strip())
    for table in (
        easygen_enums.OPERATION_MODES,
        easygen_enums.ANALOG_MANAGER,
        easygen_enums.LOGIC_MANAGER,
        easygen_enums.ANALOG_OUTPUTS,
        easygen_enums.DISCRETE_OUTPUTS,
        easygen_enums.BREAKER_CONFIG,
        easygen_enums.FLEXIBLE_LIMITS,
        easygen_enums.MISC_OPTIONS,
    ):
        for number, name in table.items():
            names.setdefault(number, name)
    return names


# ---------------------------------------------------------------------------
# Top-level parsing
# ---------------------------------------------------------------------------


def _read_source(source: Path | bytes | BinaryIO) -> bytes:
    if isinstance(source, Path):
        return source.read_bytes()
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if hasattr(source, "read"):
        data = source.read()
        if isinstance(data, str):
            raise TypeError(
                "Text streams can't be parsed as .wset files, open the file in binary mode"
            )
        return data
    raise TypeError(f"Unsupported source type for .wset parsing: {type(source).__name__}")


def application_info(settings_header: dict[str, Any]) -> dict[str, Any]:
    """
    Identify the ToolKit application (and device) from the settings header.

    Args:
        settings_header: The plain ``SettingsHeader`` (see :func:`parse_wset`)

    Returns:
        A :class:`dict` with the application ``id``, ``part_number``,
        ``revision``, ``sid``, and (if known) the ``brand``, ``model``,
        and ``product`` of the device
    """
    identifier = settings_header.get("sid_identifier") or {}
    app_id = ""
    if isinstance(identifier, dict):
        app_id = str(identifier.get("app_id_string") or "")
    elif isinstance(identifier, str):
        app_id = identifier
    if not app_id:
        app_id = str(settings_header.get("application_description") or "")

    sid = str(settings_header.get("sid_specification") or "")
    info = identify_application(app_id)
    if not info["part_number"] and not info["model"] and sid:
        info = {**identify_application(sid), "id": app_id}
    info["sid"] = sid
    return info


def parse_wset(source: Path | bytes | BinaryIO, include_raw: bool = False) -> dict[str, Any]:
    """
    Parse a Woodward ToolKit settings (``.wset``) file.

    Args:
        source: Path to the file, the raw file bytes, or a binary file object
        include_raw: Include the full decoded object graph of every NRBF
            stream as ``raw_streams``. This is large (the SID descriptors
            are repeated for every parameter) and intended for debugging.

    Returns:
        A :class:`dict` with the parsed data, or an empty :class:`dict` if the
        data isn't a settings file. Keys:

        - ``header``: the ToolKit container header, see
          :func:`~peat.modules.woodward.toolkit.describe_container_header`
        - ``nrbf``: stream offsets, classes, decode errors, and trailing bytes
        - ``settings_header``: the ``SettingsHeader`` object (snake_case keys)
        - ``application``: the SID application identity, see :func:`application_info`
        - ``parameters``: flat list of parameter records, see :func:`parameter_record`
        - ``num_parameters``, ``parameter_kinds``, ``parameter_types``, ``groups``
        - ``logics_manager_inputs``: the LogicsManager command variable list
        - ``analog_manager_inputs``: the AnalogManager data source list
        - ``raw_streams``: only if ``include_raw`` is set
    """
    try:
        data = _read_source(source)
    except (OSError, TypeError) as ex:
        log.error(f"Failed to read .wset data: {ex}")
        return {}

    if not data:
        log.error("No data to parse as a Woodward .wset file")
        return {}

    offset = WSET_HEADER_LEN if is_nrbf_at(data, WSET_HEADER_LEN) else find_nrbf_offset(data)
    if offset is None:
        log.warning(
            f"Unknown Woodward .wset format: no .NET serialization stream found "
            f"in the first {WSET_MAX_HEADER_SEARCH} bytes"
        )
        return {}

    header = data[:offset]
    parsed: dict[str, Any] = {"header": describe_container_header(header)}
    if offset != WSET_HEADER_LEN:
        log.warning(
            f"Unexpected Woodward .wset header length {offset} (expected {WSET_HEADER_LEN})"
        )
    elif parsed["header"]["type"] != "wset":
        log.info(f"Unknown Woodward .wset header value: {header.hex()}")

    objects, nrbf_info = read_nrbf_streams(data, offset)
    parsed["nrbf"] = nrbf_info
    if not objects:
        log.error("Failed to decode any .NET serialization streams from Woodward .wset file")
        return {}

    settings_header: dict[str, Any] = {}
    parameters: list[dict[str, Any]] = []
    logic_inputs: dict[str, str] = {}
    unknown_objects: list[Any] = []
    for obj in objects:
        class_name = _class_name(obj)
        if "SettingsHeader" in class_name and not settings_header:
            settings_header = _snake_keys(to_plain(obj))
        elif is_settings_table(obj):
            records, inputs = extract_settings(obj)
            parameters.extend(records)
            if inputs and not logic_inputs:
                logic_inputs = inputs
        else:
            unknown_objects.append(obj)

    if unknown_objects:
        log.info(
            f"Woodward .wset file has {len(unknown_objects)} unrecognized object(s): "
            f"{[_class_name(o) for o in unknown_objects]}"
        )
        for obj in unknown_objects:
            parameters.extend(extract_generic_parameters(to_plain(obj)))

    parsed["settings_header"] = settings_header
    parsed["application"] = application_info(settings_header)
    parsed["parameters"] = parameters
    parsed["num_parameters"] = len(parameters)
    parsed["parameter_kinds"] = dict(Counter(p.get("kind", "unknown") for p in parameters))
    parsed["parameter_types"] = dict(Counter(p.get("type", "unknown") for p in parameters))
    parsed["groups"] = dict(
        sorted(
            Counter((p.get("group") or INTERNAL_GROUP).split(".")[0] for p in parameters).items()
        )
    )
    parsed["logics_manager_inputs"] = logic_inputs
    parsed["analog_manager_inputs"] = _analog_manager_inputs(parameters)
    if include_raw:
        parsed["raw_streams"] = [to_plain(obj) for obj in objects]

    if not parameters:
        log.warning("No parameters found in Woodward .wset file")
    return parsed


def summarize_wset(parsed: dict[str, Any]) -> dict[str, Any]:
    """Compact summary of :func:`parse_wset` output, suitable for ``DeviceData.extra``."""
    return {
        "header": parsed.get("header", {}),
        "nrbf": parsed.get("nrbf", {}),
        "settings_header": parsed.get("settings_header", {}),
        "application": parsed.get("application", {}),
        "num_parameters": parsed.get("num_parameters", 0),
        "parameter_kinds": parsed.get("parameter_kinds", {}),
        "parameter_types": parsed.get("parameter_types", {}),
        "groups": parsed.get("groups", {}),
        "num_logics_manager_inputs": len(parsed.get("logics_manager_inputs", {})),
        "num_analog_manager_inputs": len(parsed.get("analog_manager_inputs", {})),
    }


def populate_device_from_wset(dev: DeviceData, parsed: dict[str, Any]) -> None:
    """
    Add the results of :func:`parse_wset` to a device.

    The application identity is used for the device description and firmware
    identifier, the parameter values are stored in ``dev.extra["parameters"]``
    (``{name: value}``), and a summary of the file in ``dev.extra["wset"]``.
    The parameters are also mapped onto the data model (registers, tags,
    I/O, interfaces, services, users, see
    :mod:`~peat.modules.woodward.easygen_data`) and the LogicsManager
    equations converted to Structured Text and TC6 XML in ``dev.logic``
    (see :mod:`~peat.modules.woodward.easygen_logic`).

    Args:
        dev: The device to populate
        parsed: Output of :func:`parse_wset`
    """
    if not parsed:
        return

    dev.extra["wset"] = summarize_wset(parsed)
    dev.extra["parameters"] = {
        p["name"]: p.get("expression", p.get("value")) for p in parsed.get("parameters", [])
    }

    app = parsed.get("application", {})
    if app.get("id") and not dev.firmware.id:
        dev.firmware.id = app["id"]
    if app.get("brand") and not dev.description.brand:
        dev.description.brand = app["brand"]
    if app.get("model") and not dev.description.model:
        dev.description.model = app["model"]
    elif not dev.description.model:
        # Don't let the module's default model mislabel a file from another device
        dev.description.model = "unknown"
    if app.get("product") and not dev.description.product:
        dev.description.product = app["product"]
    elif app.get("id") and not dev.description.product:
        dev.description.product = f"ToolKit application {app['id']}"
    if not app.get("model"):
        log.info(
            f"Device model couldn't be determined from the .wset application identifier "
            f"'{app.get('id', '')}'. Known applications: {sorted(TOOLKIT_APPLICATIONS)}"
        )

    dev.extra["wset"]["data_model"] = populate_data_model_from_wset(dev, parsed)
    program = add_logics_manager_logic(dev, parsed)
    if program:
        dev.extra["wset"]["logic"] = {
            "num_equations": program["num_equations"],
            "num_command_variables": len(program["command_variables"]),
            "unknown_operators": program["unknown_operators"],
        }


__all__ = [
    "INTERNAL_GROUP",
    "LOGICS_MANAGER_BINARY_OPERATORS",
    "LOGICS_MANAGER_UNARY_OPERATORS",
    "WSET_HEADER_LEN",
    "application_info",
    "easygen_parameter_names",
    "extract_generic_parameters",
    "extract_settings",
    "find_nrbf_offset",
    "is_wset_data",
    "parameter_record",
    "parse_wset",
    "populate_device_from_wset",
    "read_nrbf_streams",
    "split_parameter_name",
    "summarize_wset",
    "to_plain",
    "wset_signature_check",
]
