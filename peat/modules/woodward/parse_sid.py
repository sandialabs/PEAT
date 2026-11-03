"""
Woodward ToolKit Service Interface Definition (``*.sid``) file parser.

A Service Interface Definition (:term:`SID`) describes every parameter,
status value, LogicsManager equation, enumeration, and event of a Woodward
control that is serviced with ToolKit, along with the ServLink and CANopen
communication handles, default values, ranges, units, and security levels of
each item. Woodward publishes one SID per product, firmware release, and
language (as part of the ToolKit "configuration files" package, which also
contains the ``.wtool`` tool file). ToolKit needs the SID to connect to a
control and to create or edit ``.wset`` settings files.

A SID is an XML document (``<ServiceInterfaceDefinition>``, schema
``SidNN.xsd``). Woodward distributes it in two forms:

- compressed: a 10-byte ToolKit container header (type ``0x16``, see
  :mod:`~peat.modules.woodward.toolkit`) followed by a gzip stream
- plain XML, e.g. the ``*.CAN.sid`` variant for CAN connections

The parser accepts both, and also a bare gzip stream.

The XML layout (``Sid18.xsd`` to ``Sid21.xsd`` have been seen)::

    <ServiceInterfaceDefinition Identifier="EG3500XTP2 2.17-0_54728" Specification="..." ...>
      <NonVolatileProtocol Type="ServlinkSaveValues"/>
      <SecurityProtocols>
        <Servlink><Accounts/><CommandSecurityLevels>...</CommandSecurityLevels></Servlink>
      </SecurityProtocols>
      <SettingsPolicies AllowPartial="true"/>
      <Enumeration Name="ENUM_16190" Else="!!!"><Element Name="Yes" Value="1"/>...</Enumeration>
      <Structure Name="AnalogManagerType1">
        <Field Name="Analog1"><Integer .../></Field>...
      </Structure>
      <Namespace Name="PARAMETER">
        <Namespace Name="Configure system management">
          <DataItem Name="1702 Device number" Access="ReadWrite" Address="960212">
            <Integer Size="32"/>
            <CommunicationProperties>
              <Servlink Handle="2756708006"/><CANopen Multiplexor="2532865"/>
            </CommunicationProperties>
            <InitialValue>1</InitialValue>
            <Minimum><Constant>1</Constant></Minimum>
            <Maximum><Constant>32</Constant></Maximum>
            <Security Operation="Write" Level="2"/>
          </DataItem>
          <LogicManager Name="12922 Ext. mns.decoupl." InEnum1="ENUM_LOGLIST1.LOGICLIST1" ...>
            <InitialValue>0 0 False And True And True 201 201 201</InitialValue>
          </LogicManager>
        </Namespace>
      </Namespace>
      <Event Identifier="2112"><Constant>Overspeed 1</Constant></Event>
    </ServiceInterfaceDefinition>

.. note::
   A SID holds the *definition* (and defaults) of the parameters, not the
   values configured on a device. The configured values are in ``.wset``
   settings files (refer to :mod:`~peat.modules.woodward.parse_wset`).
"""

import re
import xml.etree.ElementTree as ET
import zlib
from collections import Counter
from pathlib import Path
from typing import Any, BinaryIO, Final

from peat import DeviceData, User, consts, log

from .easygen_data import populate_data_model_from_sid
from .toolkit import (
    CONTAINER_HEADER_LEN,
    container_type,
    describe_container_header,
    identify_application,
)

GZIP_MAGIC: Final[bytes] = b"\x1f\x8b"
SID_ROOT_TAG: Final[str] = "ServiceInterfaceDefinition"

#: Enumerations with at most this many elements are included in parameter records
SID_MAX_INLINE_OPTIONS: Final[int] = 32

#: Maximum size of the decompressed SID XML, to guard against gzip bombs.
#: Real SIDs are a few MB (2 to 4 MB for easYgen-3000XT and E3 SIDs).
SID_MAX_XML_SIZE: Final[int] = 256 * 1024 * 1024

# Input block sizes for gzip decompression, and the zero padding allowed after a gzip member
_GZIP_MIN_INPUT_BLOCK: Final[int] = 256
_GZIP_MAX_INPUT_BLOCK: Final[int] = 64 * 1024
_ZERO_PADDING_RE: Final[re.Pattern[bytes]] = re.compile(rb"\x00*")

_TYPE_TAGS: Final[dict[str, str]] = {
    "Integer": "integer",
    "Float": "float",
    "Boolean": "boolean",
    "String": "string",
    "BitFields": "bit_fields",
    "BitVector": "bit_vector",
    "WGTime": "time",
}
_COMMON_CHILD_TAGS: Final[frozenset[str]] = frozenset(
    {
        "CommunicationProperties",
        "InitialValue",
        "Minimum",
        "Maximum",
        "Security",
        "Units",
        "Description",
    }
)
_INT_RE: Final[re.Pattern[str]] = re.compile(r"^[+-]?\d+$")
# Parameter numbers have 2 to 6 digits. Unlike settings files, SIDs have
# genuine 2 digit parameters, e.g. "60 Data Protocol 1, Mux" in easYgen-3000XT
# SIDs, whose ServLink handles are numbered like those of the other parameters.
_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^(?P<id>\d{2,6})\s+(?P<label>.+)$")


# ---------------------------------------------------------------------------
# Container handling
# ---------------------------------------------------------------------------


def _xml_head(data: bytes, size: int = 4096) -> str:
    return data[:size].decode("utf-8", errors="replace")


def is_sid_data(data: bytes) -> bool:
    """
    Check if data looks like a Service Interface Definition file.

    Recognizes the ToolKit container (header + gzip), a bare gzip stream, and
    plain XML. For compressed data only the start of the stream is inflated.

    Args:
        data: The file data (or the beginning of it, at least a few KB)

    Returns:
        :obj:`True` if the data appears to be a SID
    """
    if not data:
        return False
    payload = data
    if container_type(data) == "sid":
        payload = data[CONTAINER_HEADER_LEN:]
    if payload.startswith(GZIP_MAGIC):
        try:
            # Inflate only the start, which also works for truncated data
            payload = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(payload[:65536], 4096)
        except zlib.error:
            return False
    return SID_ROOT_TAG in _xml_head(payload)


def sid_signature_check(stream: BinaryIO) -> bool:
    """
    :class:`~peat.file_signature.FileSignature` custom check for ``.sid`` files.
    """
    return is_sid_data(stream.read(65536))


def _gunzip(data: bytes, max_size: int = SID_MAX_XML_SIZE) -> bytes:
    """
    Decompress a gzip stream (one or more members), limiting the output size.

    The input is fed to the decompressor in blocks that start small and grow
    up to :data:`_GZIP_MAX_INPUT_BLOCK` bytes for each member, so the time
    taken grows linearly with the input size, even for a stream of many
    small members.

    Raises:
        ValueError: If the data can't be decompressed or the decompressed
            data is larger than ``max_size``
    """
    chunks: list[bytes] = []
    total = 0
    pos = 0
    view = memoryview(data)
    while pos < len(data):
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        block_size = _GZIP_MIN_INPUT_BLOCK
        while not decompressor.eof:
            pending: bytes | memoryview = view[pos : pos + block_size]
            block_size = min(block_size * 2, _GZIP_MAX_INPUT_BLOCK)
            if not pending:
                raise ValueError(
                    "Failed to decompress SID data: the compressed data ended "
                    "before the end-of-stream marker was reached"
                )
            pos += len(pending)
            while pending:
                try:
                    chunk = decompressor.decompress(pending, max_size - total + 1)
                except zlib.error as ex:
                    raise ValueError(f"Failed to decompress SID data: {ex}") from ex
                total += len(chunk)
                if total > max_size:
                    raise ValueError(
                        f"Decompressed SID data is larger than the limit of {max_size} bytes"
                    )
                chunks.append(chunk)
                pending = decompressor.unconsumed_tail
        # Go back to the start of the data after this member. Like
        # gzip.decompress, allow more members and trailing zero padding.
        pos -= len(decompressor.unused_data)
        padding = _ZERO_PADDING_RE.match(data, pos)
        if padding:
            pos = padding.end()
        if pos < len(data) and not data.startswith(GZIP_MAGIC, pos):
            raise ValueError("Failed to decompress SID data: trailing garbage after gzip data")
    return b"".join(chunks)


def read_sid_xml(data: bytes) -> tuple[bytes, dict[str, Any]]:
    """
    Get the XML document from SID file data.

    Args:
        data: The file data

    Returns:
        A tuple of the XML bytes and a :class:`dict` describing the container
        (``header`` and ``compressed``)

    Raises:
        ValueError: If the data isn't a SID, can't be decompressed, or the
            decompressed data is larger than :data:`SID_MAX_XML_SIZE`
    """
    info: dict[str, Any] = {"header": {}, "compressed": False}
    payload = data
    if container_type(data) == "sid":
        info["header"] = describe_container_header(data[:CONTAINER_HEADER_LEN])
        payload = data[CONTAINER_HEADER_LEN:]
    if payload.startswith(GZIP_MAGIC):
        info["compressed"] = True
        payload = _gunzip(payload)
    if SID_ROOT_TAG not in _xml_head(payload):
        raise ValueError(f"Not a Service Interface Definition: no <{SID_ROOT_TAG}> element")
    return payload, info


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def _attr(element: ET.Element | None, name: str, default: Any = "") -> Any:
    """
    Case-insensitive attribute lookup.
    """
    if element is None:
        return default
    for key, value in element.attrib.items():
        if key.lower() == name.lower():
            return value
    return default


def _int_attr(element: ET.Element | None, name: str) -> int | None:
    value = _attr(element, name, None)
    if value is None:
        return None
    return int(value) if _INT_RE.match(value.strip()) else None


def _bool_attr(element: ET.Element | None, name: str) -> bool | None:
    value = _attr(element, name, None)
    if value is None:
        return None
    try:
        return consts.str_to_bool(value)
    except ValueError:
        return None


def _attrs(element: ET.Element | None) -> dict[str, str]:
    return dict(element.attrib) if element is not None else {}


def _text(element: ET.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    return element.text.strip()


def _typed(text: str | None, type_name: str) -> Any:
    if text is None or text == "":
        return None
    if type_name in ("integer", "boolean", "bit_fields", "bit_vector") and _INT_RE.match(text):
        return int(text)
    if type_name == "float":
        try:
            return float(text)
        except ValueError:
            return text
    return text


def _limit(element: ET.Element | None, type_name: str) -> Any:
    """
    Value of a ``<Minimum>``/``<Maximum>`` element.
    """
    if element is None:
        return None
    constant = element.find("Constant")
    if constant is not None:
        return _typed(_text(constant), type_name)
    if len(element):
        child = element[0]
        attrs = " ".join(f"{k}={v}" for k, v in child.attrib.items())
        return f"{child.tag} {attrs}".strip()
    return _typed(_text(element), type_name)


def split_item_name(name: str) -> tuple[int | None, str]:
    """
    Split an item name such as ``1702 Device number`` into its number and label.

    Args:
        name: The item name

    Returns:
        A tuple of ``(parameter number or None, label)``
    """
    match = _NAME_RE.match(name.strip())
    if match:
        return int(match.group("id")), match.group("label").strip()
    return None, name.strip()


# ---------------------------------------------------------------------------
# Item records
# ---------------------------------------------------------------------------


def _communication(element: ET.Element) -> dict[str, Any]:
    comms = element.find("CommunicationProperties")
    record: dict[str, Any] = {
        "servlink_handle": _int_attr(
            comms.find("Servlink") if comms is not None else None, "Handle"
        ),
        "canopen_multiplexor": _int_attr(
            comms.find("CANopen") if comms is not None else None, "Multiplexor"
        ),
    }
    if comms is not None:
        for child in comms:
            if child.tag not in ("Servlink", "CANopen"):
                record[f"{child.tag.lower()}_properties"] = dict(child.attrib)
    return record


def _security(element: ET.Element) -> dict[str, int | None]:
    levels: dict[str, int | None] = {"read_security_level": None, "write_security_level": None}
    for security in element.findall("Security"):
        operation = _attr(security, "Operation", "").lower()
        level = _int_attr(security, "Level")
        if operation in ("read", "write"):
            levels[f"{operation}_security_level"] = level
    return levels


def _type_fields(
    type_element: ET.Element | None, enumerations: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """
    Describe the data type element (``<Integer>``, ``<Float>``, ...) of an item.
    """
    if type_element is None:
        return {"type": "unknown"}
    type_name = _TYPE_TAGS.get(type_element.tag, type_element.tag.lower())
    fields: dict[str, Any] = {"type": type_name}
    size = _int_attr(type_element, "Size")
    if size is not None:
        fields["size"] = size
    signed = _bool_attr(type_element, "IsSigned")
    if signed is not None:
        fields["signed"] = signed
    enumeration = _attr(type_element, "Enumeration", "")
    if enumeration:
        fields["enumeration"] = enumeration
        options = enumerations.get(enumeration, {}).get("options", {})
        if 0 < len(options) <= SID_MAX_INLINE_OPTIONS:
            fields["options"] = options
    for attr, key in (
        ("Precision", "precision"),
        ("MaximumSize", "max_size"),
        ("Encoding", "encoding"),
        ("Type", "time_type"),
    ):
        value = _attr(type_element, attr, None)
        if value is not None:
            fields[key] = _typed(value, "integer") if key == "max_size" else value
    if type_element.tag in ("BitFields", "BitVector"):
        fields["fields"] = [
            {
                "name": _attr(field, "Name"),
                "position": _int_attr(field, "Position"),
                "size": _int_attr(field, "Size"),
                "enumeration": _attr(field, "Enumeration", ""),
            }
            for field in type_element
            if field.tag in ("Field", "Bit")
        ]
    return fields


def data_item_record(
    element: ET.Element, path: str, enumerations: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """
    Build a record for a ``<DataItem>`` element.

    Args:
        element: The ``DataItem`` element
        path: Dot-separated namespace path of the item
        enumerations: Parsed enumerations (see :func:`parse_sid`)

    Returns:
        The item record
    """
    name = _attr(element, "Name")
    number, label = split_item_name(name)
    type_element = next((c for c in element if c.tag not in _COMMON_CHILD_TAGS), None)
    record: dict[str, Any] = {
        "name": name,
        "id": number,
        "label": label,
        "path": path,
        "kind": "data_item",
    }
    record.update(_type_fields(type_element, enumerations))
    type_name = record["type"]
    record["access"] = _attr(element, "Access", "")
    record["address"] = _attr(element, "Address", "")
    record.update(_communication(element))
    record["initial"] = _typed(_text(element.find("InitialValue")), type_name)
    record["minimum"] = _limit(element.find("Minimum"), type_name)
    record["maximum"] = _limit(element.find("Maximum"), type_name)
    record["units"] = _text(element.find("Units"))
    record["description"] = _text(element.find("Description"))
    record.update(_security(element))
    extra = {
        child.tag: (dict(child.attrib) or _text(child))
        for child in element
        if child.tag not in _COMMON_CHILD_TAGS and child is not type_element
    }
    if extra:
        record["extra"] = extra
    return record


def _logics_manager_initial(
    text: str, enumerations: dict[str, dict[str, Any]], enum_names: list[str]
) -> dict[str, Any]:
    """
    Interpret a LogicManager ``<InitialValue>``.

    For example, ``0 0 False And True And True 201 201 201`` is the delay on,
    delay off, operator 1, binary operator 1, operator 2, binary operator 2,
    operator 3, input 1, input 2, and input 3.
    """
    parts = text.split()
    if len(parts) != 10:
        return {"text": text}

    def _input(index: int, value: str) -> dict[str, Any]:
        enum_name = enum_names[index] if index < len(enum_names) else ""
        options = enumerations.get(enum_name, {}).get("options", {})
        return {"value": _typed(value, "integer"), "name": options.get(value, "")}

    return {
        "delay_on": _typed(parts[0], "float"),
        "delay_off": _typed(parts[1], "float"),
        "operator_1": parts[2],
        "binary_operator_1": parts[3],
        "operator_2": parts[4],
        "binary_operator_2": parts[5],
        "operator_3": parts[6],
        "input_1": _input(0, parts[7]),
        "input_2": _input(1, parts[8]),
        "input_3": _input(2, parts[9]),
    }


def logic_manager_record(
    element: ET.Element, path: str, enumerations: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """
    Build a record for a ``<LogicManager>`` element.

    Args:
        element: The ``LogicManager`` element
        path: Dot-separated namespace path of the item
        enumerations: Parsed enumerations (see :func:`parse_sid`)

    Returns:
        The item record
    """
    name = _attr(element, "Name")
    number, label = split_item_name(name)
    enum_names = [_attr(element, f"InEnum{n}", "") for n in (1, 2, 3)]
    initial_text = _text(element.find("InitialValue"))
    record: dict[str, Any] = {
        "name": name,
        "id": number,
        "label": label,
        "path": path,
        "kind": "logics_manager",
        "type": "logics_manager",
        "input_enumerations": enum_names,
        "delay_units": _attr(element, "DelayUnits", ""),
        "delay_on_text": _attr(element, "DelayOnText", ""),
        "delay_off_text": _attr(element, "DelayOffText", ""),
        "initial": _logics_manager_initial(initial_text, enumerations, enum_names),
        "initial_text": initial_text,
    }
    record.update(_communication(element))
    record.update(_security(element))
    return record


def structure_item_record(element: ET.Element, path: str) -> dict[str, Any]:
    """
    Build a record for a ``<StructureItem>`` element (an instance of a ``<Structure>``).
    """
    name = _attr(element, "Name")
    number, label = split_item_name(name)
    record: dict[str, Any] = {
        "name": name,
        "id": number,
        "label": label,
        "path": path,
        "kind": "structure_item",
        "type": "structure",
        "structure": _attr(element, "Structure", ""),
        "access": _attr(element, "Access", ""),
        "address": _attr(element, "Address", ""),
        "initial": _text(element.find("InitialValue")) or None,
    }
    record.update(_communication(element))
    record.update(_security(element))
    extra = {
        k: v
        for k, v in element.attrib.items()
        if k not in ("Name", "Structure", "Access", "Address")
    }
    if extra:
        record["extra"] = extra
    return record


def _walk_namespaces(
    element: ET.Element,
    path: list[str],
    enumerations: dict[str, dict[str, Any]],
    records: list[dict[str, Any]],
) -> None:
    for child in element:
        if child.tag == "Namespace":
            _walk_namespaces(child, [*path, _attr(child, "Name")], enumerations, records)
        elif child.tag == "DataItem":
            records.append(data_item_record(child, ".".join(path), enumerations))
        elif child.tag == "LogicManager":
            records.append(logic_manager_record(child, ".".join(path), enumerations))
        elif child.tag == "StructureItem":
            records.append(structure_item_record(child, ".".join(path)))


# ---------------------------------------------------------------------------
# Top-level parsing
# ---------------------------------------------------------------------------


def _parse_enumerations(root: ET.Element) -> dict[str, dict[str, Any]]:
    enumerations: dict[str, dict[str, Any]] = {}
    for enumeration in root.iter("Enumeration"):
        name = _attr(enumeration, "Name")
        if not name:
            continue
        enumerations[name] = {
            "else": _attr(enumeration, "Else", ""),
            "options": {
                _attr(e, "Value"): _attr(e, "Name") for e in enumeration if e.tag == "Element"
            },
        }
    return enumerations


def _parse_security(root: ET.Element) -> dict[str, Any]:
    security: dict[str, Any] = {}
    protocols = root.find("SecurityProtocols")
    if protocols is None:
        return security
    for protocol in protocols:
        accounts = []
        accounts_element = protocol.find("Accounts")
        if accounts_element is not None:
            for account in accounts_element:
                entry = {"type": account.tag, **account.attrib}
                if _text(account):
                    entry["text"] = _text(account)
                accounts.append(entry)
        commands = {}
        levels_element = protocol.find("CommandSecurityLevels")
        if levels_element is not None:
            for command in levels_element:
                commands[_attr(command, "Name")] = _int_attr(command, "Level")
        security[protocol.tag.lower()] = {
            "accounts": accounts,
            "command_security_levels": commands,
        }
    return security


def _parse_structures(
    root: ET.Element, enumerations: dict[str, dict[str, Any]]
) -> dict[str, list]:
    structures: dict[str, list] = {}
    for structure in root.findall("Structure"):
        fields = []
        for field in structure:
            if field.tag != "Field":
                continue
            type_element = field[0] if len(field) else None
            entry: dict[str, Any] = {"name": _attr(field, "Name")}
            entry.update(_type_fields(type_element, enumerations))
            entry.pop("options", None)
            fields.append(entry)
        structures[_attr(structure, "Name")] = fields
    return structures


def _read_source(source: Path | bytes | BinaryIO) -> bytes:
    if isinstance(source, Path):
        return source.read_bytes()
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if hasattr(source, "read"):
        data = source.read()
        if isinstance(data, str):
            raise TypeError(
                "Text streams can't be parsed as .sid files, open the file in binary mode"
            )
        return data
    raise TypeError(f"Unsupported source type for .sid parsing: {type(source).__name__}")


def parse_sid(
    source: Path | bytes | BinaryIO, include_enumerations: bool = True
) -> dict[str, Any]:
    """
    Parse a Woodward ToolKit Service Interface Definition (``.sid``) file.

    Args:
        source: Path to the file, the raw file bytes, or a binary file object
        include_enumerations: Include the full enumeration tables in the result

    Returns:
        A :class:`dict` with the parsed data, or an empty :class:`dict` if the
        data isn't a SID. Keys:

        - ``header``: the ToolKit container header, if present
        - ``compressed``: if the XML was gzip compressed
        - ``schema``: the SID XML schema name, e.g. ``Sid21.xsd``
        - ``identifier``, ``specification``, ``application_description``,
          ``identifier_address``, ``is_most_significant_byte_first``
        - ``application``: the device identity, see
          :func:`~peat.modules.woodward.toolkit.identify_application`
        - ``nonvolatile_protocol``, ``settings_policies``, ``security``
        - ``namespaces``: top-level namespace names
        - ``parameters``: flat list of ``DataItem``, ``LogicManager``, and
          ``StructureItem`` records with their namespace ``path``
        - ``num_parameters``, ``parameter_types``, ``parameter_kinds``,
          ``parameter_namespaces``, ``parameter_access``
        - ``enumerations`` (if requested) and ``num_enumerations``
        - ``events``: ``{identifier: text}``
        - ``structures``: ``{name: [fields]}``
    """
    try:
        data = _read_source(source)
        xml_data, info = read_sid_xml(data)
    except (OSError, TypeError, ValueError) as ex:
        log.error(f"Failed to read .sid data: {ex}")
        return {}

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as ex:
        log.error(f"Failed to parse SID XML: {ex}")
        return {}
    if root.tag != SID_ROOT_TAG:
        log.error(f"Unexpected SID root element '{root.tag}'")
        return {}

    enumerations = _parse_enumerations(root)
    records: list[dict[str, Any]] = []
    _walk_namespaces(root, [], enumerations, records)

    schema = ""
    for key, value in root.attrib.items():
        if key.endswith("noNamespaceSchemaLocation"):
            schema = value
    identifier = _attr(root, "Identifier")
    parsed: dict[str, Any] = {
        "header": info["header"],
        "compressed": info["compressed"],
        "schema": schema,
        "identifier": identifier,
        "specification": _attr(root, "Specification"),
        "application_description": _attr(root, "ApplicationDescription"),
        "identifier_address": _attr(root, "IdentifierAddress"),
        "is_most_significant_byte_first": _bool_attr(root, "IsMostSignificantByteFirst"),
        "application": identify_application(identifier),
        "nonvolatile_protocol": _attr(root.find("NonVolatileProtocol"), "Type"),
        "settings_policies": _attrs(root.find("SettingsPolicies")),
        "security": _parse_security(root),
        "namespaces": list(dict.fromkeys(_attr(ns, "Name") for ns in root.findall("Namespace"))),
        "parameters": records,
        "num_parameters": len(records),
        "parameter_kinds": dict(Counter(r["kind"] for r in records)),
        "parameter_types": dict(Counter(r["type"] for r in records)),
        "parameter_namespaces": dict(Counter(r["path"].split(".")[0] for r in records)),
        "parameter_access": dict(Counter(r.get("access", "") for r in records)),
        "num_enumerations": len(enumerations),
        "events": {
            _attr(e, "Identifier"): (_text(e.find("Constant")) or _text(e))
            for e in root.iter("Event")
        },
        "structures": _parse_structures(root, enumerations),
    }
    if include_enumerations:
        parsed["enumerations"] = enumerations

    if not records:
        log.warning("No data items found in Woodward SID file")
    return parsed


def summarize_sid(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Compact summary of :func:`parse_sid` output, suitable for ``DeviceData.extra``.
    """
    keys = (
        "header",
        "compressed",
        "schema",
        "identifier",
        "specification",
        "application_description",
        "application",
        "nonvolatile_protocol",
        "settings_policies",
        "security",
        "namespaces",
        "num_parameters",
        "parameter_kinds",
        "parameter_types",
        "parameter_namespaces",
        "parameter_access",
        "num_enumerations",
    )
    summary = {key: parsed.get(key) for key in keys}
    summary["num_events"] = len(parsed.get("events", {}))
    summary["num_structures"] = len(parsed.get("structures", {}))
    return summary


def populate_device_from_sid(dev: DeviceData, parsed: dict[str, Any]) -> None:
    """
    Add the results of :func:`parse_sid` to a device.

    The application identity is used for the device description and firmware
    version, ServLink accounts (if any) are added as users, the data items
    are added as ServLink/CANopen registers and the command variable lists
    as tags (see :mod:`~peat.modules.woodward.easygen_data`), and a summary
    of the file is stored in ``dev.extra["sid"]``.

    Args:
        dev: The device to populate
        parsed: Output of :func:`parse_sid`
    """
    if not parsed:
        return

    dev.extra["sid"] = summarize_sid(parsed)

    app = parsed.get("application", {})
    if parsed.get("identifier") and not dev.firmware.id:
        dev.firmware.id = parsed["identifier"]
    if app.get("version") and not dev.firmware.version:
        dev.firmware.version = app["version"]
    if app.get("brand") and not dev.description.brand:
        dev.description.brand = app["brand"]
    if app.get("model") and not dev.description.model:
        dev.description.model = app["model"]
    elif not dev.description.model:
        # Don't let the module's default model mislabel a file from another device
        dev.description.model = "unknown"
    if app.get("product") and not dev.description.product:
        dev.description.product = app["product"]

    dev.extra["sid"]["data_model"] = populate_data_model_from_sid(dev, parsed)

    for protocol, details in parsed.get("security", {}).items():
        for account in details.get("accounts", []):
            name = account.get("Name") or account.get("User") or account.get("text")
            if name:
                dev.store(
                    "users",
                    User(name=str(name), description=f"{protocol} account", extra=dict(account)),
                    lookup="name",
                )


__all__ = [
    "SID_MAX_INLINE_OPTIONS",
    "SID_MAX_XML_SIZE",
    "SID_ROOT_TAG",
    "data_item_record",
    "is_sid_data",
    "logic_manager_record",
    "parse_sid",
    "populate_device_from_sid",
    "read_sid_xml",
    "sid_signature_check",
    "split_item_name",
    "summarize_sid",
]
