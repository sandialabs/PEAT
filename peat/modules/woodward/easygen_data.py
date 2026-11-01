"""
Populate the PEAT data model from parsed Woodward ToolKit files.

The parsers in :mod:`~peat.modules.woodward.parse_wset` and
:mod:`~peat.modules.woodward.parse_sid` return flat parameter records. This
module maps those records onto the device data model:

- Every parameter with a ServLink handle or CANopen object address becomes a
  :class:`~peat.data.models.Register` (``protocol`` ``servlink`` or ``canopen``).
  Settings files and SIDs. The CANopen address is the SDO ``index:subindex``
  (the multiplexor stored by ToolKit is ``index << 8 | subindex``, verified
  against Woodward's EDS files).
- LogicsManager command variables and AnalogManager data sources become
  :class:`~peat.data.models.Tag` objects (``binary``/``analog``), from the
  lists embedded in settings files and SIDs.
- Discrete and analog inputs and outputs (the ``Config_IO`` groups of a
  settings file) become :class:`~peat.data.models.IO` objects. Relay outputs
  carry their LogicsManager equation as description.
- Serial, CAN, and Ethernet interface settings become
  :class:`~peat.data.models.Interface` objects, and the Modbus, CANopen, and
  J1939 settings :class:`~peat.data.models.Service` objects.
- Password and code level parameters (easYgen-3000XT and newer store
  passwords as parameters) become :class:`~peat.data.models.User` objects.
- The device name, device number, time zone, and language are set on
  ``dev.name``, ``dev.geo.timezone``, and ``dev.extra``.
- LogicsManager equations are converted to logic, see
  :mod:`~peat.modules.woodward.easygen_logic`.
"""

import re
from collections import defaultdict
from typing import Any, Final

from peat import IO, DeviceData, Interface, Register, Service, Tag, User, log

_IO_GROUP_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\.)(?P<kind>Discrete_In|Discrete_Out|Analog_In|Analog_Out|"
    r"External_DI|External_DO|External_AI|External_AO|"
    r"Discrete inputs?|Discrete outputs?|Relay outputs?|Analog inputs?|Analog outputs?|"
    r"External discrete inputs?|External discrete outputs?|External analog inputs?|"
    r"External analog outputs?)"
    r"[ ._]+(?:[A-Za-z ]+ )?(?P<number>\d{1,3})$",
    re.IGNORECASE,
)
_IO_KINDS: Final[dict[str, tuple[str, str, str]]] = {
    "discrete_in": ("DI", "input", "binary"),
    "discrete_input": ("DI", "input", "binary"),
    "discrete_inputs": ("DI", "input", "binary"),
    "discrete_out": ("DO", "output", "binary"),
    "discrete_output": ("DO", "output", "binary"),
    "discrete_outputs": ("DO", "output", "binary"),
    "relay_output": ("DO", "output", "binary"),
    "relay_outputs": ("DO", "output", "binary"),
    "analog_in": ("AI", "input", "analog"),
    "analog_input": ("AI", "input", "analog"),
    "analog_inputs": ("AI", "input", "analog"),
    "analog_out": ("AO", "output", "analog"),
    "analog_output": ("AO", "output", "analog"),
    "analog_outputs": ("AO", "output", "analog"),
    "external_di": ("External DI", "input", "binary"),
    "external_discrete_input": ("External DI", "input", "binary"),
    "external_discrete_inputs": ("External DI", "input", "binary"),
    "external_do": ("External DO", "output", "binary"),
    "external_discrete_output": ("External DO", "output", "binary"),
    "external_discrete_outputs": ("External DO", "output", "binary"),
    "external_ai": ("External AI", "input", "analog"),
    "external_analog_input": ("External AI", "input", "analog"),
    "external_analog_inputs": ("External AI", "input", "analog"),
    "external_ao": ("External AO", "output", "analog"),
    "external_analog_output": ("External AO", "output", "analog"),
    "external_analog_outputs": ("External AO", "output", "analog"),
}
_SERIAL_GROUP_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\.)(?:Config_)?Serial[ _]?(?P<number>\d)(?:\.|$)", re.IGNORECASE
)
_CAN_GROUP_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\.)(?:Config_)?CAN[ _]?(?P<number>\d)(?:\.|$)", re.IGNORECASE
)
_BAUDRATE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<value>\d+(?:[.,]\d+)?)\s*(?P<unit>k?)\s*(?:Bd|baud|bps|bit)", re.IGNORECASE
)
_PARITY: Final[dict[str, str]] = {"no": "none", "none": "none", "even": "even", "odd": "odd"}
_STOP_BITS: Final[dict[str, int]] = {"one": 1, "1": 1, "two": 2, "2": 2}
_ETHERNET_RE: Final[re.Pattern[str]] = re.compile(r"Ethernet\s+(?P<port>[A-Z])", re.IGNORECASE)
_PART_RE: Final[re.Pattern[str]] = re.compile(r"part\s*(?P<part>[2-4])\s*$", re.IGNORECASE)
_IP_BASE_LABELS: Final[dict[str, str]] = {
    "ip address": "ip",
    "subnet mask": "subnet_mask",
    "gateway ip": "gateway",
}
_TRUE_VALUES: Final[frozenset[str]] = frozenset({"yes", "on", "true", "enabled", "1"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def canopen_address(multiplexor: int) -> str:
    """
    CANopen SDO object address of a ToolKit CANopen multiplexor.

    Args:
        multiplexor: The multiplexor, ``index << 8 | subindex``

    Returns:
        The address as ``0xIIII:SS``, e.g. ``0x26A6:01`` for parameter 1702
    """
    return f"0x{multiplexor >> 8:04X}:{multiplexor & 0xFF:02X}"


def register_data_type(record: dict[str, Any]) -> str:
    """PEAT register data type (``int_16``, ``float_32``, ...) of a parameter record."""
    type_name = str(record.get("type") or "")
    size = record.get("size")
    if type_name in ("integer", "enumerated", "bit_fields", "bit_vector"):
        prefix = "int" if record.get("signed") else "uint"
        return f"{prefix}_{size}" if size else prefix
    if type_name == "boolean":
        return "bool"
    if type_name == "float":
        return "float_32"
    if type_name == "string":
        return "string"
    if type_name == "bit_field":
        return "bool"
    if type_name == "logics_manager":
        return "logics_manager"
    if type_name == "array":
        return "array"
    if type_name == "time":
        return "datetime"
    return type_name


def measurement_type(record: dict[str, Any]) -> str:
    """PEAT measurement type (``analog``/``binary``) of a parameter record."""
    type_name = str(record.get("type") or "")
    if type_name in ("boolean", "bit_field", "logics_manager"):
        return "binary"
    if type_name in ("integer", "float", "enumerated", "bit_fields", "array"):
        return "analog"
    return ""


def _scalar(value: Any) -> Any:
    """Make a parameter value suitable for ``extra`` fields (scalars only)."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in _TRUE_VALUES


def _baudrate(value: Any) -> int | None:
    """Parse a baudrate setting such as ``19.2 kBd`` or ``250 kBd``."""
    match = _BAUDRATE_RE.search(str(value))
    if not match:
        return None
    number = float(match.group("value").replace(",", "."))
    if match.group("unit").lower() == "k":
        number *= 1000
    return round(number)


def _by_group(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[str(record.get("group") or record.get("path") or "")].append(record)
    return groups


def _find(records: list[dict[str, Any]], *labels: str) -> dict[str, Any] | None:
    """First record whose label matches one of ``labels`` (case-insensitive)."""
    wanted = {label.lower() for label in labels}
    for record in records:
        if str(record.get("label") or "").strip().lower() in wanted:
            return record
    return None


def _value(record: dict[str, Any] | None, default: Any = None) -> Any:
    if record is None:
        return default
    value = record.get("value")
    return default if value is None else value


def _settings(records: list[dict[str, Any]]) -> dict[str, Any]:
    """``{label: value}`` of the records, for ``extra`` fields."""
    settings: dict[str, Any] = {}
    for record in records:
        label = str(record.get("label") or record.get("name") or "")
        if not label:
            continue
        value = (
            record.get("expression")
            if record.get("kind") == "logics_manager"
            else record.get("value")
        )
        settings[label] = _scalar(value)
    return settings


# ---------------------------------------------------------------------------
# Registers and tags
# ---------------------------------------------------------------------------


def add_registers(
    dev: DeviceData, records: list[dict[str, Any]], defaults_only: bool = False
) -> int:
    """
    Add the ServLink and CANopen addresses of the parameters as registers.

    Args:
        dev: The device
        records: Parameter records from a settings file or SID
        defaults_only: The records come from a SID (no configured values)

    Returns:
        The number of registers added
    """
    count = 0
    for record in records:
        name = str(record.get("name") or "")
        label = str(record.get("label") or name)
        group = str(record.get("group") or record.get("path") or "")
        access = str(record.get("access") or "")
        if access.lower() == "readwrite":
            read_write = "read_write"
        elif "write" in access.lower():
            read_write = "write"
        elif defaults_only:
            read_write = "read"  # SID items without access are status values
        else:
            read_write = "read_write"  # settings are writable by definition

        extra: dict[str, Any] = {}
        if record.get("id") is not None:
            extra["parameter"] = record["id"]
        if not defaults_only and "value" in record:
            extra["value"] = _scalar(record.get("expression", record["value"]))
        if record.get("initial") is not None:
            extra["initial"] = _scalar(record["initial"])
        if record.get("units"):
            extra["units"] = record["units"]
        if record.get("kind"):
            extra["kind"] = record["kind"]
        if record.get("write_security_level") is not None:
            extra["write_security_level"] = record["write_security_level"]
        if record.get("read_security_level") is not None:
            extra["read_security_level"] = record["read_security_level"]

        addresses = []
        handle = record.get("servlink_handle")
        if handle:
            addresses.append(("servlink", str(handle)))
        multiplexor = record.get("canopen_multiplexor")
        if multiplexor:
            addresses.append(("canopen", canopen_address(int(multiplexor))))
        for protocol, address in addresses:
            register = Register(
                address=address,
                name=name,
                tag=label,
                description=f"{label} ({group})" if group else label,
                group=group,
                protocol=protocol,
                data_type=register_data_type(record),
                measurement_type=measurement_type(record),
                read_write=read_write,
                enabled=True,
                extra=dict(extra),
            )
            dev.store("registers", register, append=True)
            count += 1
    return count


def add_tags(dev: DeviceData, logic_inputs: dict[str, str], analog_inputs: dict[str, str]) -> int:
    """
    Add the LogicsManager command variables and AnalogManager data sources as tags.

    Args:
        dev: The device
        logic_inputs: ``{number: name}`` of the LogicsManager command variables
        analog_inputs: ``{number: name}`` of the AnalogManager data sources

    Returns:
        The number of tags added
    """
    count = 0
    for inputs, tag_type, description in (
        (logic_inputs, "binary", "LogicsManager command variable"),
        (analog_inputs, "analog", "AnalogManager data source"),
    ):
        for number, name in inputs.items():
            name = str(name).strip()
            if not name:
                continue
            dev.store(
                "tag",
                Tag(name=name, address=str(number), type=tag_type, description=description),
                append=True,
            )
            count += 1
    return count


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def add_io(dev: DeviceData, records: list[dict[str, Any]]) -> int:
    """
    Add the configured discrete and analog inputs and outputs.

    Args:
        dev: The device
        records: Parameter records from a settings file

    Returns:
        The number of I/O points added
    """
    count = 0
    for group, group_records in sorted(_by_group(records).items()):
        match = _IO_GROUP_RE.search(group)
        if not match:
            continue
        kind_key = match.group("kind").strip().lower().replace(" ", "_")
        kind = _IO_KINDS.get(kind_key)
        if kind is None:
            continue
        prefix, direction, io_type = kind
        number = int(match.group("number"))
        point_id = f"{prefix} {number:02d}"
        settings = _settings(group_records)
        equation = next((r for r in group_records if r.get("kind") == "logics_manager"), None)
        if equation is not None:
            name = str(equation.get("label") or point_id)
            description = str(equation.get("expression") or "")
        else:
            name = point_id
            description = ""
            type_setting = _find(group_records, "Type", "Selected hardware type")
            if type_setting is not None and type_setting.get("value") not in (None, ""):
                description = f"Type: {type_setting['value']}"
        point = IO(
            id=point_id,
            name=name,
            direction=direction,
            type=io_type,
            description=description,
            extra={"group": group, **settings},
        )
        if prefix.startswith("External"):
            point.slot = ["external"]
        dev.store("io", point, lookup=["id"])
        count += 1
    return count


# ---------------------------------------------------------------------------
# Interfaces and services
# ---------------------------------------------------------------------------


def _serial_interface(number: str, group_records: list[dict[str, Any]], group: str) -> Interface:
    duplex = _find(group_records, "Full-, halfduplex mode", "Duplex mode")
    interface = Interface(
        name=f"Serial {number}",
        id=f"serial{number}",
        type="rs_485" if duplex is not None else "rs_232",
        physical=True,
        baudrate=_baudrate(_value(_find(group_records, "Baudrate"))),
        parity=_PARITY.get(str(_value(_find(group_records, "Parity"), "")).strip().lower(), ""),
        stop_bits=_STOP_BITS.get(
            str(_value(_find(group_records, "Stop bits"), "")).strip().lower()
        ),
        extra={"group": group, **_settings(group_records)},
    )
    return interface


def _can_interface(number: str, group_records: list[dict[str, Any]], group: str) -> Interface:
    return Interface(
        name=f"CAN {number}",
        id=f"can{number}",
        type="can",
        physical=True,
        baudrate=_baudrate(_value(_find(group_records, "Baudrate"))),
        extra={"group": group, **_settings(group_records)},
    )


def _ethernet_interfaces(records: list[dict[str, Any]]) -> list[Interface]:
    """
    Ethernet interfaces from IP address parameters.

    easYgen-3000XT controls store each address as four parameters: the
    base parameter (``5330 IP address``) and ``... part 2``..``part 4``
    with the following parameter numbers.
    """
    by_id = {r["id"]: r for r in records if r.get("id") is not None}
    interfaces: dict[str, dict[str, Any]] = {}
    for record in records:
        label = str(record.get("label") or "").strip().lower()
        field = _IP_BASE_LABELS.get(label)
        if field is None or record.get("id") is None:
            continue
        parts = [record]
        port = ""
        for offset in (1, 2, 3):
            part = by_id.get(record["id"] + offset)
            if part is None or not _PART_RE.search(str(part.get("label") or "")):
                break
            parts.append(part)
            port_match = _ETHERNET_RE.search(str(part.get("label") or ""))
            if port_match:
                port = port_match.group("port").upper()
        values = [part.get("value") for part in parts]
        if len(values) == 4 and all(isinstance(v, int) and 0 <= v <= 255 for v in values):
            address = ".".join(str(v) for v in values)
        elif len(values) == 1 and isinstance(values[0], str) and values[0].count(".") == 3:
            address = values[0]
        else:
            continue
        group = str(record.get("group") or "")
        key = f"{group}|{port}"
        entry = interfaces.setdefault(key, {"port": port, "group": group})
        entry[field] = address

    # Addresses whose parameters don't name the port (e.g. "Gateway IP part 2")
    # belong to the port of their parameter group, if there is exactly one
    for key, entry in list(interfaces.items()):
        if entry["port"]:
            continue
        siblings = [
            other
            for other_key, other in interfaces.items()
            if other_key != key and other["group"] == entry["group"] and other["port"]
        ]
        if len(siblings) == 1:
            for field in _IP_BASE_LABELS.values():
                if entry.get(field) and not siblings[0].get(field):
                    siblings[0][field] = entry[field]
            del interfaces[key]

    result = []
    for key, entry in interfaces.items():
        if not entry.get("ip"):
            continue
        name = f"Ethernet {entry['port']}" if entry["port"] else "Ethernet"
        result.append(
            Interface(
                name=name,
                id=name.lower().replace(" ", "_"),
                type="ethernet",
                physical=True,
                ip=entry["ip"],
                subnet_mask=entry.get("subnet_mask", ""),
                gateway=entry.get("gateway", ""),
                extra={"group": entry["group"], "key": key},
            )
        )
    return result


def add_interfaces_and_services(dev: DeviceData, records: list[dict[str, Any]]) -> tuple[int, int]:
    """
    Add the serial, CAN, and Ethernet interfaces and the protocols configured on them.

    Args:
        dev: The device
        records: Parameter records from a settings file

    Returns:
        A tuple of the number of interfaces and services added
    """
    groups = _by_group(records)
    serial_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    can_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group, group_records in groups.items():
        serial = _SERIAL_GROUP_RE.search(group)
        if serial:
            serial_groups[serial.group("number")].append((group, group_records))
            continue
        can = _CAN_GROUP_RE.search(group)
        if can:
            can_groups[can.group("number")].append((group, group_records))

    modbus_protocol = _find(groups.get("Modbus", []), "Modbus protocol number")
    interfaces = 0
    services = 0

    for number, group_list in sorted(serial_groups.items()):
        base_group, base_records = min(group_list, key=lambda item: len(item[0]))
        interface = _serial_interface(number, base_records, base_group)
        dev.store("interface", interface, lookup="name")
        interfaces += 1
        all_records = [r for _, group_records in group_list for r in group_records]
        enable = _find(all_records, "Enable Modbus protocol")
        slave_id = _find(all_records, "Modbus slave ID")
        if (enable is not None and _is_true(enable.get("value"))) or (
            enable is None and slave_id is not None
        ):
            service = Service(
                protocol="modbus",
                listen_interface=interface.name,
                enabled=True if enable is not None else None,
                extra={
                    "slave_id": _scalar(_value(slave_id)),
                    "protocol_number": _scalar(_value(modbus_protocol)),
                    "baudrate": interface.baudrate,
                },
            )
            dev.store(
                "service",
                service,
                lookup={"protocol": service.protocol, "listen_interface": interface.name},
                interface_lookup={"name": interface.name},
            )
            dev.related.protocols.add("modbus")
            services += 1
        modem = any("modem" in group.lower() for group, _ in group_list)
        if modem:
            interface.extra["modem"] = True

    for number, group_list in sorted(can_groups.items()):
        base_group, base_records = min(group_list, key=lambda item: len(item[0]))
        interface = _can_interface(number, base_records, base_group)
        dev.store("interface", interface, lookup="name")
        interfaces += 1
        all_records = [r for _, group_records in group_list for r in group_records]
        node_id = _find(all_records, f"Node-ID CAN bus {number}", "Node-ID", "Node ID")
        if node_id is not None or any("canopen" in group.lower() for group, _ in group_list):
            service = Service(
                protocol="canopen",
                listen_interface=interface.name,
                extra={"node_id": _scalar(_value(node_id)), "baudrate": interface.baudrate},
            )
            dev.store(
                "service",
                service,
                lookup={"protocol": service.protocol, "listen_interface": interface.name},
                interface_lookup={"name": interface.name},
            )
            dev.related.protocols.add("canopen")
            services += 1
        if any("j1939" in group.lower() for group, _ in group_list):
            service = Service(
                protocol="j1939",
                listen_interface=interface.name,
                extra={"baudrate": interface.baudrate},
            )
            dev.store(
                "service",
                service,
                lookup={"protocol": service.protocol, "listen_interface": interface.name},
                interface_lookup={"name": interface.name},
            )
            dev.related.protocols.add("j1939")
            services += 1

    for interface in _ethernet_interfaces(records):
        dev.store("interface", interface, lookup="name")
        interfaces += 1
        if interface.ip:
            dev.related.ip.add(interface.ip)

    return interfaces, services


# ---------------------------------------------------------------------------
# Users and identity
# ---------------------------------------------------------------------------


def add_users(dev: DeviceData, records: list[dict[str, Any]]) -> int:
    """
    Add the password parameters (code levels, interface passwords) as users.

    Args:
        dev: The device
        records: Parameter records from a settings file

    Returns:
        The number of users added
    """
    count = 0
    code_levels: dict[str, Any] = {}
    for record in records:
        label = str(record.get("label") or "").strip()
        lowered = label.lower()
        if lowered.startswith("password"):
            account = (
                re.sub(r"^password(\s+for)?\s*", "", label, flags=re.IGNORECASE).strip()
                or "password"
            )
            user = User(
                name=account,
                description=f"easYgen password parameter {record.get('id') or ''}: {label}".strip(
                    " :"
                ),
                extra={
                    "parameter": record.get("id"),
                    "password": _scalar(record.get("value")),
                    "write_security_level": record.get("write_security_level"),
                    "group": record.get("group") or "",
                },
            )
            dev.store("users", user, lookup="name")
            count += 1
        elif lowered.startswith("code level") or lowered.startswith("codelevel"):
            code_levels[label] = _scalar(record.get("value"))
    if code_levels:
        dev.extra["code_levels"] = code_levels
    return count


def add_identity(dev: DeviceData, records: list[dict[str, Any]]) -> None:
    """
    Set the device name, number, time zone, and language from the settings.

    Args:
        dev: The device
        records: Parameter records from a settings file
    """
    for record in records:
        label = str(record.get("label") or "").strip().lower()
        value = record.get("value")
        if value in (None, ""):
            continue
        if label == "device name" and record.get("type") == "string" and not dev.name:
            dev.name = str(value)
        elif label == "device number":
            dev.extra["device_number"] = _scalar(value)
        elif label == "time zone" and not dev.geo.timezone:
            dev.geo.timezone = str(value)
        elif label == "language":
            dev.extra["language"] = _scalar(value)


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def populate_data_model_from_wset(dev: DeviceData, parsed: dict[str, Any]) -> dict[str, int]:
    """
    Populate the data model from a parsed settings file.

    Args:
        dev: The device
        parsed: Output of :func:`~peat.modules.woodward.parse_wset.parse_wset`

    Returns:
        Counts of the objects added: ``registers``, ``tags``, ``io``,
        ``interfaces``, ``services``, ``users``
    """
    records = parsed.get("parameters", [])
    counts = {
        "registers": add_registers(dev, records),
        "tags": add_tags(
            dev, parsed.get("logics_manager_inputs", {}), parsed.get("analog_manager_inputs", {})
        ),
        "io": add_io(dev, records),
    }
    counts["interfaces"], counts["services"] = add_interfaces_and_services(dev, records)
    counts["users"] = add_users(dev, records)
    add_identity(dev, records)
    for protocol in ("servlink", "canopen"):
        if any(r.protocol == protocol for r in dev.registers):
            dev.related.protocols.add(protocol)
    log.debug(f"Data model objects from settings file: {counts}")
    return counts


def _sid_inputs(parsed: dict[str, Any], keyword: str) -> dict[str, str]:
    for name, enumeration in parsed.get("enumerations", {}).items():
        if keyword in name.upper():
            return enumeration.get("options", {})
    return {}


def populate_data_model_from_sid(dev: DeviceData, parsed: dict[str, Any]) -> dict[str, int]:
    """
    Populate the data model from a parsed Service Interface Definition.

    Args:
        dev: The device
        parsed: Output of :func:`~peat.modules.woodward.parse_sid.parse_sid`

    Returns:
        Counts of the objects added: ``registers`` and ``tags``
    """
    records = parsed.get("parameters", [])
    counts = {
        "registers": add_registers(dev, records, defaults_only=True),
        "tags": add_tags(dev, _sid_inputs(parsed, "LOGICLIST"), _sid_inputs(parsed, "ANALOGLIST")),
    }
    for protocol in ("servlink", "canopen"):
        if any(r.protocol == protocol for r in dev.registers):
            dev.related.protocols.add(protocol)
    log.debug(f"Data model objects from SID: {counts}")
    return counts


__all__ = [
    "add_identity",
    "add_interfaces_and_services",
    "add_io",
    "add_registers",
    "add_tags",
    "add_users",
    "canopen_address",
    "measurement_type",
    "populate_data_model_from_sid",
    "populate_data_model_from_wset",
    "register_data_type",
]
