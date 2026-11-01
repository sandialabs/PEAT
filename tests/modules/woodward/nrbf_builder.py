"""
Minimal .NET Remoting Binary Format (NRBF, a.k.a. ``BinaryFormatter``) writer
used to build synthetic Woodward ToolKit files for the unit tests.

Only the record types needed by the fixtures are implemented. Reference:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/
"""

import io
import struct
from collections.abc import Callable
from typing import Any, Final

# PrimitiveTypeEnumeration
BOOLEAN: Final[int] = 1
BYTE: Final[int] = 2
DOUBLE: Final[int] = 6
INT16: Final[int] = 7
INT32: Final[int] = 8
INT64: Final[int] = 9
SINGLE: Final[int] = 11
DATETIME: Final[int] = 13
UINT32: Final[int] = 15
STRING: Final[int] = 18

# BinaryTypeEnumeration
BT_PRIMITIVE: Final[int] = 0
BT_STRING: Final[int] = 1
BT_OBJECT: Final[int] = 2
BT_SYSTEM_CLASS: Final[int] = 3
BT_CLASS: Final[int] = 4
BT_OBJECT_ARRAY: Final[int] = 5
BT_STRING_ARRAY: Final[int] = 6
BT_PRIMITIVE_ARRAY: Final[int] = 7

# RecordTypeEnumeration
RT_HEADER: Final[int] = 0
RT_CLASS_WITH_ID: Final[int] = 1
RT_SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES: Final[int] = 4
RT_CLASS_WITH_MEMBERS_AND_TYPES: Final[int] = 5
RT_BINARY_OBJECT_STRING: Final[int] = 6
RT_MEMBER_PRIMITIVE_TYPED: Final[int] = 8
RT_MEMBER_REFERENCE: Final[int] = 9
RT_OBJECT_NULL: Final[int] = 10
RT_MESSAGE_END: Final[int] = 11
RT_BINARY_LIBRARY: Final[int] = 12
RT_ARRAY_SINGLE_PRIMITIVE: Final[int] = 15
RT_ARRAY_SINGLE_OBJECT: Final[int] = 16
RT_ARRAY_SINGLE_STRING: Final[int] = 17

_FORMATS: Final[dict[int, str]] = {
    BOOLEAN: "<?",
    BYTE: "<B",
    DOUBLE: "<d",
    INT16: "<h",
    INT32: "<i",
    INT64: "<q",
    SINGLE: "<f",
    UINT32: "<I",
    DATETIME: "<Q",
}

#: Constant bytes 1 to 7 of the ToolKit container header
TOOLKIT_MAGIC: Final[bytes] = bytes.fromhex("3ab51fd46d59c2")


def container_header(type_code: int, version: int) -> bytes:
    """Build a 10-byte ToolKit container header."""
    return bytes([type_code]) + TOOLKIT_MAGIC + version.to_bytes(2, "little")


WSET_HEADER: Final[bytes] = container_header(0x14, 0x14)
WTOOL_HEADER: Final[bytes] = container_header(0x15, 0x31)
SID_HEADER: Final[bytes] = container_header(0x16, 0x01)


class NrbfWriter:
    """Writes NRBF records to an in-memory buffer."""

    def __init__(self) -> None:
        self._buf = io.BytesIO()
        self._next_id = 1000
        self._deferred: list[Callable[[], None]] = []

    # -- low level ---------------------------------------------------------

    def getvalue(self) -> bytes:
        return self._buf.getvalue()

    def new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def raw(self, data: bytes) -> None:
        self._buf.write(data)

    def byte(self, value: int) -> None:
        self._buf.write(bytes([value]))

    def int32(self, value: int) -> None:
        self._buf.write(struct.pack("<i", value))

    def lps(self, text: str) -> None:
        """LengthPrefixedString"""
        data = text.encode("utf-8")
        length = len(data)
        while True:
            chunk = length & 0x7F
            length >>= 7
            if length:
                self.byte(chunk | 0x80)
            else:
                self.byte(chunk)
                break
        self._buf.write(data)

    def primitive(self, ptype: int, value: Any) -> None:
        """Write a primitive value (without a record type)."""
        if ptype == STRING:
            self.lps(value)
        else:
            self._buf.write(struct.pack(_FORMATS[ptype], value))

    # -- records -------------------------------------------------------------

    def header(self, root_id: int = 1, header_id: int = -1) -> None:
        self.byte(RT_HEADER)
        self.int32(root_id)
        self.int32(header_id)
        self.int32(1)
        self.int32(0)

    def library(self, library_id: int, name: str) -> None:
        self.byte(RT_BINARY_LIBRARY)
        self.int32(library_id)
        self.lps(name)

    def class_record(
        self,
        object_id: int,
        class_name: str,
        members: list[tuple[str, int, Any]],
        library_id: int | None = None,
    ) -> None:
        """
        Write a ``ClassWithMembersAndTypes`` (or ``SystemClassWithMembersAndTypes``
        if ``library_id`` is None) record. The caller writes the member values next.

        ``members`` is a list of ``(name, binary type, additional info)``. The
        additional info is the primitive type for primitives and primitive
        arrays, the class name for system classes, ``(class name, library id)``
        for classes, and ignored otherwise.
        """
        self.byte(
            RT_CLASS_WITH_MEMBERS_AND_TYPES
            if library_id is not None
            else RT_SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES
        )
        self.int32(object_id)
        self.lps(class_name)
        self.int32(len(members))
        for name, _, _ in members:
            self.lps(name)
        for _, binary_type, _ in members:
            self.byte(binary_type)
        for _, binary_type, info in members:
            if binary_type in (BT_PRIMITIVE, BT_PRIMITIVE_ARRAY):
                self.byte(info)
            elif binary_type == BT_SYSTEM_CLASS:
                self.lps(info)
            elif binary_type == BT_CLASS:
                self.lps(info[0])
                self.int32(info[1])
        if library_id is not None:
            self.int32(library_id)

    def class_with_id(self, object_id: int, metadata_id: int) -> None:
        self.byte(RT_CLASS_WITH_ID)
        self.int32(object_id)
        self.int32(metadata_id)

    def string(self, value: str, object_id: int | None = None) -> int:
        """Write a ``BinaryObjectString`` record and return its object id."""
        object_id = object_id or self.new_id()
        self.byte(RT_BINARY_OBJECT_STRING)
        self.int32(object_id)
        self.lps(value)
        return object_id

    def primitive_typed(self, ptype: int, value: Any) -> None:
        """Write a ``MemberPrimitiveTyped`` record (a boxed primitive)."""
        self.byte(RT_MEMBER_PRIMITIVE_TYPED)
        self.byte(ptype)
        self.primitive(ptype, value)

    def reference(self, id_ref: int) -> None:
        self.byte(RT_MEMBER_REFERENCE)
        self.int32(id_ref)

    def null(self) -> None:
        self.byte(RT_OBJECT_NULL)

    def array_single_object(self, object_id: int, length: int) -> None:
        """The caller writes ``length`` element records next."""
        self.byte(RT_ARRAY_SINGLE_OBJECT)
        self.int32(object_id)
        self.int32(length)

    def array_single_string(self, object_id: int, values: list[str]) -> None:
        self.byte(RT_ARRAY_SINGLE_STRING)
        self.int32(object_id)
        self.int32(len(values))
        for value in values:
            self.string(value)

    def array_single_primitive(self, object_id: int, ptype: int, values: list[Any]) -> None:
        self.byte(RT_ARRAY_SINGLE_PRIMITIVE)
        self.int32(object_id)
        self.int32(len(values))
        self.byte(ptype)
        for value in values:
            self.primitive(ptype, value)

    def end(self) -> None:
        self.byte(RT_MESSAGE_END)

    # -- deferred records ------------------------------------------------------

    def defer(self, writer: Callable[[], None]) -> None:
        """Queue a top-level record (e.g. a referenced array) to be written later."""
        self._deferred.append(writer)

    def flush(self) -> None:
        """Write all queued records (and any records they queue)."""
        while self._deferred:
            writer = self._deferred.pop(0)
            writer()

    # -- helpers for member values -------------------------------------------------

    def string_array_ref(self, values: list[str]) -> None:
        """Write a reference to a string array that is written later."""
        array_id = self.new_id()
        self.reference(array_id)
        self.defer(lambda: self.array_single_string(array_id, values))


# ---------------------------------------------------------------------------
# Generic (non-Woodward) fixture: exercises the fallback parameter extraction
# ---------------------------------------------------------------------------


def build_generic_streams(settings: list[tuple[int, str, Any]] | None = None) -> bytes:
    """
    Two NRBF streams with made-up class names: ``Example.FileInfo`` and an
    ``Example.SettingList`` of ``Example.Setting`` objects (``Id``, ``Name``,
    ``Value``).
    """
    if settings is None:
        settings = [
            (1702, "Device number", 7),
            (5518, "Frequency setpoint 1", 50.0),
            (12200, "Inhibit emergency run", True),
            (7196, "Description", "Flex. limit 16"),
            (9999, "Nothing", None),
        ]
    w = NrbfWriter()
    # Stream 1
    w.header(1)
    w.library(2, "Example, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null")
    w.class_record(
        1,
        "Example.FileInfo",
        [
            ("Name", BT_STRING, None),
            ("Version", BT_PRIMITIVE, INT32),
            ("Created", BT_PRIMITIVE, DATETIME),
            ("Tags", BT_STRING_ARRAY, None),
        ],
        library_id=2,
    )
    w.string("easYgen-3200XT-P1")
    w.primitive(INT32, 3)
    w.primitive(DATETIME, 636000000000000000)  # 2016-06-03, kind unspecified
    w.string_array_ref(["alpha", "beta"])
    w.flush()
    w.end()
    # Stream 2
    w.header(1)
    w.library(2, "Example, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null")
    w.class_record(1, "Example.SettingList", [("Items", BT_OBJECT_ARRAY, None)], library_id=2)
    w.reference(2)
    w.array_single_object(2, len(settings))
    for number, name, value in settings:
        w.class_record(
            w.new_id(),
            "Example.Setting",
            [("Id", BT_PRIMITIVE, INT32), ("Name", BT_STRING, None), ("Value", BT_OBJECT, None)],
            library_id=2,
        )
        w.primitive(INT32, number)
        w.string(name)
        if value is None:
            w.null()
        elif isinstance(value, bool):
            w.primitive_typed(BOOLEAN, value)
        elif isinstance(value, int):
            w.primitive_typed(INT32, value)
        elif isinstance(value, float):
            w.primitive_typed(DOUBLE, value)
        else:
            w.string(str(value))
    w.end()
    return w.getvalue()


def build_generic_wset(header: bytes = WSET_HEADER, trailing: bytes = b"") -> bytes:
    """A ``.wset``-shaped file whose streams use unknown (non-Woodward) classes."""
    return header + build_generic_streams() + trailing


# ---------------------------------------------------------------------------
# Woodward settings fixture: the real ``Woodward.Settings``/``Woodward.Sid`` layout
# ---------------------------------------------------------------------------

LIB_SETTINGS: Final[int] = 2
LIB_SID: Final[int] = 3
LIB_DATA_ACCESS: Final[int] = 4

SETTINGS_LIBRARY: Final[str] = "Settings, Version=1.0.186.0, Culture=neutral, PublicKeyToken=null"
SID_LIBRARY: Final[str] = "Sid, Version=1.0.190.0, Culture=neutral, PublicKeyToken=null"
DATA_ACCESS_LIBRARY: Final[str] = (
    "DataAccess, Version=1.0.192.0, Culture=neutral, PublicKeyToken=null"
)

#: Default synthetic parameters: ``(delimited name, kind, value, extras)``
DEFAULT_PARAMETERS: Final[list[dict[str, Any]]] = [
    {
        "name": "PARAMETER.Configure system management.1702 Device number",
        "type": "integer",
        "value": "7",
        "initial": "1",
        "minimum": "1",
        "maximum": "32",
        "units": "",
        "write_level": 2,
    },
    {
        "name": "PARAMETER.Configure monitoring.Mains.4104 Monitoring",
        "type": "enumerated",
        "value": "Off",
        "initial": "On",
        "minimum": "0",
        "maximum": "1",
        "options": {"0": "Off", "1": "On"},
        "write_level": 2,
    },
    {
        "name": "PARAMETER.Configure system management.1700 Device name",
        "type": "string",
        "value": "Genset 7",
        "initial": "easYgen",
        "write_level": 1,
    },
    {
        "name": "Th2GenOverFreq",
        "type": "integer",
        "value": "1150",
        "initial": "1100",
        "minimum": "500",
        "maximum": "1400",
        "write_level": 2,
    },
]


def _write_settings_header(w: NrbfWriter, app_id: str, sid: str, notes: str = "") -> None:
    w.header(1)
    w.library(LIB_SETTINGS, SETTINGS_LIBRARY)
    w.library(LIB_SID, SID_LIBRARY)
    w.class_record(
        1,
        "Woodward.Settings.SettingsHeader",
        [
            ("_sidSpecification", BT_STRING, None),
            ("_sidIdentifier", BT_CLASS, ("Woodward.Sid.ApplicationIdentifier", LIB_SID)),
            ("_notes", BT_STRING, None),
            ("_applicationDescription", BT_STRING, None),
            ("_strictSpecificationCompatibility", BT_PRIMITIVE, BOOLEAN),
            ("_partialSettingsCreationAllowed", BT_PRIMITIVE, BOOLEAN),
            ("_isPartial", BT_PRIMITIVE, BOOLEAN),
            ("_loadMessage", BT_STRING, None),
            ("_showLoadMessageAsWarning", BT_PRIMITIVE, BOOLEAN),
        ],
        library_id=LIB_SETTINGS,
    )
    w.string(sid)
    w.class_record(
        w.new_id(),
        "Woodward.Sid.ApplicationIdentifier",
        [("_appIdString", BT_STRING, None), ("_fileExtension", BT_STRING, None)],
        library_id=LIB_SID,
    )
    w.string(app_id)
    w.string(".sid")
    w.string(notes)
    w.string(app_id)
    w.primitive(BOOLEAN, False)
    w.primitive(BOOLEAN, True)
    w.primitive(BOOLEAN, False)
    w.string("")
    w.primitive(BOOLEAN, True)
    w.end()


def _write_parameter_name(w: NrbfWriter, name: str) -> None:
    w.class_record(
        w.new_id(),
        "Woodward.Sid.Descriptors.ParameterName",
        [("_delimitedName", BT_STRING, None)],
        library_id=LIB_SID,
    )
    w.string(name)


def _write_text_value(w: NrbfWriter, text: str | None) -> None:
    if text is None:
        w.null()
        return
    w.class_record(
        w.new_id(),
        "Woodward.Sid.TextValue",
        [("value", BT_STRING_ARRAY, None), ("cultureInfo", BT_OBJECT, None)],
        library_id=LIB_SID,
    )
    w.string_array_ref([text])
    w.null()


def _write_range_limit(w: NrbfWriter, text: str | None) -> None:
    if text is None:
        w.null()
        return
    w.class_record(
        w.new_id(),
        "Woodward.Sid.Descriptors.RangeLimitDescriptor",
        [
            ("parameterName", BT_OBJECT, None),
            ("value", BT_CLASS, ("Woodward.Sid.TextValue", LIB_SID)),
            ("inclusive", BT_PRIMITIVE, BOOLEAN),
        ],
        library_id=LIB_SID,
    )
    w.null()
    _write_text_value(w, text)
    w.primitive(BOOLEAN, True)


def _write_data_type(w: NrbfWriter, param: dict[str, Any]) -> None:
    kind = param["type"]
    if kind == "integer":
        w.class_record(
            w.new_id(),
            "Woodward.Sid.Descriptors.IntegerDescriptor",
            [
                ("size", BT_PRIMITIVE, INT32),
                ("isSigned", BT_PRIMITIVE, BOOLEAN),
                ("maximumPercentageChange", BT_PRIMITIVE, INT32),
            ],
            library_id=LIB_SID,
        )
        w.primitive(INT32, 16)
        w.primitive(BOOLEAN, False)
        w.primitive(INT32, 10)
    elif kind == "enumerated":
        w.class_record(
            w.new_id(),
            "Woodward.Sid.Descriptors.EnumeratedIntegerDescriptor",
            [
                ("size", BT_PRIMITIVE, INT32),
                ("isSigned", BT_PRIMITIVE, BOOLEAN),
                ("maximumPercentageChange", BT_PRIMITIVE, INT32),
                (
                    "enumeration",
                    BT_CLASS,
                    ("Woodward.Sid.Descriptors.EnumerationDescriptor", LIB_SID),
                ),
            ],
            library_id=LIB_SID,
        )
        w.primitive(INT32, 16)
        w.primitive(BOOLEAN, False)
        w.primitive(INT32, 10)
        w.class_record(
            w.new_id(),
            "Woodward.Sid.Descriptors.EnumerationDescriptor",
            [
                ("name", BT_CLASS, ("Woodward.Sid.Descriptors.ParameterName", LIB_SID)),
                ("elements", BT_OBJECT_ARRAY, None),
                ("elseText", BT_STRING, None),
                ("Translations", BT_OBJECT, None),
            ],
            library_id=LIB_SID,
        )
        _write_parameter_name(w, "ENUM_SYNTHETIC")
        options = param["options"]
        elements_id = w.new_id()
        w.reference(elements_id)
        w.string("!!!")
        w.null()

        def _elements() -> None:
            w.array_single_object(elements_id, len(options))
            for value, name in options.items():
                w.class_record(
                    w.new_id(),
                    "Woodward.Sid.Descriptors.EnumerationDescriptor+EnumerationElement",
                    [("value", BT_PRIMITIVE, INT32), ("name", BT_STRING, None)],
                    library_id=LIB_SID,
                )
                w.primitive(INT32, int(value))
                w.string(name)

        w.defer(_elements)
    else:  # string
        w.class_record(
            w.new_id(),
            "Woodward.Sid.Descriptors.StringDescriptor",
            [
                ("maxSize", BT_PRIMITIVE, INT32),
                ("nullTerminated", BT_PRIMITIVE, BOOLEAN),
                ("encoding", BT_OBJECT, None),
            ],
            library_id=LIB_SID,
        )
        w.primitive(INT32, 49)
        w.primitive(BOOLEAN, True)
        w.null()


def _write_descriptor(w: NrbfWriter, param: dict[str, Any], object_id: int) -> None:
    w.class_record(
        object_id,
        "Woodward.Sid.Descriptors.ParameterDescriptor",
        [
            ("name", BT_CLASS, ("Woodward.Sid.Descriptors.ParameterName", LIB_SID)),
            (
                "communicationProperties",
                BT_CLASS,
                ("Woodward.Sid.Descriptors.CommunicationProperties", LIB_SID),
            ),
            ("address", BT_OBJECT, None),
            ("access", BT_CLASS, ("Woodward.Sid.AccessType", LIB_SID)),
            ("dataTypeDescriptor", BT_OBJECT, None),
            ("readSecurityLevel", BT_PRIMITIVE, INT32),
            ("writeSecurityLevel", BT_PRIMITIVE, INT32),
            ("initialValue", BT_OBJECT, None),
            ("minimum", BT_OBJECT, None),
            ("maximum", BT_OBJECT, None),
            ("units", BT_STRING, None),
            ("description", BT_OBJECT, None),
            ("nonVolatileGroupId", BT_PRIMITIVE, INT32),
            ("expressionDescriptor", BT_OBJECT, None),
        ],
        library_id=LIB_SID,
    )
    _write_parameter_name(w, param["name"])
    w.class_record(
        w.new_id(),
        "Woodward.Sid.Descriptors.CommunicationProperties",
        [
            ("servlinkHandle", BT_PRIMITIVE, UINT32),
            ("canOpenMultiplexor", BT_OBJECT, None),
            ("xcpAddress", BT_OBJECT, None),
        ],
        library_id=LIB_SID,
    )
    w.primitive(UINT32, param.get("servlink_handle", 2215642790))
    w.null()
    w.null()
    w.null()  # address
    w.class_record(
        w.new_id(),
        "Woodward.Sid.AccessType",
        [("value__", BT_PRIMITIVE, INT32)],
        library_id=LIB_SID,
    )
    w.primitive(INT32, 1)
    _write_data_type(w, param)
    w.primitive(INT32, 0)
    w.primitive(INT32, param.get("write_level", 2))
    _write_text_value(w, param.get("initial"))
    _write_range_limit(w, param.get("minimum"))
    _write_range_limit(w, param.get("maximum"))
    w.string(param.get("units", ""))
    w.null()
    w.primitive(INT32, 0)
    w.null()


def _write_basic_parameter(w: NrbfWriter, param: dict[str, Any]) -> None:
    descriptor_id = w.new_id()
    w.class_record(
        w.new_id(),
        "Woodward.DataAccess.BasicParameter",
        [
            (
                "parameterValueCache",
                BT_CLASS,
                ("Woodward.Settings.BasicParameterValueCache", LIB_SETTINGS),
            ),
            ("descriptor", BT_CLASS, ("Woodward.Sid.Descriptors.ParameterDescriptor", LIB_SID)),
        ],
        library_id=LIB_DATA_ACCESS,
    )
    w.class_record(
        w.new_id(),
        "Woodward.Settings.BasicParameterValueCache",
        [
            ("descriptor", BT_CLASS, ("Woodward.Sid.Descriptors.ParameterDescriptor", LIB_SID)),
            ("value", BT_STRING, None),
        ],
        library_id=LIB_SETTINGS,
    )
    _write_descriptor(w, param, descriptor_id)
    w.string(param["value"])
    w.reference(descriptor_id)


def _write_settings_table(w: NrbfWriter, parameters: list[dict[str, Any]]) -> None:
    w.header(1)
    w.library(LIB_SETTINGS, SETTINGS_LIBRARY)
    w.library(LIB_SID, SID_LIBRARY)
    w.library(LIB_DATA_ACCESS, DATA_ACCESS_LIBRARY)
    w.class_record(
        1,
        "System.Collections.Hashtable",
        [
            ("LoadFactor", BT_PRIMITIVE, SINGLE),
            ("Version", BT_PRIMITIVE, INT32),
            ("Comparer", BT_OBJECT, None),
            ("HashCodeProvider", BT_OBJECT, None),
            ("HashSize", BT_PRIMITIVE, INT32),
            ("Keys", BT_OBJECT_ARRAY, None),
            ("Values", BT_OBJECT_ARRAY, None),
        ],
    )
    w.primitive(SINGLE, 0.72)
    w.primitive(INT32, len(parameters))
    w.null()
    w.null()
    w.primitive(INT32, 11)
    w.reference(2)
    w.reference(3)
    w.array_single_object(2, len(parameters))
    for param in parameters:
        _write_parameter_name(w, param["name"])
    w.array_single_object(3, len(parameters))
    for param in parameters:
        _write_basic_parameter(w, param)
    # Referenced arrays (TextValue strings, enumeration elements) must follow the
    # array they're referenced from, not be interleaved with its elements
    w.flush()
    w.end()


def build_woodward_wset(
    app_id: str = "EG3200XTP1 2.12-0_50976",
    sid: str | None = None,
    parameters: list[dict[str, Any]] | None = None,
    header: bytes = WSET_HEADER,
    notes: str = "",
) -> bytes:
    """
    A synthetic ``.wset`` file using the real ``Woodward.Settings`` object layout
    (settings header stream and a parameter hashtable stream).
    """
    w = NrbfWriter()
    _write_settings_header(w, app_id, sid if sid is not None else app_id, notes)
    _write_settings_table(w, parameters if parameters is not None else DEFAULT_PARAMETERS)
    return header + w.getvalue()


# ---------------------------------------------------------------------------
# Woodward tool file fixture
# ---------------------------------------------------------------------------


def _write_localized_string(w: NrbfWriter, text: str, index: str = "") -> None:
    w.class_record(
        w.new_id(),
        "Woodward.Localize.LocalizedString",
        [("defaultText", BT_STRING, None), ("localizationIndex", BT_STRING, None)],
        library_id=3,
    )
    w.string(text)
    w.string(index)


def build_woodward_wtool(
    name: str = "EG3000XT",
    sid_specifications: tuple[str, ...] = ("EG3200XTP1 2.10-1_49670", "EG3200XTP1 2.12-0_50976"),
    device_names: tuple[str, ...] = ("ToolConfigurator",),
    header: bytes = WTOOL_HEADER,
) -> bytes:
    """A synthetic ``.wtool`` file: tool properties stream and a small tool document stream."""
    w = NrbfWriter()
    w.header(1)
    w.library(2, "ToolKit, Version=7.0.359.1, Culture=neutral, PublicKeyToken=null")
    w.library(3, "Localize, Version=1.0.61.0, Culture=neutral, PublicKeyToken=null")
    w.class_record(
        1,
        "Woodward.ToolKit.Tool.ToolProperties",
        [
            ("name", BT_CLASS, ("Woodward.Localize.LocalizedString", 3)),
            ("version", BT_CLASS, ("Woodward.Localize.LocalizedString", 3)),
            ("description", BT_CLASS, ("Woodward.Localize.LocalizedString", 3)),
            ("helpFileName", BT_OBJECT, None),
            ("hideHomePage", BT_PRIMITIVE, BOOLEAN),
            ("localizationAddInName", BT_STRING, None),
            ("layoutVersion", BT_PRIMITIVE, INT32),
        ],
        library_id=2,
    )
    _write_localized_string(w, name, "41875")
    _write_localized_string(w, "1.0")
    _write_localized_string(w, "Synthetic tool file")
    w.null()
    w.primitive(BOOLEAN, True)
    w.string("ToolkitLocalization1.1_48925.dll")
    w.primitive(INT32, 0)
    w.end()

    w.header(1)
    w.library(2, "ToolKit, Version=7.0.359.1, Culture=neutral, PublicKeyToken=null")
    w.library(3, "Localize, Version=1.0.61.0, Culture=neutral, PublicKeyToken=null")
    w.library(4, "DataAccess, Version=1.0.236.0, Culture=neutral, PublicKeyToken=null")
    w.class_record(
        1,
        "Woodward.ToolKit.Tool.ToolDocument",
        [
            ("contentGraph", BT_OBJECT, None),
            ("toolHomePage", BT_OBJECT, None),
            ("deviceNames", BT_CLASS, ("Woodward.DataAccess.DeviceNamesList", 4)),
            ("sidSpecifications", BT_STRING_ARRAY, None),
        ],
        library_id=2,
    )
    w.null()
    w.null()
    w.class_record(
        w.new_id(),
        "Woodward.DataAccess.DeviceNamesList",
        [("_items", BT_OBJECT_ARRAY, None), ("_size", BT_PRIMITIVE, INT32)],
        library_id=4,
    )
    items_id = w.new_id()
    w.reference(items_id)
    w.primitive(INT32, len(device_names))
    w.string_array_ref(list(sid_specifications))
    w.array_single_object(items_id, len(device_names))
    for device_name in device_names:
        w.class_record(
            w.new_id(),
            "Woodward.DataAccess.DeviceName",
            [("name", BT_CLASS, ("Woodward.Localize.LocalizedString", 3))],
            library_id=4,
        )
        _write_localized_string(w, device_name)
    w.flush()
    w.end()
    return header + w.getvalue()


# ---------------------------------------------------------------------------
# SID fixture
# ---------------------------------------------------------------------------

SYNTHETIC_SID_XML: Final[str] = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<ServiceInterfaceDefinition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="Sid21.xsd" Identifier="{identifier}" IdentifierAddress="974848" Specification="{identifier}" ApplicationDescription="{identifier}" IsMostSignificantByteFirst="true">
\t<NonVolatileProtocol Type="ServlinkSaveValues" />
\t<SecurityProtocols>
\t\t<Servlink>
\t\t\t<Accounts>
\t\t\t\t<Account Name="service" Level="3" />
\t\t\t</Accounts>
\t\t\t<CommandSecurityLevels>
\t\t\t\t<Command Name="Browse" Level="2" />
\t\t\t\t<Command Name="Save Values" Level="5" />
\t\t\t</CommandSecurityLevels>
\t\t</Servlink>
\t</SecurityProtocols>
\t<SettingsPolicies AllowPartial="true" />
\t<Enumeration Name="ENUM_LOGLIST1.LOGICLIST1" Else="!!!">
\t\t<Element Name="00.01 LM: Flag 1" Value="0" />
\t\t<Element Name="02.01 LM FALSE" Value="201" />
\t</Enumeration>
\t<Enumeration Name="ENUM_4104" Else="!!!">
\t\t<Element Name="Off" Value="0" />
\t\t<Element Name="On" Value="1" />
\t</Enumeration>
\t<Structure Name="AnalogManagerType1">
\t\t<Field Name="Analog1">
\t\t\t<Integer Size="16" IsSigned="false" Enumeration="ENUM_LOGLIST1.LOGICLIST1" />
\t\t</Field>
\t\t<Field Name="Constant1">
\t\t\t<Float Precision="Single" />
\t\t</Field>
\t</Structure>
\t<Namespace Name="STATUS MENU">
\t\t<Namespace Name="Diagnostic">
\t\t\t<DataItem Name="12791 Device name">
\t\t\t\t<String MaximumSize="39" Encoding="UTF-8" />
\t\t\t\t<CommunicationProperties>
\t\t\t\t\t<Servlink Handle="3494916599" />
\t\t\t\t\t<CANopen Multiplexor="5371649" />
\t\t\t\t</CommunicationProperties>
\t\t\t</DataItem>
\t\t\t<DataItem Name="10287 Diff.out/inlet temp.">
\t\t\t\t<Float Precision="Single" />
\t\t\t\t<CommunicationProperties>
\t\t\t\t\t<Servlink Handle="3260033071" />
\t\t\t\t</CommunicationProperties>
\t\t\t\t<Units>°C</Units>
\t\t\t\t<Minimum><Constant>-32768</Constant></Minimum>
\t\t\t\t<Maximum><Constant>32767</Constant></Maximum>
\t\t\t</DataItem>
\t\t</Namespace>
\t</Namespace>
\t<Namespace Name="PARAMETER">
\t\t<Namespace Name="Configure system management">
\t\t\t<DataItem Name="1702 Device number" Access="ReadWrite" Address="960212">
\t\t\t\t<Integer Size="32" />
\t\t\t\t<CommunicationProperties>
\t\t\t\t\t<Servlink Handle="2756708006" />
\t\t\t\t\t<CANopen Multiplexor="2532865" />
\t\t\t\t</CommunicationProperties>
\t\t\t\t<InitialValue>1</InitialValue>
\t\t\t\t<Minimum><Constant>1</Constant></Minimum>
\t\t\t\t<Maximum><Constant>32</Constant></Maximum>
\t\t\t\t<Security Operation="Write" Level="2" />
\t\t\t</DataItem>
\t\t\t<DataItem Name="4104 Monitoring" Access="ReadWrite" Address="960300">
\t\t\t\t<Boolean Enumeration="ENUM_4104" Size="8" />
\t\t\t\t<CommunicationProperties>
\t\t\t\t\t<Servlink Handle="2756708007" />
\t\t\t\t</CommunicationProperties>
\t\t\t\t<InitialValue>1</InitialValue>
\t\t\t\t<Security Operation="Write" Level="2" />
\t\t\t\t<Security Operation="Read" Level="1" />
\t\t\t</DataItem>
\t\t\t<DataItem Name="15395 J1939 DM1 Lamp state">
\t\t\t\t<BitFields Size="32">
\t\t\t\t\t<Field Name="DM1 Protection lamp" Position="0" Size="4" Enumeration="ENUM_4104" />
\t\t\t\t\t<Field Name="DM1 Amber warning lamp" Position="4" Size="4" />
\t\t\t\t</BitFields>
\t\t\t\t<Units>hex</Units>
\t\t\t</DataItem>
\t\t\t<LogicManager Name="12922 Ext. mns.decoupl." InEnum1="ENUM_LOGLIST1.LOGICLIST1" InEnum2="ENUM_LOGLIST1.LOGICLIST1" InEnum3="ENUM_LOGLIST1.LOGICLIST1" DelayOnText="Delay ON" DelayOffText="Delay OFF" DelayUnits="s">
\t\t\t\t<CommunicationProperties>
\t\t\t\t\t<Servlink Handle="2320511610" />
\t\t\t\t</CommunicationProperties>
\t\t\t\t<Security Operation="Write" Level="2" />
\t\t\t\t<InitialValue>0 0 False And True And True 201 201 0</InitialValue>
\t\t\t</LogicManager>
\t\t\t<StructureItem Name="5780 AM Ext.mains act.pwr" Structure="AnalogManagerType1" Access="ReadWrite">
\t\t\t\t<CommunicationProperties>
\t\t\t\t\t<Servlink Handle="2320504468" />
\t\t\t\t</CommunicationProperties>
\t\t\t\t<InitialValue>601 1001 201 201 0 5 0</InitialValue>
\t\t\t\t<Security Operation="Write" Level="2" />
\t\t\t</StructureItem>
\t\t</Namespace>
\t</Namespace>
\t<Event Identifier="2112">
\t\t<Constant>Overspeed 1</Constant>
\t</Event>
</ServiceInterfaceDefinition>
"""


def build_sid_xml(identifier: str = "EG3200XTP1 2.12-0_50976") -> bytes:
    """A small synthetic SID XML document."""
    return SYNTHETIC_SID_XML.format(identifier=identifier).encode("utf-8")


def build_sid_file(
    identifier: str = "EG3200XTP1 2.12-0_50976", header: bytes = SID_HEADER
) -> bytes:
    """A synthetic compressed ``.sid`` file (ToolKit container header + gzip XML)."""
    import gzip

    return header + gzip.compress(build_sid_xml(identifier), mtime=0)
