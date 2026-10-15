"""
Conversion of the graphical IEC 61131-3 languages in Unity Pro/Control Expert
XEF files (FBD, LD and SFC) to TC6 XML.

Unity places the objects of FBD, LD and SFC sections on a grid. The
conversion keeps the layout, scaled by :data:`GRID`, since the order of
objects in the generated Structured Text depends on their positions.

FBD (``FBDSource``)
    Each function or function block (``FFBBlock``) becomes a TC6 ``block``.
    Variables and literals bound to pins (``effectiveParameter``) become
    ``inVariable`` and ``outVariable`` objects, and links between pins
    (``linkFB``) become connections.

LD (``LDSource``)
    Each row of the network (``typeLine``) lists its cells from left to right.
    Contacts and coils take one cell, function blocks two (their pins are on
    the rows below them), and horizontal links any number of cells. A vertical
    link (``VLink``) connects the right edge of its cell to the same edge on
    the next row. The cell edges that are connected by links are combined to
    find what each object's input is connected to. Objects connected to the
    same edge are ORed together.

SFC (``SFCProgram``)
    Steps, transitions and jumps are connected when they're above one another
    in a column, by alternative and parallel branches and joints, and by
    explicit links (``linkSFC``). Macro steps are replaced by the steps of
    their macro section. Action sections become actions of the POU, and
    transition sections in Structured Text become inline conditions.

Unity library blocks that aren't IEC 61131-3 standard blocks are mapped to
equivalent standard blocks where possible (see :class:`BlockLibrary`).
The other library blocks become function blocks with the same interface
and an empty body ("stubs"), since their implementation isn't in the XEF.

Authors

- Christopher Goes
"""

from __future__ import annotations

import itertools
import re
import unicodedata
from dataclasses import dataclass, field
from xml.etree.ElementTree import Element, SubElement

from peat import log
from peat.parsing.plc_open.core_modules.structures import StdBlckDct

# TC6 position units per Unity grid cell
GRID = 20

# MatIEC rejects a POU without any statements or variables, so these get a
# placeholder statement that sets this variable.
PLACEHOLDER_VAR = "PEAT_NO_ST_LOGIC"

# Unity elementary types, which may be the suffix of a typed block name, e.g. ADD_REAL
ELEMENTARY_TYPES: frozenset[str] = frozenset(
    [
        "BOOL", "EBOOL", "BYTE", "WORD", "DWORD", "LWORD", "SINT", "INT", "DINT", "LINT",
        "USINT", "UINT", "UDINT", "ULINT", "REAL", "LREAL", "TIME", "DATE", "TOD", "DT",
        "STRING",
    ]
)  # fmt: skip

# IEC 61131-3 standard blocks. The "additional" blocks of the TC6 to Structured
# Text converter (e.g. PID and RAMP) have different interfaces than the Unity
# blocks with the same names.
STANDARD_BLOCKS: frozenset[str] = frozenset(
    name
    for name, infos in StdBlckDct.items()
    if any(section != "Additional function blocks" for section, _ in infos)
)

# Names a POU can't have, in lowercase. MatIEC, which OpenPLC uses to compile
# Structured Text, fails to compile its standard library if a POU has the name
# of one of its blocks, or of a variable in one of them (e.g. S1 or Q).
RESERVED_NAMES: frozenset[str] = frozenset(
    name.lower()
    for name in [
        *StdBlckDct,
        *ELEMENTARY_TYPES,
        # Blocks in the OpenPLC and MatIEC libraries
        "CTD_DINT", "CTD_LINT", "CTD_UDINT", "CTD_ULINT", "CTUD_DINT", "CTUD_LINT",
        "CTUD_UDINT", "CTUD_ULINT", "CTU_DINT", "CTU_LINT", "CTU_UDINT", "CTU_ULINT",
        "ROTARY_SWITCH", "SEMA", "TCP_CLOSE", "TCP_CONNECT", "TCP_RECEIVE", "TCP_SEND",
        "SM_16DIN", "SM_16RELAY", "SM_4REL4IN", "SM_8DIN", "SM_8MOSFET", "SM_8RELAY",
        "SM_BAS", "SM_HOME", "SM_INDUSTRIAL", "SM_RTD",
        # Variables of the blocks in the OpenPLC and MatIEC libraries
        "AUTO", "BUSY", "BUTTON", "CD", "CDT", "CD_T", "CLAIM", "CLK", "CLOSE", "CONNECT",
        "CU", "CURRENT_TIME", "CU_T", "CV", "CYCLE", "DTERM", "DUMMY", "ERROR", "ET",
        "IN", "IN1", "IN2", "ITERM", "KP", "LD", "MSG", "OFFSET", "OUT", "PDT", "PORT",
        "PREV_IN", "PT", "PV", "Q", "Q1", "QD", "QU", "Q_INTERNAL", "R", "R1", "READ",
        "RECEIVE", "RELEASE", "RUN", "S", "S1", "SEND", "SP", "STACK", "START_TIME",
        "STATE", "SUCCESS", "T", "TD", "TR", "UDP", "X0", "X1", "XIN", "XOUT",
        # Keywords
        "ACTION", "AND", "ARRAY", "AT", "BY", "CASE", "CONFIGURATION", "CONSTANT", "DO",
        "ELSE", "ELSIF", "END", "EXIT", "FALSE", "FOR", "FROM", "FUNCTION",
        "FUNCTION_BLOCK", "IF", "INITIAL_STEP", "MOD", "NOT", "OF", "ON", "OR",
        "PRIORITY", "PROGRAM", "REPEAT", "RESOURCE", "RETAIN", "RETURN", "STEP",
        "STRUCT", "TASK", "THEN", "TO", "TRANSITION", "TRUE", "TYPE", "UNTIL", "VAR",
        "WHILE", "WITH", "XOR",
    ]
)  # fmt: skip

# Unity direct (unnamed) variables, e.g. %M10, %MW3, %I0.1.2 or %QW0.4.4
DIRECT_ADDRESS_RE = re.compile(
    r"%(?P<area>[IQMKS])(?P<size>[XBWDF]?)(?P<num>\d+(?:\.\d+)*)(?![\w.])", re.IGNORECASE
)

# Comments, strings and direct variables in Structured Text or IL
_ST_TOKEN_RE = re.compile(
    r"(?P<comment>\(\*.*?\*\))|(?P<string>'(?:\$.|[^'])*')|(?P<address>"
    + DIRECT_ADDRESS_RE.pattern
    + r")|(?P<ident>[A-Za-z_]\w*)",
    re.IGNORECASE | re.DOTALL,
)

# SFC action qualifiers. Unity uses NONE for N.
ACTION_QUALIFIERS: frozenset[str] = frozenset(
    ["N", "R", "S", "L", "D", "P", "P0", "P1", "SD", "DS", "SL", "DL"]
)

# LD contact and coil types
CONTACT_TYPES: dict[str, dict[str, str]] = {
    "openContact": {},
    "closedContact": {"negated": "true"},
    "PContact": {"edge": "rising"},
    "NContact": {"edge": "falling"},
}
COIL_TYPES: dict[str, dict[str, str]] = {
    "coil": {},
    "notCoil": {"negated": "true"},
    "setCoil": {"storage": "set"},
    "resetCoil": {"storage": "reset"},
    "PCoil": {"edge": "rising"},
    "NCoil": {"edge": "falling"},
}

# A source of a connection: the local ID of an object, and its output pin, if any
Source = tuple[str, str | None]


def sanitize_name(name: str) -> str:
    """Make a name a valid IEC 61131-3 identifier, which can only have ASCII characters."""
    # Remove accents, e.g. Séquence becomes Sequence
    name = unicodedata.normalize("NFKD", name.strip()).encode("ascii", "ignore").decode()
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not name or name[0].isdigit():
        name = f"S_{name}"
    return name


def unique_name(name: str, taken: set[str], suffix: str) -> str:
    """
    A POU name that isn't reserved and isn't in a set of names already taken.
    The name is added to the set.

    Args:
        name: Name to use if possible
        taken: Lowercase names that are already used
        suffix: Suffix to add to the name if it's reserved or taken, e.g. ``_SECTION``
    """
    base = sanitize_name(name)
    candidate = base
    i = 1
    while candidate.lower() in taken or candidate.lower() in RESERVED_NAMES:
        candidate = f"{base}{suffix}{i if i > 1 else ''}"
        i += 1
    taken.add(candidate.lower())
    return candidate


def direct_address_type(address: str) -> str:
    """IEC 61131-3 type of a Unity direct variable, e.g. INT for %MW10."""
    m = DIRECT_ADDRESS_RE.fullmatch(address)
    if not m:
        return ""

    area = m.group("area").upper()
    size = m.group("size").upper()
    if size in ["", "X"]:
        return "BOOL"
    # A bit of a word, e.g. %MW10.3. The dots of %I and %Q are the module topology.
    if area in "MKS" and "." in m.group("num"):
        return "BOOL"
    return {"B": "BYTE", "W": "INT", "D": "DINT", "F": "REAL"}[size]


def literal_type(text: str) -> str:
    """IEC 61131-3 type of a literal, or an empty string if it's not a literal."""
    text = text.strip()
    upper = text.upper()
    if upper in ["TRUE", "FALSE"]:
        return "BOOL"
    if re.fullmatch(r"[+-]?\d+\.\d*(E[+-]?\d+)?", upper):
        return "REAL"
    if re.fullmatch(r"[+-]?\d+", upper) or re.fullmatch(r"(2|8|16)#[0-9A-F_]+", upper):
        return "INT"
    if re.fullmatch(r"(T|TIME)#.+", upper):
        return "TIME"
    if text.startswith("'"):
        return "STRING"
    if "#" in upper:
        prefix = upper.split("#", 1)[0]
        if prefix in ELEMENTARY_TYPES:
            return "BOOL" if prefix == "EBOOL" else prefix
    return ""


def st_identifiers(text: str) -> set[str]:
    """Lowercase identifiers in Structured Text or IL, ignoring comments and strings."""
    names = set()
    for m in _ST_TOKEN_RE.finditer(text):
        if m.group("ident"):
            names.add(m.group("ident").lower())
    return names


def st_has_statements(text: str) -> bool:
    """If Structured Text or IL has any code, not only comments and whitespace."""
    return bool(re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL).strip())


# --------------------------------------------------------------------------
# Block library
# --------------------------------------------------------------------------


@dataclass
class BlockSpec:
    """How a Unity function or function block is converted to a TC6 block."""

    #: Name of the TC6 block type
    type_name: str
    #: "function" or "functionBlock"
    kind: str
    #: Unity pin names that are renamed for the TC6 block
    renames: dict[str, str] = field(default_factory=dict)
    #: Set or reset coil, for the Unity SET and RESET functions
    coil_storage: str = ""
    #: If the block needs an instance created for it, e.g. when a
    #: Unity function becomes a function block
    auto_instance: bool = False


@dataclass
class StubType:
    """Interface of a Unity library block that becomes a stub function block."""

    name: str
    inputs: dict[str, str] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    in_outs: dict[str, str] = field(default_factory=dict)
    comment: str = ""


# Function blocks generated with a working body, for Unity functions that
# have no IEC 61131-3 equivalent.
HELPER_BLOCKS: dict[str, tuple[dict, dict, str]] = {
    "WORD_TO_BIT": (
        {"IN": "WORD"},
        {f"BIT{i}": "BOOL" for i in range(16)},
        "\n".join(f"BIT{i} := (IN AND 16#{1 << i:04X}) <> 0;" for i in range(16)),
    ),
    "BIT_TO_WORD": (
        {f"BIT{i}": "BOOL" for i in range(16)},
        {"OUT": "WORD"},
        "OUT := " + " OR\n  ".join(f"SHL(BOOL_TO_WORD(BIT{i}), {i})" for i in range(16)) + ";",
    ),
}


# Bodies of Unity library blocks that are simple enough to implement
STUB_BODIES: dict[str, str] = {
    "INC": "INOUT := INOUT + 1;\n",
    "DEC": "INOUT := INOUT - 1;\n",
}


class BlockLibrary:
    """
    Maps Unity block types to TC6 block types.

    In order:

    - User-defined function blocks (DFBs) and IEC 61131-3 standard blocks are
      used as is.
    - Unity blocks with a standard equivalent are mapped to it, e.g. RE to
      R_TRIG, S_SR to SR, and typed variants such as ADD_REAL or CTU_UINT to
      ADD and CTU.
    - SET and RESET become set and reset coils.
    - WORD_TO_BIT and BIT_TO_WORD become generated function blocks.
    - Any other block becomes a stub function block, with the interface from
      the XEF (``EFSource``/``EFBSource``) or from how the block is used.
    """

    def __init__(
        self,
        dfb_names: set[str],
        library_types: dict[str, dict],
        variable_names: set[str] = frozenset(),
    ) -> None:
        """
        Args:
            dfb_names: Names of the user-defined function blocks (DFBs)
            library_types: Interfaces of Unity library blocks, from the
                ``EFSource`` and ``EFBSource`` elements of the XEF
            variable_names: Names of all the variables in the project. MatIEC
                can't compile a variable with the name of a POU.
        """
        #: Names taken by POUs and variables, in lowercase
        self.taken: set[str] = {name.lower() for name in variable_names}
        #: TC6 name of each DFB, by lowercase Unity name
        self.dfbs = {name.lower(): unique_name(name, self.taken, "_DFB") for name in dfb_names}
        self.library_types = {name.upper(): info for name, info in library_types.items()}
        self.stubs: dict[str, StubType] = {}
        self.helpers: set[str] = set()
        self._cache: dict[str, BlockSpec] = {}

    def resolve(self, type_name: str) -> BlockSpec:
        """How a Unity block type is converted to a TC6 block type."""
        key = type_name.upper()
        if key not in self._cache:
            self._cache[key] = self._resolve(type_name)
        return self._cache[key]

    def _resolve(self, type_name: str) -> BlockSpec:
        if type_name.lower() in self.dfbs:
            return BlockSpec(self.dfbs[type_name.lower()], "functionBlock")

        spec = self._standard(type_name.upper())
        if spec:
            return spec

        # A stub function block. Functions need an instance of it.
        stub = self._stub(type_name)
        is_fb = self.library_types.get(type_name.upper(), {}).get("kind") == "EFB"
        return BlockSpec(stub.name, "functionBlock", auto_instance=not is_fb)

    def _standard(self, name: str) -> BlockSpec | None:
        """Standard IEC 61131-3 block equivalent to a Unity block, if there is one."""
        if name in STANDARD_BLOCKS:
            return BlockSpec(name, StdBlckDct[name][0][1]["type"])
        if name in ["RE", "FE"]:
            trigger = "R_TRIG" if name == "RE" else "F_TRIG"
            return BlockSpec(
                trigger, "functionBlock", {"IN": "CLK", "OUT": "Q"}, auto_instance=True
            )
        if name in ["SET", "RESET"]:
            return BlockSpec(name, "coil", coil_storage=name.lower())
        if name.startswith("WRITE_INPUT_"):
            # Simulation blocks that write a value to an input
            return BlockSpec("MOVE", "function", {"INP": "IN", "OUTP": "OUT"})
        if name in HELPER_BLOCKS:
            self.helpers.add(name)
            return BlockSpec(name, "functionBlock", auto_instance=True)
        if name.startswith("S_") and len(name) > 2:
            # Safety variants of standard blocks, e.g. S_AND_BOOL or S_SR
            return self._standard(name[2:])

        # Typed variants of standard blocks, e.g. ADD_REAL, CTU_UINT or EXPT_REAL_REAL
        parts = name.split("_")
        for i in range(len(parts) - 1, 0, -1):
            base = "_".join(parts[:i])
            if base in STANDARD_BLOCKS and all(p in ELEMENTARY_TYPES for p in parts[i:]):
                return BlockSpec(base, StdBlckDct[base][0][1]["type"])
        return None

    def _stub(self, type_name: str) -> StubType:
        key = type_name.upper()
        if key not in self.stubs:
            stub = StubType(unique_name(type_name, self.taken, "_UNITY"))
            info = self.library_types.get(key)
            if info:
                stub.comment = info.get("comment", "")
                stub.inputs.update(info.get("inputs", {}))
                stub.outputs.update(info.get("outputs", {}))
                stub.in_outs.update(info.get("in_outs", {}))
            self.stubs[key] = stub
            log.warning(
                f"Unity block type '{type_name}' has no IEC 61131-3 equivalent, "
                f"it will be a function block with an empty body"
            )
        return self.stubs[key]

    def variable_type(self, type_name: str) -> str:
        """
        Type to declare variables of a Unity function block type with,
        or an empty string if the type isn't a block type.
        """
        key = type_name.upper()
        if type_name.lower() in self.dfbs:
            return self.dfbs[type_name.lower()]
        if key in STANDARD_BLOCKS:
            return key if StdBlckDct[key][0][1]["type"] == "functionBlock" else ""
        spec = self._standard(key)
        if spec and spec.kind == "functionBlock":
            return spec.type_name
        if self.library_types.get(key, {}).get("kind") == "EFB" or key in self.stubs:
            return self.resolve(type_name).type_name
        return ""

    def note_pin(self, type_name: str, pin: str, direction: str, pin_type: str) -> None:
        """Record a pin of a stub block and its type, from where the block is used."""
        stub = self.stubs.get(type_name.upper())
        if stub is None or pin in ["EN", "ENO"]:
            return

        other = stub.outputs if direction == "inputs" else stub.inputs
        if pin in other:
            # A pin that is both an input and an output is an in/out
            stub.in_outs[pin] = other.pop(pin)
        pins = stub.in_outs if pin in stub.in_outs else getattr(stub, direction)
        current = pins.get(pin, "")
        if not current or current.startswith("ANY"):
            pins[pin] = pin_type or current

    def pin_type(self, spec: BlockSpec, pin: str) -> str:
        """Type of a pin of a block, if it's known and not generic."""
        if spec.type_name.upper() in self.stubs:
            stub = self.stubs[spec.type_name.upper()]
            for pins in [stub.inputs, stub.outputs, stub.in_outs]:
                if pins.get(pin, "ANY")[:3] != "ANY":
                    return pins[pin]
            return ""
        for _, info in StdBlckDct.get(spec.type_name, [])[:1]:
            for name, var_type, _modifier in info["inputs"] + info["outputs"]:
                if name == pin and not var_type.startswith("ANY"):
                    return var_type
        return ""

    def add_pous(self, tc6, add_variable) -> None:
        """
        Add the stub and helper function blocks to a TC6 project.

        Args:
            tc6: TC6 project
            add_variable: Function that adds a variable to a variable list,
                with the arguments ``(var_list, name, type)``
        """
        for name in sorted(self.helpers):
            # Helper names aren't reserved, and Unity names them like this
            inputs, outputs, body = HELPER_BLOCKS[name]
            pou = tc6.make_pou(name, pou_type="functionBlock")
            _add_interface(pou, add_variable, inputs, outputs, {})
            tc6.add_st_content_to_pou(pou, body.encode("utf-8"))

        for stub in self.stubs.values():
            pou = tc6.make_pou(stub.name, pou_type="functionBlock")
            _add_interface(
                pou,
                add_variable,
                {n: _concrete_type(t) for n, t in stub.inputs.items()},
                {n: _concrete_type(t) for n, t in stub.outputs.items()},
                {n: _concrete_type(t) for n, t in stub.in_outs.items()},
            )
            if stub.name in STUB_BODIES and "INOUT" in stub.in_outs:
                tc6.add_st_content_to_pou(pou, STUB_BODIES[stub.name].encode())
                continue
            local_vars = SubElement(pou.find("interface"), "localVars")
            add_variable(local_vars, PLACEHOLDER_VAR, "BOOL")
            comment = f" {stub.comment}" if stub.comment else ""
            tc6.add_st_content_to_pou(
                pou,
                (
                    f"(* Unity library block{comment}. Its implementation "
                    f"isn't in the XEF, so it does nothing. *)\n{PLACEHOLDER_VAR} := TRUE;\n"
                ).encode(),
            )


def _concrete_type(type_name: str) -> str:
    """A concrete type for a pin with a generic (ANY_*) or unknown type."""
    upper = (type_name or "").upper()
    if upper == "EBOOL":
        return "BOOL"
    if upper in ["ANY_NUM", "ANY_REAL", "ANY_MAGNITUDE"]:
        return "REAL"
    if upper == "ANY_INT":
        return "INT"
    if not upper or upper.startswith("ANY") or upper not in ELEMENTARY_TYPES:
        return "BOOL" if not upper or upper.startswith("ANY") else type_name
    return upper


def _add_interface(pou: Element, add_variable, inputs, outputs, in_outs) -> None:
    interface = pou.find("interface")
    for tag, pins in [("inputVars", inputs), ("outputVars", outputs), ("inOutVars", in_outs)]:
        if pins:
            var_list = SubElement(interface, tag)
            for name, var_type in pins.items():
                # Unity types that aren't in the XEF, e.g. ADDM_TYPE, become BOOL
                if not add_variable(var_list, name, var_type):
                    add_variable(var_list, name, "BOOL")


# --------------------------------------------------------------------------
# Conversion context
# --------------------------------------------------------------------------


class ProjectContext:
    """State shared by the conversion of all the sections of a project."""

    def __init__(
        self,
        variables: dict[str, dict],
        library: BlockLibrary,
        allow_direct_variables: bool = True,
    ) -> None:
        """
        Args:
            variables: Variables the sections can use, keyed by name. Direct
                variables used by the sections are added to this.
            library: Block library
            allow_direct_variables: If direct variables (e.g. ``%MW10``) are
                replaced by variables. DFBs can't use direct variables.
        """
        self.variables = variables
        self.library = library
        self.allow_direct_variables = allow_direct_variables
        self.names = {name.lower(): name for name in variables}
        self.address_names: dict[str, str] = {}
        for name, var in variables.items():
            address = var.get("address", "").upper()
            if address and address not in self.address_names:
                self.address_names[address] = name
        #: Function blocks for LD operate blocks
        self.operates: list[OperateBlock] = []
        self._ids = itertools.count(1)

    def next_id(self) -> str:
        return str(next(self._ids))

    def direct_variable(self, address: str) -> str:
        """
        Name of the variable for a direct variable, e.g. ``%MW10``. A
        variable is added if no variable is declared at the address.
        """
        address = address.upper()
        if address in self.address_names:
            return self.address_names[address]

        name = "PEAT_" + re.sub(r"\W", "_", address[1:])
        # Only %I and %Q are I/O. Memory and constant areas are internal variables.
        located = address if address[1] in "IQ" else ""
        self.variables[name] = {"type": direct_address_type(address), "address": located}
        self.names[name.lower()] = name
        self.address_names[address] = name
        return name


class PouContext:
    """State of the conversion of one POU."""

    def __init__(self, project: ProjectContext, name: str) -> None:
        self.project = project
        self.name = name
        #: Variables the POU declares itself, e.g. instances of function blocks
        #: for Unity functions that become function blocks
        self.locals: dict[str, str] = {}
        #: Lowercase identifiers used by the POU, to find the global variables it uses
        self.referenced: set[str] = set()
        self._instances = itertools.count(1)

    def auto_instance(self, type_name: str) -> str:
        """Declare a new instance of a function block type."""
        while True:
            name = f"PEAT_{sanitize_name(type_name).upper()}_{next(self._instances)}"
            if name.lower() not in self.project.names:
                break
        self.locals[name] = type_name
        return name

    def expression(self, text: str) -> str:
        """
        Convert the variable or literal on a pin, contact or coil.

        Direct variables are replaced with a variable, and variable names are
        given the case they were declared with, since the TC6 to Structured
        Text conversion matches names case-sensitively.
        """
        text = text.strip()
        if self.project.allow_direct_variables:
            text = DIRECT_ADDRESS_RE.sub(lambda m: self.project.direct_variable(m.group(0)), text)

        m = re.fullmatch(r"([A-Za-z_]\w*)(.*)", text, re.DOTALL)
        if m and m.group(1).lower() in self.project.names:
            text = self.project.names[m.group(1).lower()] + m.group(2)
        self.referenced.update(st_identifiers(text))
        return text

    def text(self, text: str) -> str:
        """Convert Structured Text or IL, replacing direct variables with variables."""

        def replace(m: re.Match) -> str:
            if m.group("address") and self.project.allow_direct_variables:
                name = self.project.direct_variable(m.group("address"))
                self.referenced.add(name.lower())
                return name
            if m.group("ident"):
                self.referenced.add(m.group("ident").lower())
            return m.group(0)

        return _ST_TOKEN_RE.sub(replace, text)

    @staticmethod
    def referenced_in(text: str) -> set[str]:
        """Lowercase identifiers in Structured Text."""
        return st_identifiers(text)

    def variable_type(self, expression: str) -> str:
        """Type of a variable or literal, if it's known."""
        lit = literal_type(expression)
        if lit:
            return lit
        name = re.split(r"[.\[]", expression, maxsplit=1)[0]
        if name in self.locals:
            return self.locals[name]
        var = self.project.variables.get(self.project.names.get(name.lower(), ""))
        if var and "." not in expression and "[" not in expression:
            var_type = var.get("type", "").upper()
            return "BOOL" if var_type == "EBOOL" else var_type
        return ""


# --------------------------------------------------------------------------
# TC6 graphical bodies
# --------------------------------------------------------------------------


class Tc6Graph:
    """Builds the objects of a TC6 FBD or LD body."""

    def __init__(self, ctx: PouContext, y_offset: int = 0) -> None:
        self.ctx = ctx
        self.y_offset = y_offset
        self.elements: list[Element] = []
        #: If LD objects are used, which need an LD body
        self.uses_ld = False
        #: If any object generates code
        self.has_code = False
        self.max_y = y_offset
        self._rail: Source | None = None

    def _element(
        self, tag: str, x: int, y: int, local_id: str | None = None, **attrib: str
    ) -> tuple[Element, str]:
        local_id = local_id or self.ctx.project.next_id()
        element = Element(tag, {"localId": local_id, **attrib})
        y = y * GRID + self.y_offset
        self.max_y = max(self.max_y, y)
        SubElement(element, "position", {"x": str(x * GRID), "y": str(y)})
        self.elements.append(element)
        return element, local_id

    @staticmethod
    def _connection_in(parent: Element, sources: list[Source]) -> Element:
        point = SubElement(parent, "connectionPointIn")
        SubElement(point, "relPosition", {"x": "0", "y": "0"})
        for ref_id, pin in sources:
            attrib = {"refLocalId": ref_id}
            if pin:
                attrib["formalParameter"] = pin
            # The converter needs a point on each connection, even if it's not used
            connection = SubElement(point, "connection", attrib)
            SubElement(connection, "position", {"x": "0", "y": "0"})
        return point

    @staticmethod
    def _connection_out(parent: Element, pin: str | None = None) -> Element:
        point = SubElement(
            parent, "connectionPointOut", {"formalParameter": pin} if pin is not None else {}
        )
        SubElement(point, "relPosition", {"x": "0", "y": "0"})
        return point

    def left_rail(self) -> Source:
        """The left power rail of an LD body."""
        if self._rail is None:
            rail, local_id = self._element("leftPowerRail", 0, 0, width="2", height="2")
            self._connection_out(rail, "")
            self._rail = (local_id, None)
            self.uses_ld = True
        return self._rail

    def in_variable(
        self,
        expression: str,
        x: int,
        y: int,
        negated: bool = False,
        local_id: str | None = None,
    ) -> Source:
        attrib = {"negated": "true"} if negated else {}
        var, local_id = self._element(
            "inVariable", x, y, local_id, width="2", height="1", **attrib
        )
        self._connection_out(var)
        SubElement(var, "expression").text = self.ctx.expression(expression)
        return local_id, None

    def out_variable(self, expression: str, sources: list[Source], x: int, y: int) -> None:
        var, _ = self._element("outVariable", x, y, width="2", height="1", executionOrderId="0")
        self._connection_in(var, sources)
        SubElement(var, "expression").text = self.ctx.expression(expression)
        self.has_code = self.has_code or bool(sources)

    def block(
        self,
        type_name: str,
        instance: str | None,
        inputs: list[tuple[str, list[Source], bool]],
        outputs: list[tuple[str, bool]],
        x: int,
        y: int,
        local_id: str | None = None,
    ) -> str:
        """
        Add a function or function block.

        Args:
            type_name: Block type
            instance: Name of the instance, for function blocks
            inputs: Formal parameter, sources and if the input is negated, of each input
            outputs: Formal parameter and if the output is negated, of each output.
                In/out parameters are both inputs and outputs.
            x: Column
            y: Row
            local_id: Local ID to use, if one was allocated already

        Returns:
            Local ID of the block
        """
        attrib = {"typeName": type_name, "width": "4", "height": "4", "executionOrderId": "0"}
        if instance:
            attrib["instanceName"] = instance
        block, local_id = self._element("block", x, y, local_id, **attrib)

        in_vars = SubElement(block, "inputVariables")
        for pin, sources, negated in inputs:
            var = SubElement(in_vars, "variable", {"formalParameter": pin})
            if negated:
                var.set("negated", "true")
            self._connection_in(var, sources)
        SubElement(block, "inOutVariables")
        out_vars = SubElement(block, "outputVariables")
        for pin, negated in outputs:
            var = SubElement(out_vars, "variable", {"formalParameter": pin})
            if negated:
                var.set("negated", "true")
            self._connection_out(var)

        if instance or any(sources for _, sources, _ in inputs):
            self.has_code = True
        return local_id

    def contact(
        self,
        variable: str,
        sources: list[Source],
        x: int,
        y: int,
        local_id: str | None = None,
        **modifiers: str,
    ) -> Source:
        contact, local_id = self._element(
            "contact", x, y, local_id, width="2", height="1", **modifiers
        )
        self._connection_in(contact, sources)
        self._connection_out(contact)
        SubElement(contact, "variable").text = variable
        self.uses_ld = True
        return local_id, None

    def coil(
        self,
        variable: str,
        sources: list[Source],
        x: int,
        y: int,
        local_id: str | None = None,
        **modifiers: str,
    ) -> Source:
        coil, local_id = self._element("coil", x, y, local_id, width="2", height="1", **modifiers)
        self._connection_in(coil, sources)
        self._connection_out(coil)
        SubElement(coil, "variable").text = self.ctx.expression(variable)
        self.uses_ld = True
        self.has_code = self.has_code or bool(sources)
        return local_id, None

    def body_element(self) -> Element:
        """The TC6 ``FBD`` or ``LD`` body element with the objects."""
        body = Element("LD" if self.uses_ld else "FBD")
        body.extend(self.elements)
        return body


@dataclass
class _Pin:
    name: str
    effective: str = ""
    inverted: bool = False


@dataclass
class _Ffb:
    """A Unity function or function block (FFBBlock)."""

    element: Element
    type_name: str
    instance: str
    x: int
    y: int
    en_eno: bool
    inputs: list[_Pin]
    outputs: list[_Pin]

    @classmethod
    def parse(cls, element: Element) -> _Ffb:
        pos = element.find("objPosition")
        desc = element.find("descriptionFFB")

        def pins(tag: str) -> list[_Pin]:
            if desc is None:
                return []
            return [
                _Pin(
                    p.get("formalParameter", ""),
                    p.get("effectiveParameter", "") or "",
                    p.get("invertedPin", "false") == "true",
                )
                for p in desc.findall(tag)
            ]

        return cls(
            element=element,
            type_name=element.get("typeName", ""),
            instance=element.get("instanceName", ""),
            x=int(pos.get("posX", "0")) if pos is not None else 0,
            y=int(pos.get("posY", "0")) if pos is not None else 0,
            en_eno=element.get("enEnO", "false") == "true",
            inputs=pins("inputVariable"),
            outputs=pins("outputVariable"),
        )

    @property
    def is_function(self) -> bool:
        """Unity names functions by their execution order, e.g. ".3"."""
        return not self.instance or self.instance.startswith(".")

    def visible_pins(self, direction: str) -> list[_Pin]:
        """Pins shown on the block, in order. EN and ENO are hidden unless enabled."""
        pins = self.inputs if direction == "inputs" else self.outputs
        return [p for p in pins if self.en_eno or p.name not in ["EN", "ENO"]]


def _link_endpoints(network: Element) -> list[tuple[tuple[str, str], tuple[str, str]]]:
    """Source and destination (object name, pin) of each link between blocks."""
    links = []
    for link in network.findall("linkFB"):
        src = link.find("linkSource")
        dst = link.find("linkDestination")
        if src is None or dst is None:
            continue
        links.append(
            (
                (src.get("parentObjectName", ""), src.get("pinName", "")),
                (dst.get("parentObjectName", ""), dst.get("pinName", "")),
            )
        )
    return links


class _BlockWriter:
    """Adds Unity functions and function blocks to a TC6 graph."""

    def __init__(self, graph: Tc6Graph, section: str) -> None:
        self.graph = graph
        self.ctx = graph.ctx
        self.library = graph.ctx.project.library
        self.section = section
        #: Local ID and block conversion of each Unity block, by object name
        self.blocks: dict[str, tuple[str, BlockSpec, _Ffb]] = {}
        #: Inputs of blocks connected by other objects, by (object name, pin)
        self.extra_sources: dict[tuple[str, str], list[Source]] = {}

    def allocate(self, ffbs: list[_Ffb]) -> None:
        """Allocate local IDs, so links can refer to blocks before they're added."""
        for ffb in ffbs:
            spec = self.library.resolve(ffb.type_name)
            self.blocks[ffb.instance] = (self.ctx.project.next_id(), spec, ffb)

    def output_source(self, obj: str, pin: str) -> Source | None:
        """Source for an output pin of a block."""
        if obj not in self.blocks:
            return None
        local_id, spec, _ffb = self.blocks[obj]
        if spec.coil_storage:
            # The coil passes power through
            return (local_id, None)
        return local_id, spec.renames.get(pin, pin)

    def add_links(self, network: Element) -> set[tuple[str, str]]:
        """Connect the pins linked by ``linkFB``. Returns the linked output pins."""
        linked_outputs = set()
        for (src_obj, src_pin), (dst_obj, dst_pin) in _link_endpoints(network):
            source = self.output_source(src_obj, src_pin)
            if source is None or dst_obj not in self.blocks:
                log.warning(
                    f"Skipping link from {src_obj}.{src_pin} to {dst_obj}.{dst_pin} "
                    f"in section {self.section}, the block isn't in the section"
                )
                continue
            self.extra_sources.setdefault((dst_obj, dst_pin), []).append(source)
            linked_outputs.add((src_obj, src_pin))
        return linked_outputs

    def write(self, name: str, linked_outputs: set[tuple[str, str]], x: int, y: int) -> None:
        """Add a block, with variables for the pins bound to variables or literals."""
        local_id, spec, ffb = self.blocks[name]

        if spec.coil_storage:
            self._write_coil(name, local_id, spec, ffb, x, y)
            return

        if spec.kind == "function" and not any(
            p.effective or (name, p.name) in linked_outputs for p in ffb.outputs
        ):
            # A function without outputs connected does nothing
            return

        instance = None
        if spec.kind == "functionBlock":
            instance = (
                self.ctx.auto_instance(spec.type_name)
                if spec.auto_instance or ffb.is_function
                else self.ctx.expression(ffb.instance)
            )
            if instance.lower() not in self.ctx.project.names and instance not in self.ctx.locals:
                # Instances are global variables, but some exports have no variables
                instance = sanitize_name(instance)
                self.ctx.locals[instance] = spec.type_name

        inputs = []
        input_names = set()
        for i, pin in enumerate(ffb.inputs):
            sources = list(self.extra_sources.get((name, pin.name), []))
            tc6_pin = spec.renames.get(pin.name, pin.name)
            if pin.effective:
                value = self._literal_for_pin(spec, tc6_pin, pin.effective)
                sources.append(self.graph.in_variable(value, x - 3, y + i))
            if sources:
                pin_type = self.ctx.variable_type(pin.effective) if pin.effective else ""
                self.library.note_pin(ffb.type_name, tc6_pin, "inputs", pin_type)
                inputs.append((tc6_pin, sources, pin.inverted))
                input_names.add(tc6_pin)

        if spec.kind == "function" and not input_names - {"EN"}:
            # The converter skips functions without inputs, so the objects
            # connected to the outputs get FALSE instead
            log.warning(f"Block {ffb.type_name} in section {self.section} has no inputs connected")
            self.graph.in_variable("FALSE", x, y, local_id=local_id)
            return

        outputs = []
        for i, pin in enumerate(ffb.outputs):
            tc6_pin = spec.renames.get(pin.name, pin.name)
            if pin.name == "ENO" and not pin.effective and (name, pin.name) not in linked_outputs:
                continue
            outputs.append((tc6_pin, pin.inverted))
            pin_type = self.ctx.variable_type(pin.effective) if pin.effective else ""
            self.library.note_pin(ffb.type_name, tc6_pin, "outputs", pin_type)
            # The variable on the input of an in/out is updated by the call
            if not pin.effective or (tc6_pin in input_names and spec.kind == "functionBlock"):
                continue
            source = (local_id, tc6_pin)
            if spec.kind == "function" and "EN" in input_names and pin.name != "ENO":
                source = self._gate_output(pin.effective, source, inputs, x + 3, y + i)
            self.graph.out_variable(pin.effective, [source], x + 5, y + i)

        for pin in ffb.inputs:
            tc6_pin = spec.renames.get(pin.name, pin.name)
            if tc6_pin not in input_names and any(
                spec.renames.get(o.name, o.name) == tc6_pin for o in ffb.outputs
            ):
                log.warning(
                    f"In/out parameter {pin.name} of block {ffb.type_name} in section "
                    f"{self.section} isn't connected"
                )

        self.graph.block(spec.type_name, instance, inputs, outputs, x, y, local_id)

    def _gate_output(self, variable: str, source: Source, inputs: list, x: int, y: int) -> Source:
        """
        Only set the variable on the output of a function when it's enabled (EN).

        When a function isn't enabled, Unity leaves the variables on its outputs
        unchanged, while MatIEC returns a default value. So the variable is set
        to SEL(EN, variable, output).
        """
        _, en_sources, en_negated = next(i for i in inputs if i[0] == "EN")
        current = self.graph.in_variable(variable, x, y)
        sel_id = self.graph.block(
            "SEL",
            None,
            [("G", en_sources, en_negated), ("IN0", [current], False), ("IN1", [source], False)],
            [("OUT", False)],
            x + 1,
            y,
        )
        return sel_id, "OUT"

    def _write_coil(
        self, name: str, local_id: str, spec: BlockSpec, ffb: _Ffb, x: int, y: int
    ) -> None:
        """Unity SET and RESET set or reset the variable on their output when enabled."""
        target = next((p.effective for p in ffb.outputs if p.name == "OUT"), "")
        if not target:
            log.warning(
                f"Skipping {ffb.type_name} block in section {self.section}, "
                f"its output isn't bound to a variable"
            )
            return

        sources = list(self.extra_sources.get((name, "EN"), []))
        for pin in ffb.inputs:
            if pin.name == "EN" and pin.effective:
                sources.append(self.graph.in_variable(pin.effective, x - 3, y))
        if not sources:
            sources = [self.graph.left_rail()]
        # Links from the block's ENO refer to the allocated ID
        self.graph.coil(target, sources, x, y, local_id, storage=spec.coil_storage)

    def _literal_for_pin(self, spec: BlockSpec, pin: str, value: str) -> str:
        """
        Make a literal on a pin valid for MatIEC, which requires TRUE and FALSE
        for BOOL values. Decimal numbers on generic pins are typed as REAL, so the
        type of the block's output can be found.
        """
        value = value.strip()
        pin_type = self.library.pin_type(spec, pin)
        if value in ["0", "1"] and pin_type == "BOOL":
            return "TRUE" if value == "1" else "FALSE"
        if not pin_type and literal_type(value) == "REAL" and "#" not in value:
            return f"REAL#{value}"
        return value


def fbd_to_graph(network: Element, graph: Tc6Graph, section: str) -> None:
    """
    Convert a Unity FBD network (``networkFBD``) to TC6 objects.

    Args:
        network: The ``networkFBD`` element
        graph: TC6 graph to add the objects to
        section: Name of the section, for log messages
    """
    ffbs = [_Ffb.parse(e) for e in network.findall("FFBBlock")]
    writer = _BlockWriter(graph, section)
    writer.allocate(ffbs)
    linked_outputs = writer.add_links(network)

    for ffb in ffbs:
        writer.write(ffb.instance, linked_outputs, ffb.x, ffb.y)

    if network.find("jumpObject") is not None:
        log.warning(
            f"FBD section {section} has jumps, which aren't converted. "
            f"The objects after a jump always run."
        )


# --------------------------------------------------------------------------
# LD
# --------------------------------------------------------------------------


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict = {}

    def find(self, node):
        self.parent.setdefault(node, node)
        while self.parent[node] != node:
            self.parent[node] = self.parent[self.parent[node]]
            node = self.parent[node]
        return node

    def union(self, a, b) -> None:
        self.parent[self.find(a)] = self.find(b)


@dataclass
class _LdObject:
    """An object in an LD network, and the cell edges of its input and output."""

    element: Element
    row: int
    col: int
    width: int


def _cell_width(element: Element) -> int:
    tag = element.tag
    if tag in ["emptyCell", "HLink"]:
        return int(element.get("nbCells", "1"))
    if tag == "FFBBlock":
        return 2
    if tag in ["operateBlock", "compareBlock"]:
        return int(element.get("width", "1"))
    if tag == "shortCircuit":
        inner = [e for e in element if e.tag != "VLink"]
        return sum(_cell_width(e) for e in inner) if inner else 1
    return 1


def ld_to_graph(network: Element, graph: Tc6Graph, section: str) -> None:
    """
    Convert a Unity LD network (``networkLD``) to TC6 objects.

    The node at the left edge of column ``c`` of row ``r`` is ``(r, c)``.
    Contacts, coils and other objects connect the node at their left edge to
    the node at their right edge. Horizontal and vertical links join nodes.

    Args:
        network: The ``networkLD`` element
        graph: TC6 graph to add the objects to
        section: Name of the section, for log messages
    """
    nodes = _UnionFind()
    objects: list[_LdObject] = []
    ffbs: list[_Ffb] = []
    row = 0

    for line in network.findall("typeLine"):
        empty = line.find("emptyLine")
        if empty is not None:
            row += int(empty.get("nbRows", "1"))
            continue

        col = 0
        for element in line:
            width = _cell_width(element)
            items = list(element) if element.tag == "shortCircuit" else [element]
            item_col = col
            for item in items:
                if item.tag == "VLink":
                    continue
                item_width = _cell_width(item)
                _place_ld_item(item, row, item_col, item_width, nodes, objects, ffbs)
                item_col += item_width
            if element.tag == "VLink" or any(i.tag == "VLink" for i in items):
                # Vertical link on the right edge of the cell
                edge = col + width
                nodes.union((row, edge), (row + 1, edge))
            col += width
        row += 1

    # Nodes at the left edge of the network are on the left power rail
    rail_nodes = {nodes.find((r, 0)) for r in range(row + 1)}

    def sources_at(node: tuple[int, int], drivers: dict) -> list[Source]:
        root = nodes.find(node)
        if root in rail_nodes:
            return [graph.left_rail()]
        return list(drivers.get(root, []))

    # Allocate the blocks, which drive the nodes at their outputs
    writer = _BlockWriter(graph, section)
    writer.allocate(ffbs)
    drivers: dict = {}
    ids = {}
    for obj in objects:
        ids[id(obj)] = graph.ctx.project.next_id()
        if obj.element.tag in ["contact", "coil", "compareBlock"]:
            root = nodes.find((obj.row, obj.col + obj.width))
            drivers.setdefault(root, []).append((ids[id(obj)], None))
    for ffb in ffbs:
        for j, pin in enumerate(ffb.visible_pins("outputs")):
            source = writer.output_source(ffb.instance, pin.name)
            if source is not None and not pin.effective:
                root = nodes.find((ffb.y + 1 + j, ffb.x + 2))
                drivers.setdefault(root, []).append(source)

    # Nodes that are the input of an object or block
    consumed = {nodes.find((o.row, o.col)) for o in objects}
    for ffb in ffbs:
        for i in range(len(ffb.visible_pins("inputs"))):
            consumed.add(nodes.find((ffb.y + 1 + i, ffb.x)))

    # Inputs of blocks connected through the grid
    linked_outputs = writer.add_links(network)
    for ffb in ffbs:
        for i, pin in enumerate(ffb.visible_pins("inputs")):
            if pin.effective:
                continue
            sources = sources_at((ffb.y + 1 + i, ffb.x), drivers)
            if sources:
                writer.extra_sources.setdefault((ffb.instance, pin.name), []).extend(sources)
        for j, pin in enumerate(ffb.visible_pins("outputs")):
            if nodes.find((ffb.y + 1 + j, ffb.x + 2)) in consumed:
                linked_outputs.add((ffb.instance, pin.name))

    for obj in objects:
        sources = [s for s in sources_at((obj.row, obj.col), drivers) if s[0] != ids[id(obj)]]
        _write_ld_object(obj, ids[id(obj)], sources, graph, section)

    for ffb in ffbs:
        writer.write(ffb.instance, linked_outputs, ffb.x, ffb.y)


def _place_ld_item(
    item: Element,
    row: int,
    col: int,
    width: int,
    nodes: _UnionFind,
    objects: list[_LdObject],
    ffbs: list[_Ffb],
) -> None:
    tag = item.tag
    if tag == "HLink":
        for c in range(col, col + width):
            nodes.union((row, c), (row, c + 1))
    elif tag == "FFBBlock":
        ffb = _Ffb.parse(item)
        ffbs.append(ffb)
    elif tag in ["contact", "coil", "compareBlock", "operateBlock"]:
        objects.append(_LdObject(item, row, col, width))
    elif tag != "emptyCell":
        log.warning(f"Skipping unknown LD object '{tag}'")


def _write_ld_object(
    obj: _LdObject, local_id: str, sources: list[Source], graph: Tc6Graph, section: str
) -> None:
    element = obj.element
    tag = element.tag
    x, y = obj.col, obj.row
    if not sources:
        # Nothing powers the object
        sources = [graph.in_variable("FALSE", x - 1, y)]

    if tag == "contact":
        contact_type = element.get("typeContact", "openContact")
        if contact_type not in CONTACT_TYPES:
            log.warning(f"Unknown contact type '{contact_type}' in section {section}")
        variable = graph.ctx.expression(element.get("contactVariableName", ""))
        modifiers = CONTACT_TYPES.get(contact_type, {})
        graph.contact(variable, sources, x, y, local_id, **modifiers)
    elif tag == "coil":
        coil_type = element.get("typeCoil", "coil")
        if coil_type not in COIL_TYPES:
            log.warning(
                f"Coil type '{coil_type}' in section {section} isn't supported, "
                f"it will be a normal coil"
            )
        variable = element.get("coilVariableName", "")
        graph.coil(variable, sources, x, y, local_id, **COIL_TYPES.get(coil_type, {}))
    elif tag == "compareBlock":
        # A comparison passes power when it's true, like a contact
        expression = graph.ctx.text(element.findtext("expression", default="")).strip()
        graph.contact(f"({expression})", sources, x, y, local_id)
    elif tag == "operateBlock":
        _write_operate_block(element, local_id, sources, graph, x, y)


def _write_operate_block(
    element: Element, local_id: str, sources: list[Source], graph: Tc6Graph, x: int, y: int
) -> None:
    """
    An operate block runs a Structured Text statement when it has power.
    It becomes a function block that runs the statement, called with EN.
    """
    ctx = graph.ctx
    statement = ctx.text(element.findtext("statement", default="")).strip()
    operates = ctx.project.operates
    type_name = f"{ctx.name}_OPERATE{len(operates) + 1}"
    operates.append(OperateBlock(type_name, statement, set(ctx.referenced_in(statement))))
    instance = ctx.auto_instance(type_name)
    graph.block(type_name, instance, [("EN", sources, False)], [], x, y, local_id)


@dataclass
class OperateBlock:
    """A function block that runs the statement of an LD operate block."""

    type_name: str
    statement: str
    #: Lowercase identifiers used by the statement
    referenced: set[str]


# --------------------------------------------------------------------------
# SFC
# --------------------------------------------------------------------------


@dataclass
class _SfcNode:
    """A step, transition, jump, branch or joint of an SFC network."""

    key: str
    tag: str
    element: Element
    x: int
    y: int
    width: int = 1

    @property
    def is_pseudo(self) -> bool:
        return self.tag.endswith(("Branch", "Joint"))


def _sfc_network_graph(
    network: Element, prefix: str
) -> tuple[list[_SfcNode], dict[str, set[str]]]:
    """
    Nodes of an SFC network, and the nodes each node connects to.

    Branches and joints are kept as nodes, and removed later.
    """
    nodes: list[_SfcNode] = []
    for i, element in enumerate(network):
        if element.tag in ["linkSFC", "textBox", "commentSFC"]:
            continue
        pos = element.find("objPosition")
        if pos is None:
            continue
        nodes.append(
            _SfcNode(
                key=f"{prefix}#{i}",
                tag=element.tag,
                element=element,
                x=int(pos.get("posX", "0")),
                y=int(pos.get("posY", "0")),
                width=int(element.get("width", "1") or 1),
            )
        )

    cells = {(n.x, n.y): n for n in nodes if not n.is_pseudo}
    edges: dict[str, set[str]] = {n.key: set() for n in nodes}
    # Cell boundaries crossed by a branch or joint: (column, row above)
    covered = set()

    for node in nodes:
        span = range(node.x, node.x + max(node.width, 1))
        if node.tag.endswith("Branch"):
            # Line at the top of the row: from above it to the objects on the row
            for c in span:
                covered.add((c, node.y - 1))
                above = cells.get((c, node.y - 1))
                below = cells.get((c, node.y))
                if above:
                    edges[above.key].add(node.key)
                if below:
                    edges[node.key].add(below.key)
        elif node.tag.endswith("Joint"):
            # Line at the bottom of the row: from the objects on the row to below it
            for c in span:
                covered.add((c, node.y))
                above = cells.get((c, node.y))
                below = cells.get((c, node.y + 1))
                if above:
                    edges[above.key].add(node.key)
                if below:
                    edges[node.key].add(below.key)

    for (x, y), node in cells.items():
        below = cells.get((x, y + 1))
        if below and (x, y) not in covered:
            edges[node.key].add(below.key)

    # Explicit links
    by_position = {(n.tag, n.x, n.y): n for n in nodes}
    for link in network.findall("linkSFC"):
        ends = []
        for tag in ["directedLinkSource", "directedLinkDestination"]:
            end = link.find(tag)
            pos = end.find("objPosition") if end is not None else None
            if pos is None:
                break
            ends.append(
                by_position.get(
                    (end.get("objectType", ""), int(pos.get("posX")), int(pos.get("posY")))
                )
            )
        if len(ends) == 2 and all(ends):
            edges[ends[0].key].add(ends[1].key)

    return nodes, edges


def sfc_to_tc6(sfc_program: Element, ctx: PouContext, section: str) -> tuple[Element, list]:
    """
    Convert a Unity SFC section (``SFCProgram``) to a TC6 SFC body.

    Args:
        sfc_program: The ``SFCProgram`` element
        ctx: Conversion state of the POU
        section: Name of the section, for log messages

    Returns:
        The TC6 ``SFC`` body element, and the actions of the POU as
        ``(name, body element)`` tuples
    """
    chart = sfc_program.find("chartSource/networkSFC")
    macros = {
        m.get("name", "").lower(): m.find("networkSFC")
        for m in sfc_program.findall("macroSource")
        if m.find("networkSFC") is not None
    }

    nodes: dict[str, _SfcNode] = {}
    edges: dict[str, set[str]] = {}
    macro_ends: dict[str, tuple[str, str]] = {}
    pending = [("chart", chart)] if chart is not None else []
    seen = set()

    while pending:
        prefix, network = pending.pop()
        net_nodes, net_edges = _sfc_network_graph(network, prefix)
        for node in net_nodes:
            nodes[node.key] = node
            if node.tag == "step" and node.element.get("stepType") == "macroStep":
                name = node.element.get("stepName", "").lower()
                if name in macros and name not in seen:
                    seen.add(name)
                    pending.append((name, macros[name]))
        edges.update(net_edges)

        if prefix != "chart":
            ends = {
                n.element.get("stepType"): n.key
                for n in net_nodes
                if n.tag == "step" and n.element.get("stepType") in ["inStep", "outStep"]
            }
            if "inStep" in ends and "outStep" in ends:
                macro_ends[prefix] = (ends["inStep"], ends["outStep"])

    # Replace macro steps with the steps of the macro section
    step_names: dict[str, str] = {}
    for node in nodes.values():
        if node.tag == "step":
            step_names[node.element.get("stepName", "").lower()] = node.key
    for key, node in list(nodes.items()):
        if node.tag != "step" or node.element.get("stepType") != "macroStep":
            continue
        name = node.element.get("stepName", "").lower()
        if name not in macro_ends:
            log.warning(f"Macro step {name} in section {section} has no macro section")
            continue
        in_key, out_key = macro_ends[name]
        for targets in edges.values():
            if key in targets:
                targets.discard(key)
                targets.add(in_key)
        edges[out_key] |= edges.pop(key)
        del nodes[key]
        step_names[name] = in_key

    # Remove branches and joints, connecting the objects on either side of them
    def real_targets(key: str, visited: set) -> set[str]:
        result = set()
        for target in edges.get(key, set()):
            if target in visited:
                continue
            visited.add(target)
            if nodes[target].is_pseudo:
                result |= real_targets(target, visited)
            else:
                result.add(target)
        return result

    real = {k: n for k, n in nodes.items() if not n.is_pseudo}
    successors = {k: real_targets(k, {k}) for k in real}

    return _emit_sfc(real, successors, step_names, sfc_program, ctx, section)


def _emit_sfc(
    nodes: dict[str, _SfcNode],
    successors: dict[str, set[str]],
    step_names: dict[str, str],
    sfc_program: Element,
    ctx: PouContext,
    section: str,
) -> tuple[Element, list]:
    """Create the TC6 SFC body from the connected steps, transitions and jumps."""
    body = Element("SFC")
    project = ctx.project

    def pos(element: Element, node: _SfcNode, dx: int = 0) -> None:
        SubElement(element, "position", {"x": str((node.x + dx) * GRID), "y": str(node.y * GRID)})

    steps = {k: n for k, n in nodes.items() if n.tag == "step"}
    transitions = {k: n for k, n in nodes.items() if n.tag == "transition"}

    # Steps before and after each transition. A jump leads to the step it names.
    sources: dict[str, list[str]] = {t: [] for t in transitions}
    targets: dict[str, list[str]] = {t: [] for t in transitions}
    for key in steps:
        for t in sorted(successors[key], key=lambda k: (nodes[k].x, nodes[k].y)):
            if t in transitions:
                sources[t].append(key)
            else:
                log.warning(f"Skipping link from step to {nodes[t].tag} in section {section}")
    for t in transitions:
        for target in sorted(successors[t], key=lambda k: (nodes[k].x, nodes[k].y)):
            node = nodes[target]
            if node.tag == "jumpSFC":
                name = node.element.get("stepName", "").lower()
                if name in step_names:
                    targets[t].append(step_names[name])
                else:
                    log.warning(f"Jump to unknown step {name} in section {section}")
            elif node.tag == "step":
                targets[t].append(target)

    ids = {key: project.next_id() for key in nodes}
    valid = {t for t in transitions if sources[t] and targets[t]}
    if len(valid) < len(transitions):
        log.warning(
            f"Skipping {len(transitions) - len(valid)} transitions in section {section} "
            f"that aren't connected to steps"
        )

    # Where a transition's output is: the transition, or a parallel divergence
    out_ref: dict[str, str] = {}
    for t in valid:
        out_ref[t] = ids[t]
        if len(targets[t]) > 1:
            div_id = project.next_id()
            div = SubElement(body, "simultaneousDivergence", {"localId": div_id})
            pos(div, nodes[t])
            _sfc_connection_in(div, ids[t])
            for _ in targets[t]:
                SubElement(div, "connectionPointOut", {"formalParameter": ""})
            out_ref[t] = div_id

    incoming: dict[str, list[str]] = {s: [] for s in steps}
    for t in sorted(valid, key=lambda k: (nodes[k].y, nodes[k].x)):
        for s in targets[t]:
            incoming[s].append(t)

    actions: list[tuple[str, Element]] = []
    action_names = _convert_actions(sfc_program, ctx, section, actions)

    for key, node in steps.items():
        element = node.element
        name = element.get("stepName", "")
        attrib = {"localId": ids[key], "name": name}
        if element.get("stepType") == "initialStep":
            attrib["initialStep"] = "true"
        step = SubElement(body, "step", attrib)
        pos(step, node)
        if incoming[key]:
            _sfc_connection_in(step, out_ref[incoming[key][0]])
        SubElement(step, "connectionPointOut", {"formalParameter": ""})

        # Other transitions to the step become jumps to it
        for t in incoming[key][1:]:
            jump = SubElement(body, "jumpStep", {"localId": project.next_id(), "targetName": name})
            pos(jump, nodes[t], 2)
            _sfc_connection_in(jump, out_ref[t])

        _add_step_actions(body, element, ids[key], node, ctx, action_names, section)

    for t in sorted(valid, key=lambda k: (nodes[k].y, nodes[k].x)):
        node = nodes[t]
        transition = SubElement(body, "transition", {"localId": ids[t]})
        pos(transition, node)
        if len(sources[t]) == 1:
            _sfc_connection_in(transition, ids[sources[t][0]])
        else:
            conv_id = project.next_id()
            conv = Element("simultaneousConvergence", {"localId": conv_id})
            pos(conv, node)
            for s in sources[t]:
                _sfc_connection_in(conv, ids[s])
            SubElement(conv, "connectionPointOut")
            body.append(conv)
            _sfc_connection_in(transition, conv_id)
        SubElement(transition, "connectionPointOut")
        _add_condition(transition, node.element, sfc_program, ctx, section)

    return body, actions


def _sfc_connection_in(parent: Element, ref_id: str) -> None:
    point = SubElement(parent, "connectionPointIn")
    SubElement(point, "connection", {"refLocalId": ref_id})


def _convert_actions(
    sfc_program: Element, ctx: PouContext, section: str, actions: list
) -> dict[str, str]:
    """Convert the action sections. Returns the name of each action, by lowercase name."""
    names = {}
    for source in sfc_program.findall("actionSource"):
        name = source.get("name", "")
        if not name:
            continue
        body = section_body(source, ctx, f"{section} action {name}")
        if body is None:
            body = placeholder_body(ctx, "Empty action")
        tc6_name = sanitize_name(name)
        names[name.lower()] = tc6_name
        actions.append((tc6_name, body))
    return names


def _add_step_actions(
    body: Element,
    step: Element,
    step_id: str,
    node: _SfcNode,
    ctx: PouContext,
    action_names: dict[str, str],
    section: str,
) -> None:
    step_actions = step.findall("action")
    if not step_actions:
        return

    block = SubElement(body, "actionBlock", {"localId": ctx.project.next_id()})
    SubElement(block, "position", {"x": str((node.x + 1) * GRID), "y": str(node.y * GRID)})
    _sfc_connection_in(block, step_id)

    for action in step_actions:
        qualifier = (action.get("qualifier") or "N").upper()
        if qualifier == "NONE":
            qualifier = "N"
        if qualifier not in ACTION_QUALIFIERS:
            log.warning(f"Unknown action qualifier '{qualifier}' in section {section}")
            qualifier = "N"

        variable = action.findtext("actionName/variableName", default="").strip()
        section_name = action.findtext("actionName/sectionName", default="").strip()
        if section_name:
            reference = action_names.get(section_name.lower())
            if reference is None:
                log.warning(f"Unknown action section {section_name} in section {section}")
                continue
        elif variable:
            reference = ctx.expression(variable)
        else:
            continue

        attrib = {"localId": ctx.project.next_id(), "qualifier": qualifier}
        duration = action.findtext("tValue/tLiteral", default="").strip()
        duration = duration or action.findtext("tValue/tVariable", default="").strip()
        if duration:
            attrib["duration"] = ctx.expression(duration)
        tc6_action = SubElement(block, "action", attrib)
        SubElement(tc6_action, "relPosition", {"x": "0", "y": "0"})
        SubElement(tc6_action, "reference", {"name": reference})


def _add_condition(
    transition: Element, element: Element, sfc_program: Element, ctx: PouContext, section: str
) -> None:
    """Add the condition of a transition, as inline Structured Text."""
    condition = element.find("transitionCondition")
    text = "FALSE"
    if condition is not None:
        variable = condition.findtext("variableName", default="").strip()
        section_name = condition.findtext("sectionName", default="").strip()
        if variable:
            text = ctx.expression(variable)
        elif section_name:
            text = _transition_section_text(section_name, sfc_program, ctx, section)
        if condition.get("invertLogic", "false") == "true":
            text = f"NOT ({text})"

    tc6_condition = SubElement(transition, "condition")
    inline = SubElement(tc6_condition, "inline", {"name": ""})
    SubElement(SubElement(inline, "ST"), "xhtml:p").text = text


def _transition_section_text(
    name: str, sfc_program: Element, ctx: PouContext, section: str
) -> str:
    for source in sfc_program.findall("transitionSource"):
        if source.get("name", "").lower() != name.lower():
            continue
        st = source.find("STSource")
        if st is not None:
            text = ctx.text(st.text or "").strip().rstrip(";").strip()
            if st_has_statements(text):
                return text
            break
        log.warning(
            f"Transition section {name} in section {section} isn't in Structured Text, "
            f"the transition will never be taken"
        )
        return "FALSE"
    log.warning(f"Transition section {name} in section {section} is empty or missing")
    return "FALSE"


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def section_body(element: Element, ctx: PouContext, section: str) -> Element | None:
    """
    Convert the source of a section to a TC6 body.

    Args:
        element: Element containing the section's source, such as ``program``,
            ``FBProgram`` or ``actionSource``
        ctx: Conversion state of the POU
        section: Name of the section, for log messages

    Returns:
        The TC6 ``body`` element, or :obj:`None` if the section has no source
    """
    body = Element("body")
    for tag, language in [("STSource", "ST"), ("ILSource", "IL")]:
        source = element.find(tag)
        if source is not None:
            text = ctx.text(source.text or "")
            if not st_has_statements(text):
                return None
            SubElement(SubElement(body, language), "xhtml:p").text = text
            return body

    graph = Tc6Graph(ctx)
    if not add_graphical_section(element, graph, section):
        return None
    if not graph.has_code:
        return None
    body.append(graph.body_element())
    return body


def placeholder_body(ctx: PouContext, comment: str) -> Element:
    """A Structured Text body with only a placeholder statement."""
    ctx.locals[PLACEHOLDER_VAR] = "BOOL"
    body = Element("body")
    SubElement(
        SubElement(body, "ST"), "xhtml:p"
    ).text = f"(* {comment} *)\n{PLACEHOLDER_VAR} := TRUE;\n"
    return body


def add_graphical_section(element: Element, graph: Tc6Graph, section: str) -> bool:
    """
    Add the objects of an FBD or LD section to a TC6 graph.

    Returns:
        If the section is in FBD or LD
    """
    fbd = element.find("FBDSource")
    ld = element.find("LDSource")
    if fbd is not None:
        for network in fbd.findall("networkFBD"):
            fbd_to_graph(network, graph, section)
        return True
    if ld is not None:
        for network in ld.findall("networkLD"):
            ld_to_graph(network, graph, section)
        return True
    return False


__all__ = [
    "BlockLibrary",
    "OperateBlock",
    "PouContext",
    "ProjectContext",
    "Tc6Graph",
    "add_graphical_section",
    "fbd_to_graph",
    "ld_to_graph",
    "placeholder_body",
    "section_body",
    "sfc_to_tc6",
]
