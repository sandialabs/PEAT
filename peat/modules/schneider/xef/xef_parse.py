"""
Parsing of Schneider Electric Unity Pro/EcoStruxure Control Expert XEF files.

An XEF file is an XML export of a complete Unity Pro or Control Expert
project (root element ``FEFExchangeFile``). It contains the hardware
configuration, variables, user-defined function block (DFB) and data
(DDT) types, the program sections, and project metadata.

A ZEF file is a ZIP archive containing the same XML (``unitpro.xef``,
with root element ``ZEFExchangeFile``) and other files.

Authors

- Christopher Goes
"""

import io
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime
from typing import BinaryIO
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement

from peat import log
from peat.modules.schneider.m340 import m340_parse
from peat.parsing.plc_open import PLCControler
from peat.parsing.plc_open.core_modules.structures import StdBlckDct
from peat.parsing.tc6 import TC6

from . import xef_lang
from .xef_lang import PLACEHOLDER_VAR

# Child elements of <program> and <FBProgram> for each IEC 61131-3 language
LANGUAGE_TAGS: dict[str, str] = {
    "STSource": "ST",
    "ILSource": "IL",
    "LDSource": "LD",
    "FBDSource": "FBD",
    "SFCSource": "SFC",
}

# Root elements of a XEF file, and of the XEF in a ZEF archive
ROOT_TAGS: tuple[str, ...] = ("FEFExchangeFile", "ZEFExchangeFile")

# Name of the XEF in a ZEF archive
ZEF_XEF_NAME = "unitpro.xef"

# Largest XEF that will be extracted from a ZEF archive
MAX_ZEF_XEF_SIZE = 512 * 1024 * 1024

# IEC 61131-3 standard function blocks, which variables may be instances of
STANDARD_FB_TYPES: frozenset[str] = frozenset(
    ["TON", "TOF", "TP", "CTU", "CTD", "CTUD", "R_TRIG", "F_TRIG", "SR", "RS"]
)

# Priorities of the Unity tasks, highest first. AUXn tasks are 2 + n.
TASK_PRIORITIES: dict[str, int] = {"FAST": 0, "SAFE": 1, "MAST": 1}

# Interval of tasks that don't have one, such as cyclic tasks
DEFAULT_TASK_INTERVAL = "T#20ms"

# Variable lists of a DFB type and the TC6 variable list each maps to
DFB_VAR_LISTS: dict[str, str] = {
    "inputParameters": "inputVars",
    "outputParameters": "outputVars",
    "inOutParameters": "inOutVars",
    "publicLocalVariables": "localVars",
    "privateLocalVariables": "localVars",
}


def parse_xef(data: bytes | str) -> dict:
    """
    Parse the contents of a XEF file, or the XEF in a ZEF archive.

    Args:
        data: Contents of the XEF file, or the XEF extracted from a ZEF file
            with :func:`extract_xef_from_zef`

    Returns:
        The parsed project, with the keys ``file_header``, ``content_header``,
        ``plc``, ``modules``, ``variables``, ``dfb_types``, ``ddt_types``,
        ``library_types``, ``tasks``, ``sections`` and ``documentation``.
        Sections and the sections of DFBs have their XML element in
        ``element``, which isn't JSON serializable (see :func:`serializable`).

    Raises:
        ValueError: If the data isn't a XEF file
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as ex:
        raise ValueError(f"Invalid XML in XEF file: {ex}") from None

    if root.tag not in ROOT_TAGS:
        raise ValueError(f"Not a XEF file, root element is '{root.tag}'")

    parsed = {
        "file_header": dict(_find_attrib(root, "fileHeader")),
        "content_header": dict(_find_attrib(root, "contentHeader")),
        "plc": {},
        "modules": [],
        "variables": {},
        "dfb_types": {},
        "ddt_types": {},
        "library_types": {},
        "tasks": {},
        "sections": [],
        "documentation": {},
    }

    # Hardware configuration
    plc = root.find("IOConf/PLC")
    if plc is not None:
        parsed["plc"] = {**_part_item(plc), "attributes": dict(plc.attrib)}

        for item in plc.iter():
            if item.tag in ["rackATS", "powerSupply", "moduleATS"]:
                module = _part_item(item)
                if module:
                    parsed["modules"].append(module)

    # Global variables
    data_block = root.find("dataBlock")
    if data_block is not None:
        parsed["variables"] = _parse_variables(data_block)

    # User-defined function block (DFB) types
    for fb_source in root.findall("FBSource"):
        dfb = _parse_dfb(fb_source)
        parsed["dfb_types"][dfb["name"]] = dfb

    # User-defined data types (DDT)
    for ddt_source in root.findall("DDTSource"):
        ddt_name = ddt_source.get("DDTName", "")
        if not ddt_name:
            continue

        structure = ddt_source.find("structure")
        parsed["ddt_types"][ddt_name] = {
            "name": ddt_name,
            "version": ddt_source.get("version", ""),
            "date": ddt_source.get("dateTime", ""),
            "comment": ddt_source.findtext("comment", default="").strip(),
            # Only structures are supported. Other DDTs, such as arrays, have no fields.
            "fields": _parse_variables(structure) if structure is not None else {},
        }

    # Interfaces of the Unity library functions (EF) and function blocks (EFB) used
    for tag, kind in [("EFSource", "EF"), ("EFBSource", "EFB")]:
        for source in root.findall(tag):
            library_type = _parse_library_type(source, kind)
            if library_type["name"]:
                parsed["library_types"][library_type["name"]] = library_type

    # Tasks, and the order of the sections that run in each task
    for task in root.findall("logicConf/resource/taskDesc"):
        sections = sorted(
            task.findall("sectionDesc"),
            key=lambda s: int(s.get("SectionOrder", "0") or 0),
        )
        parsed["tasks"][task.get("task", "")] = {
            **{k: v for k, v in task.attrib.items() if k != "task"},
            "sections": [s.get("name", "") for s in sections],
        }

    # Program sections. SFC sections are SFCProgram elements.
    for program in root:
        if program.tag not in ["program", "SFCProgram"]:
            continue
        ident = _find_attrib(program, "identProgram")
        language, source = _program_source(program)
        section = {
            "name": ident.get("name", ""),
            "type": ident.get("type", ""),
            "task": ident.get("task", ""),
            "language": language,
            "source": source,
        }
        if ident.get("type") == "Timer":
            # Timer event sections run every time_base * preset milliseconds
            section["time_base"] = ident.get("timeBase", "")
            section["preset"] = ident.get("preset", "")
        section["element"] = program
        parsed["sections"].append(section)

    # Project documentation, such as the author
    footer = _find_attrib(root, "Documentation/Footer")
    title_page = _find_attrib(root, "Documentation/TitlePage")
    general = _find_attrib(root, "Documentation/General")
    parsed["documentation"] = {
        "author": footer.get("sAuthor", ""),
        "department": footer.get("sDepartment", ""),
        "designer": title_page.get("sDesigner", ""),
        "project": title_page.get("sProject", ""),
        "general_info": general.get("sGeneralInfo", ""),
    }

    return parsed


def parse_xef_date(raw_date: str) -> datetime | None:
    """
    Parse a date from a XEF file, e.g. ``date_and_time#2021-9-18-19:20:12``.
    """
    m = re.match(
        r"(?:date_and_time|dt)#(\d{4})-(\d{1,2})-(\d{1,2})-(\d{1,2}):(\d{1,2}):(\d{1,2})",
        raw_date.strip(),
        re.IGNORECASE,
    )
    if not m:
        return None

    try:
        return datetime(*(int(v) for v in m.groups()))
    except ValueError:
        return None


def is_zef_file(data: BinaryIO | bytes) -> bool:
    """
    Check if data is a ZEF file, a ZIP archive containing a XEF (``unitpro.xef``).
    """
    if isinstance(data, bytes):
        data = io.BytesIO(data)

    try:
        with zipfile.ZipFile(data) as archive:
            return ZEF_XEF_NAME in archive.namelist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def extract_xef_from_zef(data: bytes) -> bytes:
    """
    Extract the XEF (``unitpro.xef``) from a ZEF file.

    Args:
        data: Contents of the ZEF file

    Returns:
        Contents of the XEF

    Raises:
        ValueError: If the data isn't a valid ZEF file
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            try:
                info = archive.getinfo(ZEF_XEF_NAME)
            except KeyError:
                raise ValueError(f"No {ZEF_XEF_NAME} file in ZEF archive") from None
            if info.file_size > MAX_ZEF_XEF_SIZE:
                raise ValueError(
                    f"{ZEF_XEF_NAME} in ZEF archive is too large ({info.file_size} bytes)"
                )
            return archive.read(info)
    except zipfile.BadZipFile as ex:
        raise ValueError(f"Invalid ZEF file: {ex}") from None


def serializable(parsed: dict) -> dict:
    """
    Copy of a parsed XEF project that can be saved as JSON, without the XML
    elements of the sections.
    """

    def strip(sections: list[dict]) -> list[dict]:
        return [{k: v for k, v in section.items() if k != "element"} for section in sections]

    return {
        **parsed,
        "sections": strip(parsed["sections"]),
        "dfb_types": {
            name: {**dfb, "sections": strip(dfb["sections"])}
            for name, dfb in parsed["dfb_types"].items()
        },
    }


def derived_types(parsed: dict) -> set[str]:
    """
    Names of the non-elementary types that variables of a parsed XEF project may use:
    DFBs, DDTs, and IEC 61131-3 standard function blocks.
    """
    return set(parsed["dfb_types"]) | set(parsed["ddt_types"]) | STANDARD_FB_TYPES


class TypeResolver:
    """
    Resolves the types of variables of a XEF project to TC6 types.

    Unity library function block types are mapped to the TC6 types of the
    blocks (see :class:`~peat.modules.schneider.xef.xef_lang.BlockLibrary`).
    """

    def __init__(self, parsed: dict, library: xef_lang.BlockLibrary) -> None:
        self.library = library
        #: TC6 name of each DDT, by lowercase Unity name. DDTs are renamed if
        #: their name is reserved or the name of a variable.
        self.ddts = {
            name.lower(): xef_lang.unique_name(name, library.taken, "_DDT")
            for name in parsed["ddt_types"]
        }
        #: Names of the non-elementary types
        self.names = (
            derived_types(parsed)
            | set(library.dfbs.values())
            | set(self.ddts.values())
            | {name for name in xef_lang.STANDARD_BLOCKS if _is_fb(name)}
        )

    def map_type(self, var_type: str) -> str:
        """Map a Unity type, or the element type of an array, to the TC6 type."""
        m = re.fullmatch(r"(ARRAY\s*\[.*\]\s*OF\s+)(\w+)", var_type.strip(), re.IGNORECASE)
        prefix, base = (m.group(1), m.group(2)) if m else ("", var_type.strip())
        if base.lower() in self.library.dfbs:
            # DFBs are renamed if their name is reserved
            return prefix + self.library.dfbs[base.lower()]
        if base.lower() in self.ddts:
            return prefix + self.ddts[base.lower()]
        if base in self.names or base.upper() in xef_lang.ELEMENTARY_TYPES:
            return var_type
        mapped = self.library.variable_type(base)
        if not mapped:
            return var_type
        self.names.add(mapped)
        return prefix + mapped

    def resolve(self, var_type: str) -> tuple[str, tuple[str, str] | None] | None:
        """Type name and array bounds, or :obj:`None` if the type isn't supported."""
        return m340_parse.resolve_type(self.map_type(var_type), self.names)

    def add_variable(
        self, var_list: Element, name: str, var_type: str, value: str | None = None
    ) -> bool:
        """
        Add a variable to a TC6 variable list.

        Returns:
            If the variable was added, which it isn't if the type isn't supported
        """
        resolved = self.resolve(var_type)
        if not resolved:
            return False
        type_str, arr_bounds = resolved
        m340_parse.add_tc6_variable(
            var_list,
            name,
            type_str,
            arr_bounds=arr_bounds,
            value=value,
            derived=type_str in self.names,
        )
        return True


@dataclass
class _Pou:
    """A program section converted to a POU."""

    section: dict
    name: str
    ctx: xef_lang.PouContext
    body: Element
    actions: list[tuple[str, Element]]

    @property
    def is_subroutine(self) -> bool:
        return self.section["type"] == "SR"


def _block_library(parsed: dict) -> xef_lang.BlockLibrary:
    """Block library for a parsed XEF project."""
    variable_names = set(parsed["variables"])
    for dfb in parsed["dfb_types"].values():
        for variables in dfb["variables"].values():
            variable_names |= set(variables)
    for ddt in parsed["ddt_types"].values():
        variable_names |= set(ddt["fields"])
    return xef_lang.BlockLibrary(set(parsed["dfb_types"]), parsed["library_types"], variable_names)


def _is_fb(block_name: str) -> bool:
    """If a standard block is a function block."""
    return StdBlckDct[block_name][0][1]["type"] == "functionBlock"


def add_project_to_tc6(parsed: dict, tc6: TC6) -> None:
    """
    Add a parsed XEF project to a TC6 instance.

    The project becomes a configuration (``Config0``) with one resource (``Res0``):

    - The variables are global variables of the resource. I/O variables are
      located at addresses OpenPLC can use (see
      :func:`~peat.modules.schneider.m340.m340_parse.add_located_variables`).
    - Each section becomes a program, which declares the global variables it
      uses as external variables. Function block instances only used by one
      section are declared by that section instead, since MatIEC can't call
      external function block instances.
    - Each Unity task becomes a task, which runs its sections in order.
      FAST has a higher priority than MAST, which is higher than AUX tasks.
    - Subroutine (SR) sections become function blocks, which the sections
      that call them declare an instance of.
    - Timer event sections run in a periodic task. I/O event sections are
      converted, but don't run.
    - The user-defined data types (DDTs) and function blocks (DFBs) become
      data types and function blocks. Unity library blocks without an IEC
      61131-3 equivalent become function blocks with an empty body.

    Args:
        parsed: Parsed XEF project, from :func:`parse_xef`
        tc6: TC6 class instance (NOTE: this will be modified!)
    """
    # The project has its own programs, so the default main program isn't used
    if tc6.main_pou in list(tc6.pous):
        tc6.pous.remove(tc6.main_pou)

    library = _block_library(parsed)
    types = TypeResolver(parsed, library)
    add_ddt_types_to_tc6(parsed, tc6, types)
    add_dfb_types_to_tc6(parsed, tc6, library, types)

    variables = {name: dict(var) for name, var in parsed["variables"].items()}
    project = xef_lang.ProjectContext(variables, library)

    # Names of POUs can't be the names of other POUs, types or variables
    taken = library.taken
    taken |= {n.lower() for n in [*variables, *parsed["ddt_types"]]}
    pous = [_convert_section(s, project, taken) for s in _ordered_sections(parsed)]

    # Sections that call a subroutine declare an instance of it, named after the subroutine
    subroutines = {p.section["name"].lower(): p for p in pous if p.is_subroutine}
    for pou in pous:
        for name in pou.ctx.referenced & set(subroutines):
            if subroutines[name] is not pou:
                pou.ctx.locals[subroutines[name].section["name"]] = subroutines[name].name
    types.names |= {p.name for p in subroutines.values()}
    types.names |= {o.type_name for o in project.operates}

    global_vars = {
        name: {**var, "type": types.map_type(var["type"])} for name, var in variables.items()
    }
    _localize_fb_instances(global_vars, pous, library, project)

    config = SubElement(tc6.configs, "configuration", {"name": "Config0"})
    resource = SubElement(config, "resource", {"name": "Res0"})
    _add_tasks(resource, parsed, pous)

    io_vars = SubElement(resource, "globalVars")
    other_vars = SubElement(resource, "globalVars")
    resolved = m340_parse.add_located_variables(global_vars, io_vars, other_vars, types.names)
    for var_list in [io_vars, other_vars]:
        if not len(var_list):
            resource.remove(var_list)

    for pou in pous:
        _add_pou(tc6, pou, project, resolved, types)

    for operate in project.operates:
        _add_operate_pou(tc6, operate, project, resolved, types)

    library.add_pous(tc6, types.add_variable)
    repair_tc6(tc6, {p.name for p in pous} | set(library.dfbs.values()))


def repair_tc6(tc6: TC6, converted: set[str], max_repairs: int = 50) -> None:
    """
    Replace the bodies of POUs that the TC6 to Structured Text conversion
    fails on, so the rest of the project can still be converted.

    Args:
        tc6: TC6 class instance (NOTE: this will be modified!)
        converted: Names of the POUs whose bodies can be replaced
        max_repairs: Most POUs to replace
    """
    pous = {pou.get("name"): pou for pou in tc6.pous}
    for _ in range(max_repairs):
        controller = PLCControler()
        error = controller.load_project(tc6.generate_xml_string().encode("utf-8"))
        if error:
            log.warning(f"TC6 XML of the project isn't valid: {error}")
            return
        _, errors, _ = controller.GenerateProgram()
        if not errors:
            return

        message = str(errors[0])
        names = [n for n in converted if re.search(rf"\b{re.escape(n)}\b", message)]
        if not names:
            log.warning(f"Failed to convert the TC6 XML to Structured Text: {message}")
            return
        name = max(names, key=len)
        log.warning(f"Logic of {name} couldn't be converted to Structured Text: {message}")

        pou = pous[name]
        if not any(v.get("name") == PLACEHOLDER_VAR for v in pou.iter("variable")):
            local_vars = ElementTree.SubElement(pou.find("interface"), "localVars")
            m340_parse.add_tc6_variable(local_vars, PLACEHOLDER_VAR, "BOOL")
        pou.remove(pou.find("body"))
        actions = pou.find("actions")
        if actions is not None:
            pou.remove(actions)
        comment = message.replace("(*", "(").replace("*)", ")")
        body = ElementTree.SubElement(pou, "body")
        ElementTree.SubElement(
            ElementTree.SubElement(body, "ST"), "xhtml:p"
        ).text = f"(* PEAT couldn't convert this logic: {comment} *)\n{PLACEHOLDER_VAR} := TRUE;\n"
        converted = converted - {name}


def _ordered_sections(parsed: dict) -> list[dict]:
    """Sections in task execution order, then the sections not in a task."""
    sections = {s["name"]: s for s in parsed["sections"]}
    ordered = []
    for task in parsed["tasks"].values():
        ordered.extend(sections[name] for name in task["sections"] if name in sections)
    ordered.extend(s for s in parsed["sections"] if s not in ordered)
    return ordered


def _convert_section(section: dict, project: xef_lang.ProjectContext, taken: set[str]) -> _Pou:
    """Convert a program section to the body of a POU."""
    # A subroutine's instance has the section's name, so its type needs another name
    name = section["name"] + ("_SR" if section["type"] == "SR" else "")
    ctx = xef_lang.PouContext(project, xef_lang.unique_name(name, taken, "_SECTION"))
    actions = []

    body = None
    if section["language"] == "SFC":
        sfc, actions = xef_lang.sfc_to_tc6(section["element"], ctx, section["name"])
        if len(sfc):
            body = Element("body")
            body.append(sfc)
    elif section.get("element") is not None:
        body = xef_lang.section_body(section["element"], ctx, section["name"])

    if body is None:
        body = xef_lang.placeholder_body(ctx, f"Section {section['name']} has no logic")
    return _Pou(section, ctx.name, ctx, body, actions)


def _localize_fb_instances(
    global_vars: dict[str, dict],
    pous: list[_Pou],
    library: xef_lang.BlockLibrary,
    project: xef_lang.ProjectContext,
) -> None:
    """
    Declare function block instances that are only used by one POU in that POU.

    MatIEC can't call function block instances that are external variables,
    so only instances used by more than one POU remain global variables.
    """
    fb_types = (
        set(library.dfbs.values())
        | {s.name for s in library.stubs.values()}
        | library.helpers
        | {o.type_name for o in project.operates}
        | {name for name in xef_lang.STANDARD_BLOCKS if _is_fb(name)}
    )
    for name, var in list(global_vars.items()):
        if var["type"] not in fb_types:
            continue
        users = [p for p in pous if name.lower() in p.ctx.referenced]
        if len(users) == 1:
            users[0].ctx.locals[name] = var["type"]
            del global_vars[name]
        elif len(users) > 1:
            log.warning(
                f"Function block instance {name} is used by {len(users)} sections, "
                f"so it's a global variable. MatIEC can't compile calls of it."
            )


def _add_tasks(resource: Element, parsed: dict, pous: list[_Pou]) -> None:
    """Add a task for each Unity task, and instances of the programs that run in them."""
    by_section = {p.section["name"]: p for p in pous}
    assigned = set()
    tasks: dict[str, Element] = {}

    for task_name, task in parsed["tasks"].items():
        interval = DEFAULT_TASK_INTERVAL
        if task.get("taskType") == "periodic" and task.get("valueType", "").isdigit():
            if int(task["valueType"]) > 0:
                interval = f"T#{int(task['valueType'])}ms"

        if task_name.upper().startswith("AUX") and task_name[3:].isdigit():
            priority = 2 + int(task_name[3:])
        else:
            priority = TASK_PRIORITIES.get(task_name.upper(), 1)

        element = SubElement(
            resource,
            "task",
            {
                "name": xef_lang.sanitize_name(task_name),
                "priority": str(priority),
                "interval": interval,
            },
        )
        tasks[task_name.upper()] = element
        for section_name in task["sections"]:
            pou = by_section.get(section_name)
            if pou is not None and not pou.is_subroutine:
                _add_instance(element, pou)
                assigned.add(section_name)

    for pou in pous:
        section = pou.section
        if section["name"] in assigned or pou.is_subroutine:
            continue

        if section["type"] == "Timer":
            interval = DEFAULT_TASK_INTERVAL
            time_base, preset = section.get("time_base", ""), section.get("preset", "")
            if time_base.isdigit() and preset.isdigit() and int(time_base) * int(preset) > 0:
                interval = f"T#{int(time_base) * int(preset)}ms"
            element = SubElement(
                resource,
                "task",
                {"name": f"{pou.name}_TIMER", "priority": "0", "interval": interval},
            )
            _add_instance(element, pou)
        elif section["type"] == "Evt":
            log.warning(
                f"I/O event section {section['name']} is converted, but isn't run by a task"
            )
        else:
            # A section that isn't in its task's section list
            task_name = section.get("task", "").upper() or "MAST"
            if task_name not in tasks:
                tasks[task_name] = SubElement(
                    resource,
                    "task",
                    {
                        "name": xef_lang.sanitize_name(task_name),
                        "priority": str(TASK_PRIORITIES.get(task_name, 1)),
                        "interval": DEFAULT_TASK_INTERVAL,
                    },
                )
            _add_instance(tasks[task_name], pou)


def _add_instance(task: Element, pou: _Pou) -> None:
    SubElement(task, "pouInstance", {"name": f"{pou.name}_inst", "typeName": pou.name})


def _add_externals(
    interface: Element,
    referenced: set[str],
    project: xef_lang.ProjectContext,
    resolved: dict[str, tuple[str, tuple[str, str] | None]],
    types: TypeResolver,
    exclude: set[str],
) -> None:
    """Declare the global variables a POU uses as external variables."""
    names = sorted(
        {project.names[r] for r in referenced if r in project.names} & set(resolved) - exclude,
        key=str.lower,
    )
    if not names:
        return
    external_vars = SubElement(interface, "externalVars")
    for name in names:
        type_str, arr_bounds = resolved[name]
        m340_parse.add_tc6_variable(
            external_vars, name, type_str, arr_bounds, derived=type_str in types.names
        )


def _add_pou(
    tc6: TC6,
    pou: _Pou,
    project: xef_lang.ProjectContext,
    resolved: dict[str, tuple[str, tuple[str, str] | None]],
    types: TypeResolver,
) -> None:
    element = tc6.make_pou(pou.name, "functionBlock" if pou.is_subroutine else "program")
    interface = element.find("interface")

    _add_externals(interface, pou.ctx.referenced, project, resolved, types, set(pou.ctx.locals))

    if pou.ctx.locals or not len(interface):
        if not len(interface):
            # MatIEC requires programs to have at least one variable
            pou.ctx.locals.setdefault(PLACEHOLDER_VAR, "BOOL")
        local_vars = SubElement(interface, "localVars")
        for name, var_type in pou.ctx.locals.items():
            if not types.add_variable(local_vars, name, var_type):
                log.warning(f"Skipping variable {name} of {pou.name} with type '{var_type}'")

    if pou.actions:
        actions = Element("actions")
        for name, body in pou.actions:
            action = SubElement(actions, "action", {"name": name})
            action.append(body)
        element.insert(list(element).index(element.find("body")), actions)

    element.remove(element.find("body"))
    element.append(pou.body)


def _add_operate_pou(
    tc6: TC6,
    operate: xef_lang.OperateBlock,
    project: xef_lang.ProjectContext,
    resolved: dict[str, tuple[str, tuple[str, str] | None]],
    types: TypeResolver,
) -> None:
    """Function block that runs the statement of an LD operate block."""
    element = tc6.make_pou(operate.type_name, "functionBlock")
    interface = element.find("interface")
    _add_externals(interface, operate.referenced, project, resolved, types, set())
    statement = operate.statement.rstrip()
    if not statement.endswith(";"):
        statement += ";"
    if not len(interface):
        types.add_variable(SubElement(interface, "localVars"), PLACEHOLDER_VAR, "BOOL")
    tc6.add_st_content_to_pou(element, f"(* LD operate block *)\n{statement}\n".encode())


def add_ddt_types_to_tc6(parsed: dict, tc6: TC6, types: TypeResolver | None = None) -> None:
    """
    Add the user-defined data types (DDTs) of a parsed XEF project to a TC6
    instance as structure data types. DDTs that aren't structures are skipped.

    Args:
        parsed: Parsed XEF project, from :func:`parse_xef`
        tc6: TC6 class instance (NOTE: this will be modified!)
        types: Type resolver for the project
    """
    data_types = tc6.types.find("dataTypes")
    if types is None:
        types = TypeResolver(parsed, _block_library(parsed))

    for ddt in parsed["ddt_types"].values():
        if not ddt["fields"]:
            log.warning(f"Skipping DDT {ddt['name']}, only structure DDTs are supported")
            continue

        tc6_name = types.ddts[ddt["name"].lower()]
        if tc6_name != ddt["name"]:
            log.warning(f"Renamed DDT {ddt['name']} to {tc6_name}, its name is taken")
        data_type = ElementTree.SubElement(data_types, "dataType", {"name": tc6_name})
        struct = ElementTree.SubElement(ElementTree.SubElement(data_type, "baseType"), "struct")
        for var_name, var_values in ddt["fields"].items():
            if not types.add_variable(
                struct, var_name, var_values["type"], var_values.get("value")
            ):
                log.warning(
                    f"Skipping variable {var_name} of DDT {ddt['name']} with "
                    f"unimplemented type '{var_values['type']}'"
                )


def add_dfb_types_to_tc6(
    parsed: dict,
    tc6: TC6,
    library: xef_lang.BlockLibrary | None = None,
    types: TypeResolver | None = None,
) -> None:
    """
    Add the user-defined function block (DFB) types of a parsed XEF project
    to a TC6 instance as function block POUs.

    A DFB with one section has a body in its language. The Structured Text
    sections of a DFB are combined, as are its FBD and LD sections. A DFB
    with sections in both text and graphical languages only has its Structured
    Text sections converted, and a comment marks where the others would run.

    Args:
        parsed: Parsed XEF project, from :func:`parse_xef`
        tc6: TC6 class instance (NOTE: this will be modified!)
        library: Block library for the blocks in the DFBs' sections
        types: Type resolver for the DFBs' variables
    """
    if library is None:
        library = _block_library(parsed)
    if types is None:
        types = TypeResolver(parsed, library)

    for dfb in parsed["dfb_types"].values():
        tc6_name = library.dfbs[dfb["name"].lower()]
        if tc6_name != dfb["name"]:
            log.warning(f"Renamed DFB {dfb['name']} to {tc6_name}, its name is reserved")
        pou = tc6.make_pou(tc6_name, pou_type="functionBlock")
        interface = pou.find("interface")

        dfb_vars = {}
        for xef_list, tc6_list in DFB_VAR_LISTS.items():
            variables = dfb["variables"].get(xef_list, {})
            if not variables:
                continue
            dfb_vars.update(variables)

            var_list = interface.find(tc6_list)
            if var_list is None:
                var_list = ElementTree.SubElement(interface, tc6_list)
            for var_name, var_values in variables.items():
                if not types.add_variable(
                    var_list, var_name, var_values["type"], var_values.get("value")
                ):
                    log.warning(
                        f"Skipping variable {var_name} of DFB {dfb['name']} with "
                        f"unimplemented type '{var_values['type']}'"
                    )

        project = xef_lang.ProjectContext(dfb_vars, library, allow_direct_variables=False)
        ctx = xef_lang.PouContext(project, dfb["name"])
        body = _dfb_body(dfb, ctx)

        if ctx.locals:
            var_list = interface.find("localVars")
            if var_list is None:
                var_list = ElementTree.SubElement(interface, "localVars")
            for name, var_type in ctx.locals.items():
                types.add_variable(var_list, name, var_type)

        pou.remove(pou.find("body"))
        pou.append(body)


def _dfb_body(dfb: dict, ctx: xef_lang.PouContext) -> Element:
    """Convert the sections of a DFB to the body of its POU."""
    sections = dfb["sections"]
    languages = {s["language"] for s in sections}

    if len(sections) == 1 and sections[0].get("element") is not None:
        body = xef_lang.section_body(sections[0]["element"], ctx, f"DFB {dfb['name']}")
        return body or xef_lang.placeholder_body(ctx, f"DFB {dfb['name']} has no logic")

    if sections and languages <= {"FBD", "LD"}:
        graph = xef_lang.Tc6Graph(ctx)
        for section in sections:
            name = f"DFB {dfb['name']} section {section['name']}"
            xef_lang.add_graphical_section(section["element"], graph, name)
            # The next section goes below this one
            graph.y_offset = graph.max_y + 4 * xef_lang.GRID
        if not graph.has_code:
            return xef_lang.placeholder_body(ctx, f"DFB {dfb['name']} has no logic")
        body = Element("body")
        body.append(graph.body_element())
        return body

    if languages - {"ST"}:
        log.warning(
            f"DFB {dfb['name']} has sections in both text and graphical languages, "
            f"only its Structured Text sections are converted"
        )
    st = _sections_to_st(sections)
    if not _has_st(sections):
        ctx.locals[PLACEHOLDER_VAR] = "BOOL"
    body = Element("body")
    ElementTree.SubElement(ElementTree.SubElement(body, "ST"), "xhtml:p").text = st
    return body


def _sections_to_st(sections: list[dict]) -> str:
    """
    Combine sections into Structured Text, with a comment before each.
    Sections in languages other than Structured Text are marked as not converted.
    """
    st_parts = []

    for section in sections:
        header = f"(* Section {section['name']} ({section['language']}"
        if section.get("task"):
            header += f", task {section['task']}"
        header += ") *)"

        if section["language"] == "ST":
            st_parts.append(f"{header}\n{section['source'].strip()}\n")
        else:
            st_parts.append(f"{header}\n(* Not converted to Structured Text by PEAT *)\n")

    if not _has_st(sections):
        st_parts.append(f"{PLACEHOLDER_VAR} := TRUE;\n")

    return "\n".join(st_parts)


def _has_st(sections: list[dict]) -> bool:
    """If any of the sections have Structured Text statements, not only comments."""
    return any(s["language"] == "ST" and xef_lang.st_has_statements(s["source"]) for s in sections)


def _find_attrib(element: Element, path: str) -> dict[str, str]:
    """Attributes of the first element matching a path, or an empty dict."""
    found = element.find(path)
    return found.attrib if found is not None else {}


def _part_item(element: Element) -> dict[str, str | int]:
    """Hardware part information of a PLC, rack, power supply or module."""
    part = _find_attrib(element, "partItem")
    if not part:
        return {}

    equip = _find_attrib(element, "equipInfo")
    info = {
        "family": part.get("family", ""),
        "part_number": part.get("partNumber", ""),
        "vendor": part.get("vendorName", ""),
        "version": part.get("version", ""),
        "topo_address": equip.get("topoAddress", ""),
    }
    try:
        info["position"] = int(equip.get("position", ""))
    except ValueError:
        pass

    return info


def _parse_variables(element: Element) -> dict[str, dict[str, str]]:
    """Parse the ``variables`` children of an element."""
    variables = {}

    for var in element.findall("variables"):
        name = var.get("name", "")
        if not name:
            continue

        var_info = {
            "type": var.get("typeName", ""),
            "address": var.get("topologicalAddress", "").upper(),
        }

        init = var.find("variableInit")
        if init is not None and init.get("value") is not None:
            var_info["value"] = init.get("value")

        comment = var.findtext("comment", default="").strip()
        if comment:
            var_info["comment"] = comment

        attributes = {a.get("name"): a.get("value") for a in var.findall("attribute")}
        if attributes:
            var_info["attributes"] = attributes

        variables[name] = var_info

    return variables


def _program_source(program: Element) -> tuple[str, str]:
    """Language and source (Structured Text and IL only) of a program section."""
    if program.tag == "SFCProgram":
        return "SFC", ""
    for tag, language in LANGUAGE_TAGS.items():
        source = program.find(tag)
        if source is not None:
            text = (source.text or "") if language in ["ST", "IL"] else ""
            return language, text

    return "", ""


def _parse_dfb(fb_source: Element) -> dict:
    """Parse a user-defined function block (DFB) type."""
    dfb = {
        "name": fb_source.get("nameOfFBType", ""),
        "version": fb_source.get("version", ""),
        "date": fb_source.get("dateTime", ""),
        "comment": fb_source.findtext("comment", default="").strip(),
        "variables": {},
        "sections": [],
    }

    for var_list in DFB_VAR_LISTS:
        element = fb_source.find(var_list)
        if element is not None:
            dfb["variables"].setdefault(var_list, {}).update(_parse_variables(element))

    for fb_program in fb_source.findall("FBProgram"):
        language, source = _program_source(fb_program)
        dfb["sections"].append(
            {
                "name": fb_program.get("name", ""),
                "language": language,
                "source": source,
                "element": fb_program,
            }
        )

    return dfb


def _parse_library_type(source: Element, kind: str) -> dict:
    """Parse the interface of a Unity library function (EF) or function block (EFB)."""
    info = {
        "name": source.get("nameOfEFType") or source.get("nameOfEFBType") or "",
        "kind": kind,
        "comment": source.findtext("comment", default="").strip(),
        "inputs": {},
        "outputs": {},
        "in_outs": {},
    }

    for tag, key in [
        ("inputParameters", "inputs"),
        ("outputParameters", "outputs"),
        ("inOutParameters", "in_outs"),
    ]:
        for var in source.findall(f"ExternalToolsOnly/{tag}/variables"):
            attributes = {a.get("name"): a.get("value") for a in var.findall("attribute")}
            if attributes.get("IsVariableHidden") in ["-1", "1", "TRUE"]:
                continue
            info[key][var.get("name", "")] = var.get("typeName", "")

    return info
