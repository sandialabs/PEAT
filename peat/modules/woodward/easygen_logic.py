"""
Woodward easYgen LogicsManager equations as IEC 61131-3 Structured Text and
PLCopen TC6 XML.

The LogicsManager is the programmable logic of the easYgen genset
controllers: it decides when relays close, when the engine starts, which
alarms are inhibited, and so on. Every LogicsManager parameter (e.g.
``12200 Inhibit emerg..run`` or ``12110 Relay 2``) is one equation::

    output = ((sign1(cv1) operator1 sign2(cv2)) operator2 sign3(cv3)), delayed

- ``cv1``..``cv3`` are *command variables*, boolean values of the control
  such as ``03.05 Horn`` or ``00.01 LM: Flag 1`` (the output of another
  equation).
- The *signs* are per-input operators: pass-through (``NoOperator``),
  ``Not``, or a fixed ``True``/``False`` that ignores the command variable.
- The *operators* are ``And``, ``Nand``, ``Or``, ``Nor``, ``Xor``, and ``Nxor``.
- *Delay ON* is the time the equation must be true before the output
  becomes true, and *Delay OFF* the time it must be false before the output
  becomes false (``TON`` and ``TOF`` timers in IEC 61131-3 terms).

The equations are chained left to right, matching the order of the
LogicsManager "command chain" documented in the easYgen Modbus appendix
(sign 1, operator 1, sign 2, operator 2, sign 3).

The conversion produces one ``PROGRAM`` with a ``BOOL`` variable per
command variable (``CV_03_05``) and per equation output (``LM_12110``), and
``TON``/``TOF`` function block instances for the delays. The PLCopen TC6
XML is built with :class:`~peat.parsing.tc6.TC6`, the same class the
Schneider M340 and Rockwell modules use, so the easYgen logic goes through
the same Structured Text generation and SCEPTRE/OpenPLC compatibility
options as the PLC logic PEAT parses.

.. note::
   Operator and sign semantics were verified against the easYgen-3400/3500
   manual (37528, tables 102/103 and 117). The AnalogManager (the analog
   counterpart of the LogicsManager) isn't converted: in settings files it
   is stored as data source selections, not as equations.
"""

import re
from typing import Any, Final
from xml.etree.ElementTree import SubElement

from peat import DeviceData, log
from peat.parsing.tc6 import TC6

#: Structured Text for each LogicsManager binary operator
ST_BINARY_OPERATORS: Final[dict[str, str]] = {
    "And": "{a} AND {b}",
    "Nand": "NOT ({a} AND {b})",
    "Or": "{a} OR {b}",
    "Nor": "NOT ({a} OR {b})",
    "Xor": "{a} XOR {b}",
    "Nxor": "NOT ({a} XOR {b})",
}

#: Structured Text for each LogicsManager sign (per-input operator)
ST_SIGNS: Final[dict[str, str]] = {
    "NoOperator": "{v}",
    "Not": "NOT {v}",
    "True": "TRUE",
    "False": "FALSE",
}

_CV_NUMBER_RE: Final[re.Pattern[str]] = re.compile(r"^(\d{2})\.(\d{2})\b")
_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_]+")


def st_identifier(text: str, prefix: str = "") -> str:
    """
    Make a valid IEC 61131-3 identifier from arbitrary text.

    Args:
        text: The text, e.g. a parameter label
        prefix: Prefix to add, e.g. ``LM_``

    Returns:
        The identifier, e.g. ``LM_Inhibit_emerg_run``
    """
    identifier = _IDENTIFIER_RE.sub("_", text.strip()).strip("_")
    identifier = re.sub(r"_+", "_", identifier)
    if not identifier:
        identifier = "unnamed"
    identifier = f"{prefix}{identifier}"
    if identifier[0].isdigit():
        identifier = f"_{identifier}"
    return identifier


def command_variable_identifier(name: str) -> str:
    """
    Identifier of a LogicsManager command variable.

    Command variables are numbered (``03.05 Horn``), so the number is used
    for a short, stable identifier: ``CV_03_05``.

    Args:
        name: The command variable name

    Returns:
        The identifier
    """
    match = _CV_NUMBER_RE.match(name.strip())
    if match:
        return f"CV_{match.group(1)}_{match.group(2)}"
    return st_identifier(name, "CV_")


def output_identifier(record: dict[str, Any]) -> str:
    """
    Identifier of a LogicsManager equation output, e.g. ``LM_12110``.

    Args:
        record: The LogicsManager parameter record

    Returns:
        The identifier
    """
    if record.get("id"):
        return f"LM_{record['id']}"
    return st_identifier(record.get("label") or record.get("name") or "", "LM_")


def time_literal(seconds: Any) -> str:
    """Convert a delay in seconds to a Structured Text time literal, e.g. ``T#500ms``."""
    try:
        milliseconds = round(float(seconds) * 1000)
    except (TypeError, ValueError):
        milliseconds = 0
    return f"T#{milliseconds}ms"


def _equation(record: dict[str, Any]) -> dict[str, Any] | None:
    """The equation of a LogicsManager record (its value, or its default from a SID)."""
    value = record.get("value")
    if not isinstance(value, dict) or "input_1" not in value:
        value = record.get("initial")
    if not isinstance(value, dict) or "input_1" not in value:
        return None
    return value


def _input_name(equation: dict[str, Any], number: int) -> str:
    selector = equation.get(f"input_{number}")
    if isinstance(selector, dict):
        name = str(selector.get("name") or "")
        if not name and selector.get("value") is not None:
            name = f"command variable {selector['value']}"
        return name
    if isinstance(selector, str):
        return selector
    return ""


def equation_to_st(
    record: dict[str, Any], identifiers: dict[str, str]
) -> tuple[list[str], list[tuple[str, str]], int]:
    """
    Convert one LogicsManager equation to Structured Text statements.

    Args:
        record: The LogicsManager parameter record (from
            :func:`~peat.modules.woodward.parse_wset.parse_wset` or
            :func:`~peat.modules.woodward.parse_sid.parse_sid`)
        identifiers: Command variable identifiers by name, updated with any
            new command variables

    Returns:
        A tuple of the statements, the ``(name, type)`` function block
        instances the statements use, and the number of unknown operators
    """
    equation = _equation(record)
    output = output_identifier(record)
    label = record.get("label") or record.get("name") or output
    group = record.get("group") or record.get("path") or ""
    header = f"(* {record.get('id') or ''} {label}".strip() + (
        f" [{group}] *)" if group else " *)"
    )
    if equation is None:
        return [header, f"(* no equation for {output} *)"], [], 0

    unknown = 0
    terms = []
    for number in (1, 2, 3):
        name = _input_name(equation, number)
        identifier = (
            identifiers.setdefault(name, command_variable_identifier(name)) if name else "FALSE"
        )
        sign = str(equation.get(f"operator_{number}") or "NoOperator")
        template = ST_SIGNS.get(sign)
        if template is None:
            unknown += 1
            terms.append(f"{identifier} (* unknown sign {sign} *)")
        else:
            terms.append(template.format(v=identifier))

    expression = terms[0]
    for number, term in ((1, terms[1]), (2, terms[2])):
        operator = str(equation.get(f"binary_operator_{number}") or "And")
        template = ST_BINARY_OPERATORS.get(operator)
        if template is None:
            unknown += 1
            template = "{a} AND {b} (* unknown operator " + operator + " *)"
        expression = "(" + template.format(a=expression, b=term) + ")"

    delay_on = equation.get("delay_on") or 0
    delay_off = equation.get("delay_off") or 0
    try:
        has_on = float(delay_on) > 0
        has_off = float(delay_off) > 0
    except (TypeError, ValueError):
        has_on = has_off = False

    lines = [header]
    blocks: list[tuple[str, str]] = []
    if not has_on and not has_off:
        lines.append(f"{output} := {expression};")
        return lines, blocks, unknown

    signal = f"{output}_IN"
    lines.append(f"{signal} := {expression};")
    if has_on:
        blocks.append((f"{output}_TON", "TON"))
        lines.append(f"{output}_TON(IN := {signal}, PT := {time_literal(delay_on)});")
        signal = f"{output}_TON.Q"
    if has_off:
        blocks.append((f"{output}_TOF", "TOF"))
        lines.append(f"{output}_TOF(IN := {signal}, PT := {time_literal(delay_off)});")
        signal = f"{output}_TOF.Q"
    lines.append(f"{output} := {signal};")
    return lines, blocks, unknown


def logics_manager_program(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Build the Structured Text program body for a set of LogicsManager equations.

    Args:
        records: Parameter records, only ``logics_manager`` records are used

    Returns:
        A :class:`dict` with the program ``body`` (statements), the
        ``variables`` (``{"name", "type", "comment"}``) to declare, the
        ``command_variables`` (``{name: identifier}``), ``num_equations``,
        and the number of ``unknown_operators``
    """
    equations = [r for r in records if r.get("kind") == "logics_manager"]
    identifiers: dict[str, str] = {}
    statements: list[str] = []
    blocks: list[tuple[str, str]] = []
    outputs: list[tuple[str, str]] = []
    unknown = 0
    intermediates: list[str] = []

    for record in sorted(equations, key=lambda r: (r.get("id") or 0, r.get("name", ""))):
        lines, record_blocks, record_unknown = equation_to_st(record, identifiers)
        output = output_identifier(record)
        outputs.append((output, record.get("name", "")))
        if record_blocks:
            intermediates.append(f"{output}_IN")
        statements.extend(lines)
        statements.append("")
        blocks.extend(record_blocks)
        unknown += record_unknown

    variables: list[dict[str, str]] = [
        {"name": identifier, "type": "BOOL", "comment": name}
        for name, identifier in sorted(identifiers.items(), key=lambda item: item[1])
    ]
    variables.extend({"name": output, "type": "BOOL", "comment": name} for output, name in outputs)
    variables.extend({"name": name, "type": "BOOL", "comment": ""} for name in intermediates)
    variables.extend({"name": name, "type": block, "comment": ""} for name, block in blocks)

    body_lines = []
    if identifiers:
        body_lines.append("(* LogicsManager command variables *)")
        body_lines.extend(
            f"(* {identifier} : {name} *)"
            for name, identifier in sorted(identifiers.items(), key=lambda item: item[1])
        )
        body_lines.append("")
    body_lines.extend(statements)

    if unknown:
        log.warning(f"{unknown} unknown LogicsManager operators, check the generated logic")

    return {
        "body": "\n".join(body_lines).rstrip() + "\n",
        "variables": variables,
        "command_variables": identifiers,
        "num_equations": len(equations),
        "unknown_operators": unknown,
    }


def logics_manager_tc6(
    program: dict[str, Any],
    project_name: str = "easYgen LogicsManager",
    product_name: str = "",
    product_version: str = "",
    description: str = "",
) -> TC6:
    """
    Build a PLCopen TC6 project for a LogicsManager program.

    Args:
        program: Output of :func:`logics_manager_program`
        project_name: TC6 project name
        product_name: Device name for the TC6 file header
        product_version: Device firmware or application version
        description: Content description for the TC6 file header

    Returns:
        The TC6 project, with the equations as a Structured Text ``main`` program
    """
    tc6 = TC6(
        project_name=project_name,
        product_name=product_name,
        product_version=product_version,
        company_name="Woodward",
        content_description=description,
    )
    interface = tc6.main_pou.find("interface")
    local_vars = SubElement(interface, "localVars")
    for variable in program["variables"]:
        element = SubElement(local_vars, "variable", {"name": variable["name"]})
        type_element = SubElement(element, "type")
        if variable["type"] in ("TON", "TOF"):
            SubElement(type_element, "derived", {"name": variable["type"]})
        else:
            SubElement(type_element, variable["type"])
        if variable.get("comment"):
            documentation = SubElement(element, "documentation")
            SubElement(documentation, "xhtml:p").text = variable["comment"]
    tc6.add_st_content_to_pou(tc6.main_pou, program["body"].encode("utf-8"))
    return tc6


def expression_listing(records: list[dict[str, Any]]) -> str:
    """
    Human-readable listing of the LogicsManager equations, one per line.

    Args:
        records: Parameter records, only ``logics_manager`` records are used

    Returns:
        Lines such as ``Config_IO.Discrete_Out.02.12110 Relay 2 = [NoOperator 03.05 Horn]
        And [True 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1], delay on 0 s, delay off 0 s``
    """
    lines = []
    for record in sorted(
        (r for r in records if r.get("kind") == "logics_manager"),
        key=lambda r: (r.get("id") or 0, r.get("name", "")),
    ):
        expression = record.get("expression")
        if not expression:
            continue
        name = record.get("name") or record.get("label") or ""
        lines.append(f"{name} = {expression}")
    return "\n".join(lines) + ("\n" if lines else "")


def add_logics_manager_logic(
    dev: DeviceData, parsed: dict[str, Any], sceptre: bool = False
) -> dict[str, Any]:
    """
    Add the LogicsManager equations of a parsed settings file to a device's logic.

    Sets ``dev.logic.original`` to the readable equation listing,
    ``dev.logic.parsed`` and ``dev.logic.formats["structured_text"]`` to the
    generated Structured Text, and ``dev.logic.formats["tc6"]`` to the
    PLCopen TC6 XML.

    Args:
        dev: The device
        parsed: Output of :func:`~peat.modules.woodward.parse_wset.parse_wset`
        sceptre: Generate SCEPTRE/OpenPLC compatible Structured Text

    Returns:
        The program information from :func:`logics_manager_program`, or an
        empty :class:`dict` if there are no equations
    """
    records = parsed.get("parameters", [])
    program = logics_manager_program(records)
    if not program["num_equations"]:
        return {}

    application = parsed.get("application", {})
    name = application.get("product") or application.get("id") or "easYgen"
    version = application.get("version") or ""
    tc6 = logics_manager_tc6(
        program,
        project_name=f"{name} LogicsManager",
        product_name=name,
        product_version=version,
        description=(
            f"LogicsManager equations from ToolKit application {application.get('id', '')}"
        ),
    )
    xml_string = tc6.generate_xml_string(sceptre=sceptre)
    st_logic = tc6.generate_st(xml_string, sceptre=sceptre)

    if not dev.logic.name:
        dev.logic.name = f"{name} LogicsManager"
    if not dev.logic.description:
        dev.logic.description = (
            f"{program['num_equations']} LogicsManager equations "
            f"({len(program['command_variables'])} command variables)"
        )
    dev.logic.original = expression_listing(records)
    if st_logic:
        dev.logic.parsed = st_logic
        dev.logic.formats["structured_text"] = st_logic
    else:
        log.warning("Structured Text generation failed, storing the program body only")
        dev.logic.parsed = program["body"]
    dev.logic.formats["tc6"] = xml_string
    program["structured_text"] = st_logic
    program["tc6"] = xml_string
    return program


__all__ = [
    "ST_BINARY_OPERATORS",
    "ST_SIGNS",
    "add_logics_manager_logic",
    "command_variable_identifier",
    "equation_to_st",
    "expression_listing",
    "logics_manager_program",
    "logics_manager_tc6",
    "output_identifier",
    "st_identifier",
    "time_literal",
]
