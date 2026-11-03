"""Tests for the LogicsManager to Structured Text/TC6 conversion (easygen_logic.py)."""

import gzip
import re
from pathlib import Path
from typing import Final

import pytest

from peat import DeviceData
from peat.modules.woodward.easygen_logic import (
    ST_BINARY_OPERATORS,
    ST_SIGNS,
    add_logics_manager_logic,
    command_variable_constant,
    command_variable_identifier,
    delay_seconds,
    equation_result_label,
    equation_to_st,
    expression_listing,
    link_command_variables,
    logics_manager_program,
    logics_manager_tc6,
    output_identifier,
    st_identifier,
    time_literal,
)
from peat.modules.woodward.parse_wset import parse_wset

REAL_WSET_GZ: Final[Path] = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "devices"
    / "woodward"
    / "easygen-3500"
    / "4_MVA_Diesel_20161116.wset.gz"
)


def equation(
    inputs=("03.05 Horn", "00.01 LM: Flag 1", "00.01 LM: Flag 1"),
    operators=("NoOperator", "True", "True"),
    binary=("And", "And"),
    delay_on=0,
    delay_off=0,
) -> dict:
    """A LogicsManager parameter record like the ones parse_wset() produces."""
    value = {
        "input_1": {"value": 183, "name": inputs[0]},
        "operator_1": operators[0],
        "binary_operator_1": binary[0],
        "input_2": {"value": 0, "name": inputs[1]},
        "operator_2": operators[1],
        "binary_operator_2": binary[1],
        "input_3": {"value": 0, "name": inputs[2]},
        "operator_3": operators[2],
        "delay_on": delay_on,
        "delay_off": delay_off,
        "delay_units": "s",
    }
    return {
        "name": "Config_IO.Discrete_Out.02.12110 Relay 2",
        "group": "Config_IO.Discrete_Out.02",
        "id": 12110,
        "label": "Relay 2",
        "kind": "logics_manager",
        "type": "logics_manager",
        "value": value,
        "expression": "[NoOperator 03.05 Horn] And [True 00.01 LM: Flag 1] "
        "And [True 00.01 LM: Flag 1], delay on 0 s, delay off 0 s",
    }


@pytest.mark.parametrize(
    ("text", "prefix", "expected"),
    [
        ("Inhibit emerg..run", "LM_", "LM_Inhibit_emerg_run"),
        ("03.05 Horn", "", "_03_05_Horn"),
        ("   ", "", "unnamed"),
        ("a--b__c", "", "a_b_c"),
        ("1st", "", "_1st"),
    ],
)
def test_st_identifier(text, prefix, expected):
    assert st_identifier(text, prefix) == expected


def test_command_variable_identifier():
    assert command_variable_identifier("03.05 Horn") == "CV_03_05"
    assert command_variable_identifier("  00.01 LM: Flag 1") == "CV_00_01"
    assert command_variable_identifier("28.06 Command 6 to LS5(OR) ") == "CV_28_06"
    assert command_variable_identifier("Custom input") == "CV_Custom_input"


def test_output_identifier():
    assert output_identifier({"id": 12110, "label": "Relay 2"}) == "LM_12110"
    assert output_identifier({"id": None, "label": "Relay 2"}) == "LM_Relay_2"
    assert output_identifier({"name": "x.y"}) == "LM_x_y"


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (0, "T#0ms"),
        (0.5, "T#500ms"),
        (50, "T#50000ms"),
        ("2.25", "T#2250ms"),
        ("bad", "T#0ms"),
        (None, "T#0ms"),
    ],
)
def test_time_literal(seconds, expected):
    assert time_literal(seconds) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 0.0),
        ("", 0.0),
        (0, 0.0),
        (1.5, 1.5),
        (" 2.25 ", 2.25),
        ("0,5", 0.5),
        ("bad", None),
        ([1], None),
        (10**400, None),
        (float("inf"), None),
        (float("nan"), None),
        ("-inf", None),
        (-0.5, None),
    ],
)
def test_delay_seconds(value, expected):
    assert delay_seconds(value) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("00.01 LM: Flag 1", "Flag 1"),
        ("96.01 LM: Flag 1 ", "Flag 1"),
        ("lm:Start w/o load", "Start w/o load"),
        ("03.05 Horn", ""),
        ("28.01 Command 1 to LS5(OR) ", ""),
    ],
)
def test_equation_result_label(name, expected):
    assert equation_result_label(name) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("02.01 LM FALSE", "FALSE"),
        ("02.02 LM TRUE ", "TRUE"),
        ("lm true", "TRUE"),
        ("00.01 LM: Flag 1", ""),
        ("03.05 Horn", ""),
    ],
)
def test_command_variable_constant(name, expected):
    assert command_variable_constant(name) == expected


def test_logics_manager_program_constants():
    program = logics_manager_program(
        [equation(inputs=("02.02 LM TRUE", "02.01 LM FALSE", "03.05 Horn"))]
    )
    assert program["constant_command_variables"] == {"CV_02_01": "FALSE", "CV_02_02": "TRUE"}
    comments = {v["name"]: v["comment"] for v in program["variables"]}
    assert comments["CV_02_02"] == "02.02 LM TRUE (constant TRUE)"
    assert comments["CV_03_05"] == "03.05 Horn"
    body = program["body"]
    assert "CV_02_01 := FALSE;\nCV_02_02 := TRUE;\n" in body
    assert body.index("CV_02_02 := TRUE;") < body.index("LM_12110 :=")


def test_link_command_variables():
    flag = {**equation(), "id": 12230, "label": "Flag 1"}
    start = {**equation(), "id": 12120, "label": "Start req. in AUTO"}
    duplicate = {**equation(), "id": 99, "label": "Relay 2"}
    no_equation = {"id": 5, "label": "Flag 2", "kind": "logics_manager"}
    identifiers = {
        "00.01 LM: Flag 1": "CV_00_01",
        "86.09 LM: Start req.in AUTO": "CV_86_09",
        "00.42 LM: Relay 2": "CV_00_42",  # two equations with this label
        "00.02 LM: Flag 2": "CV_00_02",  # no equation
        "03.05 Horn": "CV_03_05",
    }
    links = link_command_variables(
        [equation(), flag, start, duplicate, no_equation, {"kind": "logics_manager"}],
        identifiers,
    )
    assert links == {"CV_00_01": "LM_12230", "CV_86_09": "LM_12120"}


def test_equation_without_delays():
    identifiers: dict[str, str] = {}
    lines, blocks, unknown = equation_to_st(equation(), identifiers)
    assert lines == [
        "(* 12110 Relay 2 [Config_IO.Discrete_Out.02] *)",
        "LM_12110 := ((CV_03_05 AND TRUE) AND TRUE);",
    ]
    assert blocks == []
    assert unknown == 0
    assert identifiers == {"03.05 Horn": "CV_03_05", "00.01 LM: Flag 1": "CV_00_01"}


def test_equation_with_delays_and_operators():
    record = equation(
        inputs=("03.05 Horn", "07.25 Mains ok", "02.01 LM FALSE"),
        operators=("Not", "NoOperator", "False"),
        binary=("Or", "Nand"),
        delay_on=1.5,
        delay_off=0.25,
    )
    lines, blocks, unknown = equation_to_st(record, {})
    assert lines == [
        "(* 12110 Relay 2 [Config_IO.Discrete_Out.02] *)",
        "LM_12110_IN := (NOT ((NOT CV_03_05 OR CV_07_25) AND FALSE));",
        "LM_12110_TON(IN := LM_12110_IN, PT := T#1500ms);",
        "LM_12110_TOF(IN := LM_12110_TON.Q, PT := T#250ms);",
        "LM_12110 := LM_12110_TOF.Q;",
    ]
    assert blocks == [("LM_12110_TON", "TON"), ("LM_12110_TOF", "TOF")]
    assert unknown == 0


def test_equation_delay_off_only():
    lines, blocks, _ = equation_to_st(equation(delay_off=2), {})
    assert lines[2] == "LM_12110_TOF(IN := LM_12110_IN, PT := T#2000ms);"
    assert lines[3] == "LM_12110 := LM_12110_TOF.Q;"
    assert blocks == [("LM_12110_TOF", "TOF")]


def test_equation_invalid_delays():
    lines, blocks, _ = equation_to_st(equation(delay_on="bad", delay_off=float("nan")), {})
    assert lines[1] == "LM_12110 := ((CV_03_05 AND TRUE) AND TRUE);"
    assert blocks == []


def test_equation_input_selectors():
    record = equation()
    record["value"]["input_1"] = "03.05 Horn"
    record["value"]["input_2"] = None
    record["value"]["input_3"] = {"value": 7}
    identifiers: dict[str, str] = {}
    lines, _, _ = equation_to_st(record, identifiers)
    assert lines[1] == "LM_12110 := ((CV_03_05 AND TRUE) AND TRUE);"
    assert identifiers == {
        "03.05 Horn": "CV_03_05",
        "command variable 7": "CV_command_variable_7",
    }


def test_equation_unknown_operators():
    record = equation(
        operators=("unknown(7)", "NoOperator", "NoOperator"), binary=("unknown(9)", "And")
    )
    lines, _, unknown = equation_to_st(record, {})
    assert unknown == 2
    assert "unknown sign unknown(7)" in lines[1]
    assert "unknown operator unknown(9)" in lines[1]


def test_equation_from_sid_defaults_and_missing():
    sid_record = {
        "name": "12922 Ext. mns.decoupl.",
        "id": 12922,
        "label": "Ext. mns.decoupl.",
        "path": "PARAMETER.Configuration",
        "kind": "logics_manager",
        "initial": {
            "delay_on": 0.0,
            "delay_off": 0.0,
            "operator_1": "False",
            "binary_operator_1": "And",
            "operator_2": "True",
            "binary_operator_2": "And",
            "operator_3": "True",
            "input_1": {"value": 201, "name": "02.01 LM FALSE"},
            "input_2": {"value": 201, "name": "02.01 LM FALSE"},
            "input_3": {"value": 201, "name": ""},
        },
    }
    lines, _, _ = equation_to_st(sid_record, {})
    assert lines[0] == "(* 12922 Ext. mns.decoupl. [PARAMETER.Configuration] *)"
    assert lines[1] == "LM_12922 := ((FALSE AND TRUE) AND TRUE);"

    lines, blocks, unknown = equation_to_st(
        {"id": 5, "label": "No equation", "kind": "logics_manager"}, {}
    )
    assert lines == ["(* 5 No equation *)", "(* no equation for LM_5 *)"]
    assert blocks == []
    assert unknown == 0


def test_all_operators_have_st():
    assert set(ST_SIGNS) == {"NoOperator", "Not", "True", "False"}
    assert set(ST_BINARY_OPERATORS) == {"And", "Nand", "Or", "Nor", "Xor", "Nxor"}


def test_logics_manager_program():
    records = [
        equation(),
        {"name": "x.1702 Device number", "kind": "basic", "value": 1},
        {
            **equation(delay_on=1),
            "name": "Config_Application.12200 Inhibit emerg..run",
            "id": 12200,
            "label": "Inhibit emerg..run",
            "group": "Config_Application",
        },
    ]
    program = logics_manager_program(records)
    assert program["num_equations"] == 2
    assert program["unknown_operators"] == 0
    assert program["command_variables"] == {
        "03.05 Horn": "CV_03_05",
        "00.01 LM: Flag 1": "CV_00_01",
    }
    names = [(v["name"], v["type"]) for v in program["variables"]]
    assert names == [
        ("CV_00_01", "BOOL"),
        ("CV_03_05", "BOOL"),
        ("LM_12110", "BOOL"),
        ("LM_12200", "BOOL"),
        ("LM_12200_IN", "BOOL"),
        ("LM_12200_TON", "TON"),
    ]
    assert program["variables"][0]["comment"] == "00.01 LM: Flag 1"
    body = program["body"]
    assert body.startswith(
        "(* LogicsManager command variables *)\n(* CV_00_01 : 00.01 LM: Flag 1 *)\n"
    )
    assert "LM_12110 := ((CV_03_05 AND TRUE) AND TRUE);" in body
    assert "LM_12200_TON(IN := LM_12200_IN, PT := T#1000ms);" in body
    assert body.index("12110 Relay 2") < body.index("12200 Inhibit")  # sorted by parameter number

    unknown = logics_manager_program(
        [equation(binary=("unknown(9)", "And")), {"id": 5, "kind": "logics_manager"}]
    )
    assert unknown["unknown_operators"] == 1
    assert unknown["num_equations"] == 2
    assert "(* no equation for LM_5 *)" in unknown["body"]

    empty = logics_manager_program([{"kind": "basic"}])
    assert empty["num_equations"] == 0
    assert empty["body"] == "\n"


def test_logics_manager_tc6_and_structured_text():
    program = logics_manager_program([equation(delay_on=1, delay_off=0.5)])
    tc6 = logics_manager_tc6(
        program, project_name="Test", product_name="easYgen-3500", product_version="1.2"
    )
    assert not tc6.logic_is_empty()
    xml = tc6.generate_xml_string()
    assert 'productName="easYgen-3500"' in xml
    assert 'companyName="Woodward"' in xml
    compact = re.sub(r">\s+<", "><", xml)
    assert '<variable name="LM_12110_TON"><type><derived name="TON"/></type>' in compact
    assert "<documentation><xhtml:p>03.05 Horn</xhtml:p></documentation>" in compact
    st = tc6.generate_st(xml)
    assert st.startswith("PROGRAM main\n  VAR\n")
    assert "    LM_12110_TON : TON;" in st
    assert "    LM_12110_TOF : TOF;" in st
    assert "  LM_12110_TON(IN := LM_12110_IN, PT := T#1000ms);" in st
    assert "  LM_12110 := LM_12110_TOF.Q;" in st
    assert st.rstrip().endswith("END_PROGRAM")
    sceptre = tc6.generate_st(sceptre=True)
    assert "CONFIGURATION" in sceptre


def test_expression_listing():
    records = [
        equation(),
        {"kind": "basic", "name": "x"},
        {**equation(), "id": 12120, "expression": ""},
    ]
    listing = expression_listing(records)
    assert listing == (
        "Config_IO.Discrete_Out.02.12110 Relay 2 = [NoOperator 03.05 Horn] "
        "And [True 00.01 LM: Flag 1] And [True 00.01 LM: Flag 1], delay on 0 s, delay off 0 s\n"
    )
    assert expression_listing([]) == ""


def test_add_logics_manager_logic():
    parsed = {
        "application": {
            "id": "EG3200XTP1 2.12-0_50976",
            "product": "easYgen-3200XT-P1",
            "version": "2.12-0",
        },
        "parameters": [equation(delay_on=1)],
    }
    dev = DeviceData()
    program = add_logics_manager_logic(dev, parsed)
    assert program["num_equations"] == 1
    assert program["structured_text"].strip() == dev.logic.parsed.strip()
    assert dev.logic.name == "easYgen-3200XT-P1 LogicsManager"
    assert dev.logic.description == "1 LogicsManager equations (2 command variables)"
    assert dev.logic.original.startswith("Config_IO.Discrete_Out.02.12110 Relay 2 = ")
    assert dev.logic.formats["structured_text"].strip() == dev.logic.parsed.strip()
    assert "PROGRAM main" in dev.logic.parsed
    assert 'productVersion="2.12-0"' in dev.logic.formats["tc6"]
    dev.logic.annotate(dev)
    assert dev.logic.hash.sha256  # hashed from the original listing

    # Existing names are kept, no equations means nothing is changed
    dev2 = DeviceData()
    dev2.logic.name = "existing"
    assert add_logics_manager_logic(dev2, {"parameters": [{"kind": "basic"}]}) == {}
    assert dev2.logic.parsed == ""
    dev2.logic.description = "existing description"
    add_logics_manager_logic(dev2, parsed)
    assert dev2.logic.name == "existing"
    assert dev2.logic.description == "existing description"


def test_add_logics_manager_logic_st_failure(monkeypatch):
    monkeypatch.setattr(
        "peat.modules.woodward.easygen_logic.TC6.generate_st", lambda *_args, **_kwargs: ""
    )
    dev = DeviceData()
    program = add_logics_manager_logic(dev, {"parameters": [equation()]})
    assert program["structured_text"] == ""
    assert dev.logic.parsed.strip() == program["body"].strip()
    assert "structured_text" not in dev.logic.formats
    assert dev.logic.formats["tc6"] == program["tc6"]
    assert dev.logic.name == "easYgen LogicsManager"


@pytest.fixture(scope="module")
def real_parsed() -> dict:
    return parse_wset(gzip.decompress(REAL_WSET_GZ.read_bytes()))


def test_real_file_program(real_parsed):
    program = logics_manager_program(real_parsed["parameters"])
    assert program["num_equations"] == 130
    assert len(program["command_variables"]) == 43
    assert program["unknown_operators"] == 0
    body = program["body"]
    assert "(* 12310 Relay 3 [Config_IO.Discrete_Out.03] *)" in body
    assert "LM_12310_TON(IN := LM_12310_IN, PT := T#50000ms);" in body
    assert "(* 12200 Inhibit emerg..run [Config_Application.Emergency_Run] *)" in body
    assert "LM_12200 := ((FALSE AND TRUE) AND TRUE);" in body
    dev = DeviceData()
    add_logics_manager_logic(dev, real_parsed)
    assert dev.logic.parsed.count("\n") > 500
    assert dev.logic.original.count("\n") == 130
    assert "END_PROGRAM" in dev.logic.parsed
