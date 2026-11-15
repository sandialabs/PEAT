"""
Tests for the vendored Beremiz PLCOpen code in peat/parsing/plc_open.

beremiz_first_steps_plc.xml is the "first_steps" example project from
Beremiz (https://github.com/beremiz/beremiz), unmodified.
It has POUs written in all five IEC 61131-3 languages (ST, IL, FBD, LD, SFC),
plus configurations, resources, tasks and global variables.
"""

from xml.etree.ElementTree import SubElement

import pytest

from peat.parsing.logic_gen import tc6_to_st
from peat.parsing.plc_open import PLCControler
from peat.parsing.tc6 import TC6


@pytest.fixture
def first_steps_xml(datapath) -> bytes:
    return datapath("beremiz_first_steps_plc.xml").read_bytes()


@pytest.fixture
def first_steps_st(datapath) -> str:
    return datapath("beremiz_first_steps_expected.st").read_text(encoding="utf-8")


def test_generate_program_all_languages(first_steps_xml, first_steps_st):
    controller = PLCControler()
    assert controller.load_project(first_steps_xml) is None

    program, errors, warnings = controller.GenerateProgram()

    assert errors == []
    assert warnings == []
    assert program == first_steps_st


@pytest.mark.parametrize(
    "expected",
    [
        "FUNCTION AverageVal : REAL",  # ST function
        "_TMP_ADD4_OUT := ADD(1, Cnt);",  # FBD and LD
        "INITIAL_STEP Start:",  # SFC
        "JMPC ResetCnt",  # IL
        "VAR_GLOBAL CONSTANT",
        "TASK plc_task(INTERVAL := T#100ms,PRIORITY := 1);",
        "PROGRAM plc_task_instance WITH plc_task : plc_prg;",
    ],
)
def test_generate_program_contents(first_steps_xml, expected):
    controller = PLCControler()
    controller.load_project(first_steps_xml)
    program, _, _ = controller.GenerateProgram()
    assert expected in program


def test_load_project_accepts_str(first_steps_xml, first_steps_st):
    controller = PLCControler()
    assert controller.load_project(first_steps_xml.decode("utf-8")) is None
    assert controller.GenerateProgram()[0] == first_steps_st


def test_load_project_invalid_xml():
    controller = PLCControler()
    error = controller.load_project(b"<project>not closed")
    assert error.startswith("Project file syntax error")
    assert controller.Project is None
    assert controller.GenerateProgram() == ("", ["No project opened"], [])


def test_load_project_invalid_utf8():
    controller = PLCControler()
    error = controller.load_project(b"\xff\xfe<project/>")
    assert error.startswith("Project file syntax error")
    assert controller.Project is None


def test_load_project_schema_error():
    # Valid XML that doesn't conform to the TC6 schema
    xml = TC6("Empty").generate_xml_string()
    controller = PLCControler()
    error = controller.load_project(xml.encode())
    assert "tc6_0201}body" in str(error)


def test_generate_program_no_project():
    assert PLCControler().GenerateProgram() == ("", ["No project opened"], [])


def test_generate_program_writes_file(tmp_path, first_steps_xml, first_steps_st):
    out_file = tmp_path / "program.st"
    controller = PLCControler()
    controller.load_project(first_steps_xml)

    program, errors, _ = controller.GenerateProgram(str(out_file))

    assert errors == []
    assert out_file.read_text(encoding="utf-8") == program == first_steps_st


def test_generate_program_noconfig(first_steps_xml):
    controller = PLCControler()
    controller.load_project(first_steps_xml)
    program, errors, _ = controller.GenerateProgram(noconfig=True)
    assert errors == []
    assert "END_PROGRAM" in program
    assert "CONFIGURATION" not in program


def test_tc6_to_st(first_steps_xml, first_steps_st):
    assert tc6_to_st(first_steps_xml) == first_steps_st


def test_tc6_to_st_empty():
    assert tc6_to_st(b"") == ""


def _make_tc6_with_st(sceptre: bool) -> str:
    tc6 = TC6("PEAT test project")
    local_vars = SubElement(tc6.main_pou.find("interface"), "localVars")
    for name, typ in [("counter", "INT"), ("enabled", "BOOL")]:
        var = SubElement(local_vars, "variable", {"name": name})
        SubElement(SubElement(var, "type"), typ)
    TC6.add_st_content_to_pou(
        tc6.main_pou,
        b"IF enabled THEN\n  counter := counter + 1;\nEND_IF;",
    )
    return tc6.generate_st(sceptre=sceptre)


@pytest.mark.parametrize("sceptre", [False, True])
def test_tc6_generate_st(sceptre):
    st = _make_tc6_with_st(sceptre)
    assert "PROGRAM main" in st
    assert "counter : INT;" in st
    assert "enabled : BOOL;" in st
    assert "counter := counter + 1;" in st
    assert "END_PROGRAM" in st
    # Only the SCEPTRE-compatible project has a configuration
    assert ("CONFIGURATION" in st) is sceptre


def test_tc6_generate_st_sceptre_task():
    st = _make_tc6_with_st(sceptre=True)
    assert "TASK TaskMain(INTERVAL := T#50ms,PRIORITY := 0);" in st
    assert "PROGRAM MainProgram WITH TaskMain : main;" in st


def test_uri_model_no_catastrophic_backtracking():
    from peat.parsing.plc_open.xml_modules.xmlclass import URI_model

    assert URI_model.match("http://www.plcopen.org/xml/tc6_0201")
    assert URI_model.match("https://www.w3.org/1999/xhtml")
    assert URI_model.match("/relative/path-1.0/")
    assert not URI_model.match("not a uri")
    # Would hang with upstream's original nested-quantifier pattern
    assert not URI_model.match("-" * 50_000 + "!")
