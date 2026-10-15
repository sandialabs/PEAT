import io
import zipfile
from datetime import datetime

import pytest

from peat import M340, XEF, datastore
from peat.api.parse_api import parsable_file_by_signature
from peat.modules.schneider.xef import xef_parse
from peat.parsing.tc6 import TC6

SIM_XEF = "xef/pacframework_sim_wthout_framework.xef"
ALL_FILES = [
    "xef/pacframework_sim_wthout_framework.xef",
    "xef/atpv_atv71m340.xef",
    "xef/estradege_m340.xef",
    "xef/estradege_m340.zef",
    "xef/estradege_m580-safety.zef",
    "xef/schneider_unitytranslator_base.zef",
]


@pytest.fixture
def sim_parsed(datapath):
    return xef_parse.parse_xef(datapath(SIM_XEF).read_bytes())


def test_parse_xef_metadata(sim_parsed):
    assert sim_parsed["file_header"]["product"] == "Unity Pro XL V13.1 - 180823C"
    assert sim_parsed["content_header"]["name"] == "Project"
    assert sim_parsed["plc"]["part_number"] == "BMXP342000"
    assert sim_parsed["plc"]["version"] == "02.00"
    assert sim_parsed["plc"]["attributes"]["numberInternalWord"] == "2048"
    assert sim_parsed["tasks"]["MAST"]["sections"] == ["SimTanks", "SimHeat"]


def test_parse_xef_modules(sim_parsed):
    modules = [(m["family"], m["part_number"], m.get("position")) for m in sim_parsed["modules"]]
    assert modules == [
        ("Rack", "BMXXBP0800", 0),
        ("Supply", "BMXCPS2000", -1),
        ("Micro Basic", "BMXP342000", 0),
        ("Discrete", "BMXDDM3202K", 1),
        ("Analog", "BMXAMM0600", 2),
        ("Discrete", "BMXDDM3202K", 3),
        ("Analog", "BMXAMM0600", 4),
    ]


def test_parse_xef_variables(sim_parsed):
    variables = sim_parsed["variables"]
    assert len(variables) == 45
    assert variables["VDoz_T1toT2"]["type"] == "EBOOL"
    assert variables["VDoz_T1toT2"]["address"] == "%Q0.1.25"
    assert variables["VDoz_T1toT2"]["comment"].startswith("3-ходовий клапан")
    # Lowercase addresses are normalized
    assert variables["VSliv_D1_CLS"]["address"] == "%I0.1.10"
    assert variables["smObject1"]["type"] == "smObject1"
    assert variables["EDGE1"]["address"] == ""


def test_parse_xef_dfb_types(sim_parsed):
    dfbs = sim_parsed["dfb_types"]
    assert set(dfbs) == {
        "smValve",
        "smHeatExch",
        "smValve_0",
        "smTankT",
        "smDELAY",
        "smObject1",
        "smLevelCyl1",
    }
    valve = dfbs["smValve"]
    assert list(valve["variables"]["inputParameters"]) == ["INIT", "cmdOPN", "cmdCLS", "cmdPOS"]
    assert valve["variables"]["publicLocalVariables"]["d_t"]["value"] == "0.1"
    assert [s["language"] for s in valve["sections"]] == ["FBD"]
    assert dfbs["smTankT"]["sections"][0]["language"] == "ST"
    assert "V:=V0" in dfbs["smTankT"]["sections"][0]["source"]


def test_parse_xef_sections(sim_parsed):
    sections = [(s["name"], s["type"], s["task"], s["language"]) for s in sim_parsed["sections"]]
    assert sections == [
        ("SimTanks", "section", "MAST", "FBD"),
        ("SimHeat", "section", "MAST", "FBD"),
    ]


def test_parse_xef_invalid():
    with pytest.raises(ValueError, match="Not a XEF file"):
        xef_parse.parse_xef(b"<?xml version='1.0'?><RSLogix5000Content/>")
    with pytest.raises(ValueError, match="Invalid XML"):
        xef_parse.parse_xef(b"<FEFExchangeFile>")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("date_and_time#2021-9-18-19:20:12", datetime(2021, 9, 18, 19, 20, 12)),
        ("dt#2012-11-17-17:55:52", datetime(2012, 11, 17, 17, 55, 52)),
        ("", None),
        ("dt#2021-13-40-00:00:00", None),
    ],
)
def test_parse_xef_date(raw, expected):
    assert xef_parse.parse_xef_date(raw) == expected


def test_xef_st_generation(sim_parsed):
    tc6 = TC6("Sim")
    xef_parse.add_project_to_tc6(sim_parsed, tc6)
    st = tc6.generate_st(openplc=True)

    # DFBs become function blocks, with their Structured Text sections
    assert "FUNCTION_BLOCK smTankT" in st
    assert "    Vmax : REAL := 10.0;" in st
    assert "V:=V+d_t*(Fin-Fout);" in st
    # DFBs with FBD sections are converted
    assert "LIMIT18_OUT := LIMIT(REAL#0.0, POS, REAL#100.0);" in st
    # BOOL initial values are TRUE/FALSE
    assert "INIT : BOOL := FALSE;" in st
    # Global variables, with DFB instances and located I/O
    assert "smHeater1 : smHeatExch;" in st
    assert "VDoz_T1toT2 AT %QX0.1 : BOOL;" in st
    # Sections are programs, which declare the global variables they use
    assert "PROGRAM SimTanks" in st
    assert "    LE_T1 : INT;" in st
    # Direct variables are replaced with variables
    assert "MOVE1_OUT := MOVE(PEAT_S5);" in st
    assert "PROGRAM SimTanks_inst WITH MAST : SimTanks;" in st
    assert "CONFIGURATION Config0" in st


def test_xef_parse_module(datapath, mocker):
    mocker.patch.object(datastore, "objects", [])
    dev = XEF.parse(datapath(SIM_XEF))

    # "Project" is the default project name, so the filename is used as the ID
    assert dev.id == "xef_pacframework_sim_wthout_framework"
    assert dev.description.vendor.id == "Schneider"
    assert dev.description.product == "BMXP342000"
    assert dev.description.model == "M340"
    assert dev.firmware.version == "02.00"
    assert dev.logic.name == "Project"
    assert dev.logic.last_updated == datetime(2021, 9, 18, 18, 17, 46)
    assert dev.extra["exported_by"] == "Unity Pro XL V13.1 - 180823C"

    slots = {m.slot: m.description.product for m in dev.module if m.slot}
    assert slots == {
        "0": "BMXP342000",
        "1": "BMXDDM3202K",
        "2": "BMXAMM0600",
        "3": "BMXDDM3202K",
        "4": "BMXAMM0600",
    }
    assert len(dev.tag) == 45
    assert len(dev.io) == 37
    io = next(i for i in dev.io if i.id == "VDoz_T1_OPN")
    assert io.address == "%I0.3.0"
    assert io.direction == "input"

    assert "FUNCTION_BLOCK smHeatExch" in dev.logic.formats["structured_text"]
    assert dev.logic.formats["tc6"].startswith("<?xml")


def read_xef(datapath, filename: str) -> dict:
    data = datapath(filename).read_bytes()
    if xef_parse.is_zef_file(data):
        data = xef_parse.extract_xef_from_zef(data)
    return xef_parse.parse_xef(data)


def test_zef_extraction(datapath):
    zef_data = datapath("xef/estradege_m340.zef").read_bytes()
    assert xef_parse.is_zef_file(zef_data)
    assert not xef_parse.is_zef_file(datapath(SIM_XEF).read_bytes())

    xef_data = xef_parse.extract_xef_from_zef(zef_data)
    assert b"<ZEFExchangeFile>" in xef_data[:200]

    with pytest.raises(ValueError, match="Invalid ZEF file"):
        xef_parse.extract_xef_from_zef(b"PK\x03\x04 truncated")


def test_parse_xef_ddt_types(datapath):
    parsed = read_xef(datapath, "xef/estradege_m340.xef")

    assert parsed["ddt_types"]["DDTTYPE1"]["fields"] == {
        "Var1": {"type": "BOOL", "address": ""},
        "Var2": {"type": "REAL", "address": ""},
        "Var3": {"type": "ARRAY[0..10] OF DINT", "address": ""},
    }
    assert parsed["tasks"]["FAST"]["sections"]

    tc6 = TC6("m340")
    xef_parse.add_project_to_tc6(parsed, tc6)
    st = tc6.generate_st(openplc=True)

    assert "DDTTYPE1 : STRUCT" in st
    assert "Var3 : ARRAY [0..10] OF DINT;" in st
    # Variables of DDTs, DFBs and standard function blocks
    assert "Pub1 : DDTTYPE1;" in st
    assert "OBJ1 : DFBTYPE1;" in st
    assert "TON_1 : TON;" in st
    # FB instances used by one section are declared by the section
    assert "TON_1(IN := OBJ2.OUT1, PT := t#30m);" in st
    # DFBs and sections without logic get a placeholder statement
    assert "FUNCTION_BLOCK DFBTYPE1" in st
    assert "(* Section ProgrFast2 has no logic *)" in st
    assert st.count("PEAT_NO_ST_LOGIC := TRUE;") == 3


def test_parse_xef_m580_safety(datapath):
    parsed = read_xef(datapath, "xef/estradege_m580-safety.zef")

    assert parsed["plc"]["part_number"] == "BMEP584040S"
    assert len(parsed["modules"]) == 51
    assert len(parsed["dfb_types"]) == 83
    assert len(parsed["ddt_types"]) == 13
    assert set(parsed["tasks"]) == {"MAST", "SAFE"}
    # The project was exported without global variables
    assert parsed["variables"] == {}


def test_xef_all_languages(datapath, mocker):
    # Schneider's test project has a section in each language
    mocker.patch.object(datastore, "objects", [])
    dev = XEF.parse(datapath("xef/schneider_unitytranslator_base.zef"))
    st = dev.logic.formats["structured_text"]

    # ST, with direct variables replaced with variables
    assert "PEAT_M1:=true;" in st
    # IL
    assert "LD TRUE" in st
    assert "ST PEAT_M2" in st
    # FBD
    assert "TESTCOMMENT_1();" in st
    # SFC, with the macro step replaced by its steps
    assert "INITIAL_STEP S_1_1:" in st
    assert "TRANSITION FROM S_1_1 TO MS_1_2_IN" in st
    # LD
    assert "PEAT_M1 := TRUE;" in st
    # Timer section
    assert "TASK Timer0_TIMER(INTERVAL := T#100ms,PRIORITY := 0);" in st


@pytest.mark.parametrize("filename", ALL_FILES)
def test_xef_parse_all_files(datapath, mocker, caplog, filename):
    mocker.patch.object(datastore, "objects", [])
    dev = XEF.parse(datapath(filename))

    assert dev.description.product
    assert dev.description.model in ["M340", "M580"]
    assert dev.module
    assert dev.logic.formats["tc6"]
    assert "END_PROGRAM" in dev.logic.formats["structured_text"]
    assert "ERROR" not in caplog.text


@pytest.mark.parametrize("filename", ALL_FILES)
def test_xef_file_signatures(datapath, tmp_path, filename):
    # Copy without the extension, so only the file contents identify the file
    file = tmp_path / "project"
    file.write_bytes(datapath(filename).read_bytes())

    assert parsable_file_by_signature(str(file), XEF)
    assert not parsable_file_by_signature(str(file), M340)


def test_xef_file_signatures_negative(tmp_path):
    other_xml = tmp_path / "other_xml"
    other_xml.write_bytes(b'<?xml version="1.0"?>\n<Project></Project>')
    other_zip = tmp_path / "other_zip"
    other_zip.write_bytes(make_zip({"other.xef": b"<FEFExchangeFile/>"}))

    assert not parsable_file_by_signature(str(other_xml), XEF)
    assert not parsable_file_by_signature(str(other_zip), XEF)


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buf.getvalue()
