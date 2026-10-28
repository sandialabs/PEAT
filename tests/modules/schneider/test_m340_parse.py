import pytest

from peat.modules.schneider.m340 import m340_parse
from peat.parsing.tc6 import TC6


@pytest.fixture
def logic_blocks():
    return {
        "vars": {
            "level": {"type": "INT", "address": "%IW0.1", "value": 5},
            "setpoint": {"type": "INT", "address": "%IW0.2"},
            "local_count": {"type": "INT", "address": ""},
            "local_ratio": {"type": "REAL", "address": "%MW10", "value": 1.5},
            "local_flags": {"type": "ARRAY[0..2] OF EBOOL", "address": ""},
            **{f"coil_{i}": {"type": "EBOOL", "address": f"%Q0.1.{i}"} for i in range(9)},
        },
        "ST": [[b"level := level + 1;"]],
    }


def _vars_by_name(tc6: TC6) -> dict:
    return {v.get("name"): v for v in tc6.main_pou.iter("variable")}


def test_add_logic_to_tc6_int_io_uses_word_addresses(logic_blocks):
    tc6 = TC6("M340Test")
    m340_parse.add_logic_to_tc6(logic_blocks, tc6)
    variables = _vars_by_name(tc6)

    # INT is 16 bits, so it must be at %MW, not %MD, for MatIEC/OpenPLC
    assert variables["level"].get("address") == "%MW0"
    assert variables["level"].find("type/INT") is not None
    assert variables["level"].find("initialValue/simpleValue").get("value") == "5"
    assert variables["setpoint"].get("address") == "%MW1"
    assert variables["setpoint"].find("type/INT") is not None
    assert not tc6.main_pou.findall(".//REAL[@address]")


def test_add_logic_to_tc6_bool_io_bit_index_rolls_over(logic_blocks):
    tc6 = TC6("M340Test")
    m340_parse.add_logic_to_tc6(logic_blocks, tc6)
    variables = _vars_by_name(tc6)

    assert variables["coil_0"].get("address") == "%QX0.1"
    assert variables["coil_6"].get("address") == "%QX0.7"
    assert variables["coil_7"].get("address") == "%QX1.0"
    assert variables["coil_8"].get("address") == "%QX1.1"
    assert variables["coil_0"].find("type/BOOL") is not None


def test_add_logic_to_tc6_local_variables(logic_blocks):
    tc6 = TC6("M340Test")
    m340_parse.add_logic_to_tc6(logic_blocks, tc6)
    variables = _vars_by_name(tc6)

    assert variables["local_count"].get("address") is None
    assert variables["local_count"].find("type/INT") is not None
    assert variables["local_ratio"].find("type/REAL") is not None
    assert variables["local_ratio"].find("initialValue/simpleValue").get("value") == "1.5"
    assert variables["local_flags"].find("type/array/baseType/BOOL") is not None


@pytest.mark.parametrize("openplc", [False, True])
def test_add_logic_to_tc6_generates_st(logic_blocks, openplc):
    tc6 = TC6("M340Test")
    m340_parse.add_logic_to_tc6(logic_blocks, tc6)
    st = tc6.generate_st(openplc=openplc)

    assert "level AT %MW0 : INT := 5;" in st
    assert "coil_7 AT %QX1.0 : BOOL;" in st
    assert "%MD" not in st
    assert "REAL := 5.0" not in st
    assert ("CONFIGURATION Config0" in st) is openplc
    assert ("RESOURCE Res0" in st) is openplc


@pytest.mark.parametrize(
    ("var_type", "expected"),
    [("INT", "INT"), ("EBOOL", "BOOL"), ("BOOL", "BOOL"), ("REAL", "REAL"), ("FOO", "")],
)
def test_get_type_string(var_type, expected):
    assert m340_parse.get_type_string(var_type) == expected
