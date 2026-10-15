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


def test_add_logic_to_tc6_locates_all_sizes():
    logic_blocks = {
        "vars": {
            "b1": {"type": "BYTE", "address": "%IW1"},
            "b2": {"type": "USINT", "address": "%IW2"},
            "w1": {"type": "UINT", "address": "%IW3"},
            "w2": {"type": "WORD", "address": "%IW4"},
            "d1": {"type": "REAL", "address": "%IW5", "value": 2.5},
            "d2": {"type": "DINT", "address": "%IW6"},
            "l1": {"type": "LREAL", "address": "%IW7"},
            "l2": {"type": "ULINT", "address": "%IW8"},
        },
        "ST": [[b"b1 := b2;"]],
    }
    tc6 = TC6("M340Test")
    m340_parse.add_logic_to_tc6(logic_blocks, tc6)
    addresses = {name: v.get("address") for name, v in _vars_by_name(tc6).items()}

    assert addresses == {
        "b1": "%QB0",
        "b2": "%QB1",
        "w1": "%MW0",
        "w2": "%MW1",
        "d1": "%MD0",
        "d2": "%MD1",
        "l1": "%ML0",
        "l2": "%ML1",
    }


def test_add_logic_to_tc6_unlocatable_io_variables():
    logic_blocks = {
        "vars": {
            "levels": {"type": "ARRAY[1..3] OF INT", "address": "%IW1", "value": 7},
            "coils": {"type": "ARRAY[0..1] OF EBOOL", "address": "%Q0.1.0"},
            "delay": {"type": "TIME", "address": "%IW4"},
            "label": {"type": "STRING", "address": "%IW5"},
            "after": {"type": "INT", "address": "%IW6"},
            "unknown": {"type": "ANALOG_IN", "address": "%IW7"},
        },
        "ST": [[b"after := levels[1];"]],
    }
    tc6 = TC6("M340Test")
    m340_parse.add_logic_to_tc6(logic_blocks, tc6)
    variables = _vars_by_name(tc6)

    # MatIEC can't locate arrays, strings or times, so they have no address
    for name in ["levels", "coils", "delay", "label"]:
        assert variables[name].get("address") is None
    assert variables["levels"].find("type/array/dimension").get("lower") == "1"
    assert variables["levels"].find("type/array/baseType/INT") is not None
    assert len(variables["levels"].findall("initialValue/arrayValue/value")) == 3
    assert variables["coils"].find("type/array/baseType/BOOL") is not None
    assert variables["delay"].find("type/TIME") is not None
    assert variables["label"].find("type/string") is not None
    # Unlocated variables don't use up a location
    assert variables["after"].get("address") == "%MW0"
    assert "unknown" not in variables

    st = tc6.generate_st(openplc=True)
    assert "levels : ARRAY [1..3] OF INT := [7, 7, 7];" in st
    assert "delay : TIME;" in st
    assert "label : STRING;" in st
