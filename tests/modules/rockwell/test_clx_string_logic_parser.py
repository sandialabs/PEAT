import pytest

from peat.modules.rockwell.clx_const import *
from peat.modules.rockwell.clx_string_logic_parser import *


def test_disassemble_process_logic_unsupported_language():
    with pytest.raises(DisassembleStringLogicError):
        disassemble_string_process_logic(b"", 0)


def test_disassemble_process_logic_st_wellformed_input(text_data):
    data = (
        b"\x00\x00\x00\x00\x08\x31\x1f\x00"
        b"\x67\xcc\x07\x78\x90\x4f\x4e\x00"
        b"\x98\x31\x1f\x3c\x00\x00\x00\x00"
        b"\x56\x00\x00\x00\x00\x00\x00\x00"
        b"\x59\x00\x00\x00x\x9c+\00I-.\x00"
        b"\x89/.\x00)\xca\xcc\x00K\x07\x00\x00"
        b"\x1cy\x04\x00\xb7\x00\x00\x00"
        b"\x9c\x31\x1f\x7a\x00\x00\x00\x78"
    )
    disassembled, logic_string = disassemble_string_process_logic(
        data, LOGIC_LANGUAGE["Structured Text"]
    )
    assert disassembled == text_data("st-disassembled.txt")
    assert logic_string == "test_string"


def test_disassemble_process_logic_st_data_too_short():
    with pytest.raises(DisassembleStringLogicError):
        disassemble_string_process_logic(b"", LOGIC_LANGUAGE["Structured Text"])


def test_disassemble_process_logic_st_malformed_data_length():
    data = (
        b"\x00\x00\x00\x00\x08\x31\x1f\x00"
        b"\x67\xcc\x07\x78\x90\x4f\x4e\x00"
        b"\x98\x31\x1f\x3c\x00\x00\x00\x00"
        b"\x56\x00\x00\x00\x00\x00\x00\x00"
        b"\x59\x00\x00\x00x\x9c+\00I-.\x00"
        b"\x89/.\x00)\xca\xcc\x00"
        b"K\x07\x00\x00\x1cy\x04\x00\xb7\x00\x00"
        b"\x9c\x31\x1f\x7a\x00\x00\x00\x78"
    )
    with pytest.raises(DisassembleStringLogicError):
        disassemble_string_process_logic(data, LOGIC_LANGUAGE["Structured Text"])


def test_disassemble_process_logic_st_malformed_zlib_section():
    data = (
        b"\x00\x00\x00\x00\x08\x31\x1f\x00"
        b"\x67\xcc\x07\x78\x90\x4f\x4e\x00"
        b"\x98\x31\x1f\x3c\x00\x00\x00\x00"
        b"\x56\x00\x00\x00\x00\x00\x00\x00"
        b"\x59\x00\x00\x00x\x9c+\00I-.\x00"
        b"\x89/.\x00)\xca\xcc\x00"
        b"K\x07\x00\x00\x1cy\x04\x00"
        b"\x9c\x31\x1f\x7a\x00\x00\x00\x78"
    )
    with pytest.raises(DisassembleStringLogicError):
        disassemble_string_process_logic(data, LOGIC_LANGUAGE["Structured Text"])


def test_disassemble_process_logic_fbd_wellformed_input(text_data):
    data = (
        b"\x00\x00\x00\x00\x98\x3e\x1f\x00"
        b"\x39\xd0\x07\x78\x93\x9a\x56\x00"
        b"\xe0\x40\x1f\x3c\x00\x00\x00\x00"
        b"\xa0\x01\x00\x00\x00\x00\x00\x00"
        b"\xa4\x05\x00\x00x\x9c+\00I-.\x00"
        b"\x89/.\x00)\xca\xcc\x00"
        b"K\x07\x00\x00\x1cy\x04\x00\xb7\x00\x00\x00"
        b"\xe4\x40\x1f\x7a\x00\x00\x00\x78"
    )
    disassembled, logic_string = disassemble_string_process_logic(
        data, LOGIC_LANGUAGE["Function Block Diagram"]
    )
    assert disassembled == text_data("fbd-disassembled.txt")
    assert logic_string == "test_string"


def test_disassemble_process_logic_fbd_malformed_data_length():
    data = (
        b"\x00\x00\x00\x00\x98\x3e\x1f\x00"
        b"\x39\xd0\x07\x78\x93\x9a\x56\x00"
        b"\xe0\x40\x1f\x3c\x00\x00\x00\x00"
        b"\xa0\x01\x00\x00\x00\x00\x00\x00"
        b"\xa4\x05\x00\x00x\x9c+\00I-.\x00"
        b"\x89/.\x00)\xca\xcc\x00"
        b"K\x07\x00\x00\x1cy\x04\x00\xb7\x00\x00"
        b"\xe4\x40\x1f\x7a\x00\x00\x00\x78"
    )
    with pytest.raises(DisassembleStringLogicError):
        disassemble_string_process_logic(data, LOGIC_LANGUAGE["Function Block Diagram"])


def test_disassemble_process_logic_fbd_malformed_zlib_section():
    data = (
        b"\x00\x00\x00\x00\x98\x3e\x1f\x00"
        b"\x39\xd0\x07\x78\x93\x9a\x56\x00"
        b"\xe0\x40\x1f\x3c\x00\x00\x00\x00"
        b"\xa0\x01\x00\x00\x00\x00\x00\x00"
        b"\xa4\x05\x00\x00x\x9c+\00I-.\x00"
        b"\x89/.\x00)\xca\xcc\x00"
        b"K\x07\x00\x00\x1cy\x04\x00"
        b"\xe4\x40\x1f\x7a\x00\x00\x00\x78"
    )
    with pytest.raises(DisassembleStringLogicError):
        disassemble_string_process_logic(data, LOGIC_LANGUAGE["Function Block Diagram"])


def test_disassemble_process_logic_sfc_wellformed_input(text_data):
    data = (
        b"\x00\x00\x00\x00\x8c-\x1f\x00"
        b"? \x00\x00\x00\x00\x00\x00"
        b"\xe0\x01\x00\x00\x00\x00\x00\x00"
        b"\xd3\x01\x00\x80\xf7\x05\x00\x00"
        b"x\x9c+I-.\x89/.)\xca\xccK\x07\x00\x1cy\x04\xb7"
    )
    disassembled, logic_string = disassemble_string_process_logic(
        data, LOGIC_LANGUAGE["Sequential Function Chart"]
    )
    assert disassembled == text_data("sfc-disassembled.txt")
    assert logic_string == "test_string"


def test_disassemble_process_logic_sfc_malformed_zlib_section():
    data = (
        b"\x00\x00\x00\x00\x8c-\x1f\x00"
        b"? \x00\x00\x00\x00\x00\x00"
        b"\xe0\x01\x00\x00\x00\x00\x00\x00"
        b"\xd3\x01\x00\x80\xf7\x05\x00\x00"
        b"x\x9c+I-.\x89/.)\xca\xccK\x07\x00\x1cy\x04"
    )
    with pytest.raises(DisassembleStringLogicError):
        disassemble_string_process_logic(data, LOGIC_LANGUAGE["Sequential Function Chart"])


@pytest.mark.skip("Token lookups are not finished yet")
def test_decompile_string_process_logic_template_token():
    # TODO: token_name == self.__resolve_token_name
    data = f"test_@{CLASS_CODE['Template Object']} 1 5 46883 0 0@_test"
    assert decompile_string_process_logic(data) == "test_mock_name4_test"


@pytest.mark.skip("Token lookups are not finished yet")
def test_decompile_string_process_logic_symbol_token():
    # TODO: token_name == self.__resolve_token_name
    data = f"test_@1 2 3 4 {CLASS_CODE['Symbol Object']} 5@_test"
    assert decompile_string_process_logic(data) == "test_var1_test"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param("test_string", id="no_tokens"),
        pytest.param("test_@1 2 3 4 5 6@_test", id="unknown_token"),
        pytest.param("test_@1 2 3 4 5@_test", id="token_size_odd"),
        pytest.param(
            f"test_@{CLASS_CODE['Template Object']} 1 5 1 0 0@_test",
            id="malformed_token_template",
        ),
        pytest.param(
            f"test_@11 12 13 14 {CLASS_CODE['Symbol Object']} 15@_test",
            id="malformed_token_symbol",
        ),
    ],
)
def test_decompile_string_process_logic_edge_cases(data):
    assert decompile_string_process_logic(data) == data
