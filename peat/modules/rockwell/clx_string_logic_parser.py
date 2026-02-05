"""
ControlLogix structured text logic parsing libraries.

Authors

- Craig Buchanan
- Christopher Goes
"""

import zlib
from collections.abc import Callable
from typing import Final

from peat import ParseError, log
from peat.modules.rockwell.clx_const import LOGIC_LANGUAGE
from peat.protocols.cip import *
from peat.protocols.data_packing import *

from .clx_cip import ClxCIP


class DisassembleStringLogicError(ParseError):
    def __init__(self, value) -> None:
        self.__value = value

    def __str__(self) -> str:
        return repr(self.__value)


def decompile_string_process_logic(
    logic_string: str,
    template_tags: dict | None = None,
    driver: ClxCIP | None = None,
) -> str:
    """
    Returns the original source code of the structured text logic from
    the zlib-compressed string of the disassembled process logic.

    Args:
        logic_string: the zlib decompressed string
        template_tags:
        driver: Driver to use to resolve Symbol objects, if available

    Returns:
        The original source code of the structured text
    """
    log.trace3(f"decompile_string_process_logic({logic_string})")

    data_split = logic_string.split("@")  # odd indices are tokens to process

    for token_idx in range(1, len(data_split), 2):  # process every token
        token = [int(path_val) for path_val in data_split[token_idx].split(" ")]
        token_name = _resolve_token_name(token, template_tags, driver)
        if token_name == "":
            token_name = f"@{data_split[token_idx]}@"
        data_split[token_idx] = token_name

    tag_name_replaced = "".join(data_split)
    log.trace(f"decompile_process_logic: DONE: Returning:\n{tag_name_replaced}")

    return tag_name_replaced


def disassemble_string_process_logic(
    logic_bytes: bytes, logic_language: int
) -> tuple[str, str]:
    """
    Returns the disassembled logic of a text-based program as it is
    stored on the Logix5000 device.

    Args:
        logic_bytes: the buffer (byte list) of the logic captured from the Logix5000 device
        logic_language: ID of the logic language to parse

    Returns:
        Tuple of a string of the disassembled text-based process logic
        and a string of the text-based logic
    """
    log.trace3(f"disassemble_string_process_logic({logic_bytes}, {logic_language})")

    try:
        routine_data = ROUTINE_DATA[logic_language]
    except KeyError as e:
        error_message = f"Language {e.args[0]} not supported."
        log.error(error_message)
        raise DisassembleStringLogicError(error_message) from e

    min_data_len = (len(routine_data["HEADER"]) + len(routine_data["FOOTER"])) * 4
    if len(logic_bytes) < min_data_len:
        error_message = (
            f"Data too short to be valid "
            f"(len={len(logic_bytes)} < min_len={min_data_len})"
        )
        log.warning(error_message)
        raise DisassembleStringLogicError(error_message)

    # Parse logic
    header = {}
    data_offset = 4
    for header_field in routine_data["HEADER"]:
        # TODO: weird stuff with bytes?
        # val = b"".join(bytes([x]) for x in logic_bytes[data_offset:data_offset + 4])
        val = logic_bytes[data_offset : data_offset + 4]
        header[header_field] = unpack_dint(val)
        data_offset += 4

    footer = {}
    data_offset_reverse = 0
    for footer_field in routine_data["FOOTER"][::-1]:
        # TODO: weird stuff with bytes?
        # val = b"".join(
        #     bytes([x]) for x in logic_bytes[-(data_offset_reverse + 4):
        #                                     len(logic_bytes) - data_offset_reverse])
        val = logic_bytes[
            -(data_offset_reverse + 4) : len(logic_bytes) - data_offset_reverse
        ]
        footer[footer_field] = unpack_dint(val)
        data_offset_reverse += 4

    logic_string_raw_length = len(logic_bytes) - data_offset - data_offset_reverse
    logic_string_raw = logic_bytes[data_offset : data_offset + logic_string_raw_length]
    logic_string = routine_data["FORMAT_LOGIC_STRING"](logic_string_raw).decode()

    # Build the string of disassembly
    out = []
    instruction_address = header["LOGIC START"]
    for header_field in routine_data["HEADER"]:
        out.append(
            f"[0x{instruction_address & 0xFFFFFFFF:0>8x}]  "
            f"{header[header_field] & 0xFFFFFFFF:0>8x}  {header_field}\n"
        )
        instruction_address += 4

    out.append(
        f"[0x{instruction_address & 0xFFFFFFFF:0>8x}]            LOGIC STRING:\n"
    )
    out.append(logic_string)
    instruction_address += logic_string_raw_length

    for footer_field in routine_data["FOOTER"]:
        out.append(
            f"[0x{instruction_address & 0xFFFFFFFF:0>8x}]  "
            f"{footer[footer_field] & 0xFFFFFFFF:0>8x}  {footer_field}\n"
        )
        instruction_address += 4
    out = "".join(out)

    log.trace3(
        f"disassemble_string_process_logic: DONE. Returning:\n{out}{logic_string}"
    )
    return out, logic_string


def _resolve_token_name(
    token: list[int], template_tags: dict, driver: ClxCIP | None = None
) -> str:
    """
    Returns a string representing the name of the token.

    Example:

    - token = ``[0x6C, 0x2420, 0x6A, 0x1BB0, 0, 0,]``
    - token_name = ``_resolve_token_name(token)``

    Args:
        token: A list of int representing the instance of the token
        template_tags: Template Tags from device (needed if Template Object)
        driver: Driver to use to get Token Attributes from device
            (needed if Symbol Object)

    Returns:
        String representing the name of the token.
        If token resolution fails, an empty string is returned.
    """
    # Remove path values with class code 0
    token_size = 0
    for class_code_idx in range(0, len(token), 2):
        if token[class_code_idx] != 0:
            token_size += 2
        else:
            break
    token = token[:token_size]

    token_name = ""
    if token[0] == CLASS_CODE["Template Object"]:
        try:
            template_member_idx = INDEX_HASH[token[3]]
            ordered_template_members = list(
                template_tags[token[1]]["Structure"].values()
            )
            token_name = ordered_template_members[template_member_idx]["Name"]
        except KeyError:
            log.warning(f"Cannot resolve token name ({token})")
    elif token[-2] == CLASS_CODE["Symbol Object"]:
        if driver is None:
            log.warning(
                f"Could not resolve token {token_name} of class Symbol Object: "
                f"no driver to lookup get_attributes was specified."
            )
            return ""

        path = ()
        for path_idx in range(0, len(token), 2):
            path += (token[path_idx + 0], token[path_idx + 1])

        token_attributes = driver.get_attributes(path, [1])
        if 1 in token_attributes:
            token_name = token_attributes[1]
        else:
            log.warning(f"Cannot resolve token name ({token})")
    else:
        log.warning(f"Cannot resolve token name ({token})")

    return token_name


def format_logic_string_fbd(logic_string_raw: bytes) -> bytes:
    """
    Returns the meaningful logic string from the raw string buffer
    stored on the Logix5000 device (function block diagram).

    Args:
        logic_string_raw: The raw string buffer from the device

    Returns:
        The meaningful logic string
    """
    if len(logic_string_raw) % 4 != 0:
        error_message = (
            "Error while decompressing FBD logic string "
            "(length of raw logic string not multiple of 4)"
        )
        log.warning(error_message)
        raise DisassembleStringLogicError(error_message)

    logic_string_formatted = []
    for line in zip(
        logic_string_raw[0::4],
        logic_string_raw[1::4],
        logic_string_raw[2::4],
        strict=False,
    ):
        logic_string_formatted.extend(line)
    logic_string_formatted.extend(
        (
            0,
            0,
            0,
        )
    )

    try:
        val = b"".join(bytes([x]) for x in logic_string_formatted)
        logic_string = zlib.decompress(val)
    except zlib.error as err:
        error_message = f"error while decompressing FBD logic string: {err}"
        log.warning(error_message)
        raise DisassembleStringLogicError(error_message) from err

    return logic_string


def format_logic_string_sfc(logic_string_raw: bytes) -> bytes:
    """
    Returns the meaningful logic string from the raw string buffer
    stored on the Logix5000 device (sequential function chart).

    Args:
        logic_string_raw: The raw string buffer from the device

    Returns:
        The meaningful logic string
    """
    try:
        val = b"".join(bytes([x]) for x in logic_string_raw)
        logic_string = zlib.decompress(val)
    except zlib.error as err:
        error_message = f"error while decompressing SFC logic string: {err}"
        log.warning(error_message)
        raise DisassembleStringLogicError(error_message) from err

    return logic_string


def format_logic_string_st(logic_string_raw: bytes) -> bytes:
    """
    Returns the meaningful logic string from the raw string buffer
    stored on the Logix5000 device (structured text).

    Args:
        logic_string_raw: The raw string buffer from the device

    Returns:
        The meaningful logic string
    """
    if len(logic_string_raw) % 4 != 0:
        error_message = (
            "Error while decompressing ST logic string "
            "(length of raw logic string not multiple of 4)"
        )
        log.warning(error_message)
        raise DisassembleStringLogicError(error_message)

    logic_string_formatted = []
    for line in zip(
        logic_string_raw[0::4],
        logic_string_raw[1::4],
        logic_string_raw[2::4],
        strict=False,
    ):
        logic_string_formatted.extend(line)
    logic_string_formatted.extend(
        (
            0,
            0,
            0,
        )
    )

    try:
        val = b"".join(bytes([x]) for x in logic_string_formatted)
        logic_string = zlib.decompress(val)
    except zlib.error as err:
        error_message = f"error while decompressing ST logic string: {err}"
        log.warning(error_message)
        raise DisassembleStringLogicError(error_message) from err

    return logic_string


ROUTINE_DATA: Final[dict[int, dict[str, list[str] | Callable]]] = {
    LOGIC_LANGUAGE["Structured Text"]: {
        "HEADER": [
            "LOGIC START",
            "FUNCTION START",
            "UNKNOWN[2]",
            "STRING LOGIC END ADDRESS",
            "UNKNOWN[4]",
            "STRING LOGIC DATA LENGTH",
            "UNKNOWN[6]",
            "? LENGTH",
        ],
        "FORMAT_LOGIC_STRING": format_logic_string_st,
        "FOOTER": [
            "FUNCTION END",
            "LOGIC END",
        ],
    },
    LOGIC_LANGUAGE["Function Block Diagram"]: {
        "HEADER": [
            "LOGIC START",
            "FUNCTION START",
            "UNKNOWN[2]",
            "STRING LOGIC END ADDRESS",
            "UNKNOWN[4]",
            "STRING LOGIC DATA LENGTH",
            "UNKNOWN[6]",
            "? LENGTH",
        ],
        "FORMAT_LOGIC_STRING": format_logic_string_fbd,
        "FOOTER": [
            "FUNCTION END",
            "LOGIC END",
        ],
    },
    LOGIC_LANGUAGE["Sequential Function Chart"]: {
        "HEADER": [
            "LOGIC START",
            "PROGRAM ID?",  # TODO: check if this is right
            "UNKNOWN[2]",
            "UNKNOWN[3]",
            "UNKNOWN[4]",
            "UNKNOWN[5]",
            "UNKNOWN[6]",
        ],
        "FORMAT_LOGIC_STRING": format_logic_string_sfc,
        "FOOTER": [],
    },
}
