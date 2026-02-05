"""
Rockwell Allen-Bradley ControlLogix PLC logic parsing methods.

Authors

- Craig Buchanan
- Christopher Goes
"""

from peat import log

from .clx_cip import ClxCIP
from .clx_const import *
from .clx_relay_ladder_parser import decompile_ladder_process_logic
from .clx_string_logic_parser import (
    DisassembleStringLogicError,
    decompile_string_process_logic,
    disassemble_string_process_logic,
)

LayoutType = list[tuple[int, str]]
AttrsType = dict[int, dict]
MapAttrsType = dict[int, dict[int, int | bytes]]


def parse_logic(logic_dict: dict[str, dict], driver: ClxCIP | None = None) -> str:
    """
    Parse memory layout, symbol list, and logic from a attributes :class:`dict`.

    The logic dict should have the following keys

    - ``template_attributes``
    - ``template_tags``
    - ``symbol_attributes``
    - ``program_attributes``
    - ``program_symbol_attributes``
    - ``program_routine_attributes``
    - ``program_routine_tags``
    - ``map_attributes``
    - ``map_cxn_attributes``

    Args:
        logic_dict: Attributes dict
        driver: CIP driver to use for tag lookups, if needed

    Returns:
        The parsed memory layout, symbol list, and logic as a humand-readable
        string, or an empty string if the parse failed
    """
    log.debug("Parsing memory layout, symbol list, and logic from dict")
    if not logic_dict:
        log.error("Empty logic dictionary was passed to parse_logic")
        return ""

    logic_str = ""
    try:
        memory_list = extract_memory_layout(
            symbol_attributes=logic_dict["symbol_attributes"],
            program_attributes=logic_dict["program_attributes"],
            program_routine_attributes=logic_dict["program_routine_attributes"],
            program_symbol_attributes=logic_dict["program_symbol_attributes"],
            map_attributes=logic_dict["map_attributes"],
            map_cxn_attributes=logic_dict["map_cxn_attributes"],
        )
        log.debug("Extracted memory layout")
        logic_str += memory_layout_to_str(memory_list)

        # Symbol list is needed for Relay Ladder sections of program
        symbol_list = extract_symbol_list(
            symbol_attributes=logic_dict["symbol_attributes"],
            program_symbol_attributes=logic_dict["program_symbol_attributes"],
            program_attributes=logic_dict["program_attributes"],
        )
        log.debug("Extracted symbol list")

        parsed_logic = parse_process_logic(
            program_routine_tags=logic_dict["program_routine_tags"],
            program_routine_attributes=logic_dict["program_routine_attributes"],
            symbol_list=symbol_list,
            template_tags=logic_dict["template_tags"],
            driver=driver,
        )
        log.debug("Finished logic parsing")
        logic_str += parsed_logic
    except Exception:
        log.exception("Unknown exception occurred during logic parsing")
        return logic_str

    log.debug("Finished parsing memory layout, symbol list, and logic")
    return logic_str


def extract_memory_layout(
    symbol_attributes: AttrsType,
    program_attributes: AttrsType,
    program_routine_attributes: AttrsType,
    program_symbol_attributes: AttrsType,
    map_attributes: MapAttrsType,
    map_cxn_attributes: AttrsType,
) -> LayoutType:
    # TODO: docstring
    # TODO: comments on what each section of code is doing + variable naming
    # TODO: are any of the labels potentially bytes?
    memory_list = []

    for symbol in symbol_attributes.values():
        sym_val = symbol[3] & 0xFFFFFFFF
        try:  # Convert bytes to str (UTF-8)
            sym_str = symbol[1].decode()
        except AttributeError:
            sym_str = symbol[1]
        memory_list.append((sym_val, sym_str))

    for prog in [0x10, 0x5]:
        for key, value in program_attributes.items():
            attr_val = value[prog] & 0xFFFFFFFF
            attr_str = f"program{hex(prog)}: {hex(key)}"
            memory_list.append((attr_val, attr_str))

    for program_id, program_symbols in program_routine_attributes.items():
        for routine_id, routine_value in program_symbols.items():
            for key, label in [(0x2, "Routine"), (8, "Symbol")]:
                r_val = routine_value[key] & 0xFFFFFFFF
                r_str = (
                    f"Program{hex(program_id)} Routine{hex(routine_id)} {label} Address"
                )
                memory_list.append((r_val, r_str))

    for program_symbols in program_symbol_attributes.values():
        program_name = ""  # TODO: when would this get set?
        for symbol in program_symbols.values():
            sym_val = symbol[3] & 0xFFFFFFFF
            try:  # Convert bytes to str (UTF-8)
                sym_str = f"{program_name}.{symbol[1].decode()}"
            except AttributeError:
                sym_str = f"{symbol[1]} Symbol"
            memory_list.append((sym_val, sym_str))

    for key, value in map_attributes.items():
        memory_list.append((value[13] & 0xFFFFFFFF, "map0xd: " + hex(key)))

    for map_id, map_val in map_cxn_attributes.items():
        for cxn_id, cxn_attr in map_val.items():
            for key in [0x4, 0x6, 0x10]:
                cxn_val = cxn_attr[key] & 0xFFFFFFFF
                cxn_str = f"Map{hex(map_id)} Cxn{hex(cxn_id)} Attr{hex(key)}"
                memory_list.append((cxn_val, cxn_str))

    # NOTE(?): add in program.tags.symbols too! (?)

    if not memory_list:
        log.debug("No memory layout found")

    return memory_list


def memory_layout_to_str(memory_list: LayoutType) -> str:
    """
    Parses a memory list into a formatted layout of the memory.

    Args:
        memory_list: List of Value/Label tuples defining the memory layout

    Returns:
        Formatted human-readable layout of the memory.
    """
    if not memory_list:
        return ""

    layout_str = "Memory Layout:"
    for sym_val, sym_str in sorted(memory_list):
        layout_str += f"\n[0x{sym_val & 0xFFFFFFFF:0>8x}]  "
        layout_str += sym_str
        if isinstance(sym_str, bytes):
            log.warning("memory_layout_to_str: unexpected bytes!")

    return layout_str


def extract_symbol_list(
    symbol_attributes: AttrsType,
    program_symbol_attributes: AttrsType,
    program_attributes: AttrsType,
) -> LayoutType:
    # TODO: docstring
    # TODO: comments on what this is doing
    symbol_dict = {}

    for symbol in symbol_attributes.values():
        symbol_dict[symbol[3] & 0xFFFFFFFF] = symbol

    for program_id, program_symbols in program_symbol_attributes.items():
        for symbol in program_symbols.values():
            program_name = symbol_dict[program_attributes[program_id][16] & 0xFFFFFFFF][
                1
            ]
            program_name = program_name.decode()  # bytes to str
            symbol[1] = program_name + "." + symbol[1].decode()  # bytes to str
            symbol_dict[symbol[3] & 0xFFFFFFFF] = symbol

    # Convert any remaining bytes to str
    for key, value in symbol_dict.items():
        if isinstance(value[1], bytes):
            symbol_dict[key][1] = value[1].decode()  # bytes to str

    symbol_list = list(symbol_dict.items())
    symbol_list.sort()

    return symbol_list


def parse_process_logic(
    program_routine_tags: AttrsType,
    program_routine_attributes: AttrsType,
    symbol_list: LayoutType,
    template_tags: AttrsType,
    driver: ClxCIP | None = None,
) -> str:
    # TODO: docstring
    log.info("Decompiling Process Logic...")
    logic_str = ""

    for program_id, program_tag in program_routine_tags.items():
        for routine_id, logic_data in program_tag.items():
            # TODO: function to parse routine and/or program
            logic_str += f"\nProgram: {hex(program_id)}"
            logic_str += f"\nRoutine: {hex(routine_id)}"
            disassembly = ""
            decompiled = ""

            attrs = program_routine_attributes[program_id][routine_id]
            routine_language = attrs[0x01]  # Routine language (IEC 61131-3)
            starting_address = attrs[0x02]  # Starting address of the routine

            # TODO
            #   Save the logic_data (the raw binary) for each routine?
            #   Use: print_bytes_line(logic_data)

            # TODO: function to parse each language type
            lang_name = LOGIC_LANGUAGE_BY_INT.get(
                routine_language, f"unknown {routine_language}"
            )

            log.debug(
                f"Language for routine {routine_id}: {lang_name} "
                f"(program id: {program_id})"
            )
            if routine_language == LANG_RLL:
                logic_str += "\nProgram is Relay Ladder Logic\n"
                # TODO: finish implementing RLL disassembly and save it somewhere
                # disassembly = disassemble_ladder_process_logic(
                #     process_logic=logic_data, starting_address=starting_address
                # )
                decompiled = decompile_ladder_process_logic(
                    process_logic=logic_data,
                    symbol_list=symbol_list,
                    template_tags=template_tags,
                    starting_address=starting_address,
                )

            # TODO: add logic samples from L8 to unit tests

            elif routine_language in [LANG_STL, LANG_SFC, LANG_FBD]:
                # TODO: write the routine language type?
                try:
                    disassembly, logic_string = disassemble_string_process_logic(
                        logic_bytes=logic_data, logic_language=routine_language
                    )
                    # TODO: get attributes lookup for resolve_token_name
                    decompiled = decompile_string_process_logic(
                        logic_string=logic_string,
                        template_tags=template_tags,
                        driver=driver,
                    )
                except DisassembleStringLogicError as e:
                    log.warning(repr(e))
            else:
                disassembly = "ERROR: Language not recognized"

            if disassembly:
                log.trace(f"Size of disassmebly for '{lang_name}': {len(disassembly)}")
                logic_str += "\nDisassembly:"
                logic_str += disassembly
            else:
                log.warning(
                    f"No disassembled '{lang_name}' logic for routine {routine_id} "
                    f"and program {program_id}"
                )

            if decompiled:
                log.trace(f"Size of decompilation for '{lang_name}': {len(decompiled)}")
                logic_str += "\nDecompiled:"
                logic_str += decompiled
            else:
                log.warning(
                    f"No decompiled '{lang_name}' logic for routine {routine_id} "
                    f"and program {program_id}"
                )

    return logic_str


# NOTE(cegoes, 12/09/2024): leave this alone, it's been needed
#   more than once for random, silly things.
# def print_bytes_line(msg) -> str:
#     out = ""
#     for ch in msg:
#         out += "{:0>2x}".format(ch)
#     return out
