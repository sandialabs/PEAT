"""
ControlLogix ladder logic parsing libraries.

Authors

- Craig Buchanan
- Christopher Goes
- Greg Walkup
"""

from typing import Final
from collections.abc import Callable

from peat import log
from peat.protocols.data_packing import *

LayoutType = list[tuple[int, str]]


def decompile_ladder_process_logic(
    process_logic: list[int],
    symbol_list: LayoutType,
    template_tags: dict,
    starting_address: int = 0,
) -> str:
    """
    Transforms device bytecode into a string representing the ladder logic.

    Args:
        process_logic: the bytecode representation of the relay ladder routine
        symbol_list:
        template_tags:
        starting_address: the starting address of the relay ladder routine in the device

    Returns:
        String representing the source code of a relay ladder
        routine from the respective bytecode format from the device
    """
    log.trace3(
        f"decompile_ladder_process_logic: len={len(process_logic)}, "
        f"starting_address={starting_address}"
    )

    process_logic = instruction_buffer_to_instruction_list(process_logic)
    out = decompile_process_logic_segment(process_logic, starting_address)
    out_resolved = _resolve_all_token_names("".join(out), symbol_list, template_tags)

    return out_resolved


def disassemble_ladder_process_logic(
    process_logic: list[int], starting_address: int = 0
) -> str:
    """
    Disassembles a buffer (list of bytes) representing the process logic.
    """
    log.trace3(
        f"disassemble_ladder_process_logic: len={len(process_logic)}, "
        f"starting_address={starting_address}"
    )

    # TODO: disassemble_ladder_process_logic was previously commented out,
    # it is non-functional as-is.
    # instruction_byte_list = zip(*(iter(process_logic),) * 4)
    # # breakpoint()
    # # do 4 ints need to be combined? or have they already been unpacked?
    # instruction_list = [
    #     unpack_dint("".join(instruction)) for instruction in instruction_byte_list
    # ]

    instruction_list = process_logic
    out = []
    if instruction_list:
        out.append("Relay Ladder")
        for instruction in instruction_list:
            out.append(
                f"[0x{starting_address:0>8x}]  "
                 f"{instruction & 0xFFFFFFFF:0>8x}  "
                + disassemble_instruction(instruction)
            )
            starting_address += 0x4
        return "\n".join(out)
    else:
        log.debug(
            f"No instruction list for ladder_process logic starting "
            f"address: {starting_address}\nbytes: {process_logic}"
        )
        return ""


def _get_line_prefix(address: int, instruction: int, indent_level: int = 0) -> str:
    """
    Returns a standard line prefix based on an address and an instruction.

    If both the address and instruction are 0, prints spaces that
    evenly space out the columns instead.
    """
    out = []

    if address == 0x00 and instruction == 0x00:
        out.append(" " * 24)
    else:
        out.append(f"[0x{address:0>8x}]  {instruction & 0xFFFFFFFF:0>8x}  ")
    out.append("  " * indent_level)

    return "".join(out)


def _decompile_OPERAND(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles an OPERAND instruction.

    This represents an argument to a operation.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24
    # operand_index = opcode & 0x07
    # Second hex digit is the operand number
    operand_index = opcode & 0x0F

    # If second byte is "d8", it's an intermediate result
    if (operand & 0x00FF0000) == 0x00D80000:
        argument = operand & 0x0000FFFF
        decompiled = "{0}[{1}] := INTERMED RESULT [0x{2:0>4x}]".format(
            LOGIC_OPCODE[opcode]["name"], str(operand_index), argument
        )
        return decompiled, starting_address
    else:
        if operand & 0x00800000:
            operand &= 0x007FFFFF
            operand += MODULE_SEGMENT_ADDRESS
        decompiled = "{0}[{1}] := [@0x{2:0>8x}@]".format(
            LOGIC_OPCODE[opcode]["name"], str(operand_index), operand
        )
        return decompiled, starting_address


def _decompile_CONST(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a CONST instruction.

    This holds an immediate value in its lowest two bytes.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction ends.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24
    val = operand & 0x0000FFFF
    operand_index = (operand & 0x00FE0000) >> 17

    # Don"t think this is right for constants
    # if (operand & 0x00800000):
    #    operand = operand & 0x007FFFFF
    #    val = operand + MODULE_SEGMENT_ADDRESS
    return (
        "{0}[{1}] := [0x{2:0>8x}]".format(
            LOGIC_OPCODE[opcode]["name"], operand_index, val
        ),
        starting_address,
    )


def _decompile_LOADMEM(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a LOAD MEM instruction.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24
    argument = operand >> 3
    return (
        "{0} := 0x{1:0>8x}".format(LOGIC_OPCODE[opcode]["name"], argument),
        starting_address,
    )


# Still unsure exactly what these do - they are grouped as "STR" in original code
def _decompile_STR(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a "STR" instruction.

    Not exactly sure what these are supposed to represent.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24

    # Special case - PUSH ARG is best guess for what this does; it postfixes
    # operation arguments and appears to allow operations to take a variable number
    # of arguments
    if opcode == 0xAC and operand == 0xFD1000:
        return "PUSH ARG", starting_address
    # Parse intermediate results
    elif (operand & 0x00E00000) == 0x00800000:  # If third hex digit is 8 or 9
        operand_index = (operand & 0x001E0000) >> 17
        argument = operand & 0x0000FFFF
        return (
            "{0}[{1}] := INTERMED RESULT [0x{2:0>4x}]".format(
                LOGIC_OPCODE[opcode]["name"], str(operand_index), argument
            ),
            starting_address,
        )
    else:
        argument = operand >> 3
        return (
            "{0}    := [0x{1:0>8x}]".format(LOGIC_OPCODE[opcode]["name"], argument),
            starting_address,
        )


def _decompile_default(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple:
    """
    Default decompiliation function.

    Just returns the stored name of the opcode.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24
    # TODO: not sure if this function is working correctly, should just return name...
    return LOGIC_OPCODE[opcode]["dec"](opcode, operand), starting_address


def _decompile_TIMER(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a timer-related instruction.

    Does so by just printing out the instruction name.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24
    return LOGIC_OPCODE[opcode]["name"], starting_address


def _decompile_PTR(
    instruction_list: list[int],
    starting_address: int,
    indent_level: int,
    operand: int,
    resolve_operand: bool = True,
) -> tuple[str, int]:
    """
    Decompiles a PTR instruction.

    This represents a pointer to somewhere in memory.
    The pointer is right-shifted by two bits.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer
        resolve_operand: Boolean representing whether or not to perform name
            resolution on the operand of this instruction

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24
    operand_index = opcode & 0x0F
    argument = operand << 2

    if resolve_operand:
        return (
            "{0}[{1}] := [@0x{2:0>8x}@]".format(
                LOGIC_OPCODE[opcode]["name"], str(operand_index), argument
            ),
            starting_address,
        )
    else:
        return (
            "{0}[{1}] := [0x{2:0>8x}]".format(
                LOGIC_OPCODE[opcode]["name"], str(operand_index), argument
            ),
            starting_address,
        )


def _decompile_BIT_OP(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles instructions that operate on individual boolean variables.

    Ex: XIC, OTE

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    opcode = (instruction_list[0] & 0xFF000000) >> 24
    operand_bit_index = opcode & 0x07
    argument_value = operand & 0x007FFFFF
    argument_segment = (operand & 0x00800000) >> 23
    # Still don"t really know the purpose of MODULE_SEGMENT_ADDRESS
    if argument_segment == 1:
        argument_value += MODULE_SEGMENT_ADDRESS
    argument = f"@0x{argument_value & 0xFFFFFFFF:0>8x}@"

    return (
        "{0}({1})[{2}]".format(
            LOGIC_OPCODE[opcode]["name"], argument, str(operand_bit_index)
        ),
        starting_address,
    )


def _decompile_RUNGEND(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a rung ending instruction.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    return "RUNG END", starting_address


def _decompile_BST(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[list[str], int]:
    """
    Decompiles a branch start instruction and branch sub-instructions.

    Includes the sub-instructions that are a part of the starting branch.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled and containing all of its
            (potential) sub-instructions
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    out = ["BRANCH START ["]
    branch_length = len(instruction_list)

    # Loop through instructions until we find a next branch or branch end instruction
    for idx, instruction in enumerate(instruction_list[1:]):
        next_opcode = (instruction & 0xFF000000) >> 24
        if next_opcode in LOGIC_OPCODE and LOGIC_OPCODE[next_opcode]["name"] in [
            "NXB",
            "BND",
        ]:
            branch_length = idx + 1
            break

    # Decompile the branch as one indent level higher
    branch_out = decompile_process_logic_segment(
        instruction_list[1:branch_length], starting_address + 4, indent_level + 1
    )
    out.append("".join(branch_out))
    # Offset the address by however many instructions were in the branch

    return out, starting_address + (4 * (branch_length - 1))


def _decompile_NXB(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[list[str], int]:
    """
    Decompiles a "next branch" instruction and the branches instructions.

    Inclues the instructions that make up the branch it represents.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled and containing all of its
            (potential) sub-instructions
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    out = ["] NEXT BRANCH ["]
    branch_length = len(instruction_list)

    # Loop through instructions until we find a next branch or branch end instruction
    for idx, instruction in enumerate(instruction_list[1:]):
        next_opcode = (instruction & 0xFF000000) >> 24
        # Use dict.get() to handle unknown opcodes
        if LOGIC_OPCODE.get(next_opcode, {}).get("name") in ["NXB", "BND"]:
            branch_length = idx + 1
            break

    # Decompile the branch as one indent level higher
    branch_out = decompile_process_logic_segment(
        instruction_list[1:branch_length], starting_address + 4, indent_level + 1
    )
    out.append("".join(branch_out))

    # Offset the address by however many instructions were in the branch
    return out, starting_address + (4 * (branch_length - 1))


def _decompile_BND(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple:
    """
    Decompiles a branch end instruction.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction ends.
    """
    return "] BRANCH END", starting_address


def _decompile_RUNG(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[list[str], int]:
    """
    Decompiles a ladder-logic rung.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled and containing all of its
            (potential) sub-instructions.
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    out = ["RUNG:"]
    current_address = starting_address

    rungend_address = (operand << 2) - 4
    rungend_idx = (rungend_address - current_address) // 4
    rung_instruction_list = instruction_list[2:rungend_idx]

    block_out = decompile_process_logic_segment(
        rung_instruction_list, current_address + 8, indent_level + 1
    )
    out.append("".join(block_out))

    rungend_instruction = instruction_list[rungend_idx : rungend_idx + 1]
    rungend_out = decompile_process_logic_segment(
        rungend_instruction, rungend_address, indent_level
    )
    out.append("".join(rungend_out))

    return out, rungend_address


def _decompile_BLOCK(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[list[str], int]:
    """
    Decompile an instruction block.

    Args:
        instruction_list: A list of instructions, starting with the
            instruction to be decompiled and containing all of its
            (potential) sub-instructions
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        operand: The lower three bytes of the instruction, as an integer

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    out = ["INSTRUCTION BLOCK:"]
    current_address = starting_address

    next_instructions = instruction_list[1:3]
    if (
        (len(next_instructions) == 2)
        and (next_instructions[0] & 0xFFFFFFFF == 0xACFD1FFC)
        and (next_instructions[1] & 0xFFFFFFFF == 0x179F1000)
    ):
        blockend_address = operand - 8
        blockstart_idx = 3
        inblock_address = current_address + 12
        next_instruction_address = blockend_address + 4
    else:
        blockend_address = operand - 4
        blockstart_idx = 1
        inblock_address = current_address + 4
        next_instruction_address = blockend_address

    blockend_idx = 1 + ((blockend_address - current_address) // 4)
    block_instruction_list = instruction_list[blockstart_idx:blockend_idx]
    block_out = decompile_process_logic_segment(
        block_instruction_list, inblock_address, indent_level + 1
    )
    out.append("".join(block_out))
    out.append(
        "\n" + _get_line_prefix(0x00, 0x00, indent_level) + "END INSTRUCTION BLOCK"
    )

    return out, next_instruction_address


def _decompile_SPC_block_op_default(
    instruction_list: list[int],
    starting_address: int,
    indent_level: int,
    spc_instruction: int,
) -> tuple[str, int]:
    """
    Decompiles normal SPC operations.

    These contain sub-instructions with their parameters.

    Args:
        instruction_list: A list of instructions, starting with the SPC
            instruction to be decompiled and containing all of its
            (potential) sub-instructions.
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """

    out = []
    current_address = starting_address

    next_instructions = instruction_list[0:2]
    arg_length, arg_offset = _get_spc_arg_length2(next_instructions)

    out.append(OPERATION_STRUCT[spc_instruction]["name"])
    # Calculate which of the following instructions are the parameters
    # The "header" and "footer" of the operation are currently ignored, as they appear
    # to be mostly deterministic for each operation
    argsstart_idx = 1 + arg_offset + OPERATION_STRUCT[spc_instruction]["header_len"]
    argsstart_address = current_address + (argsstart_idx * 4)
    argsend_idx = argsstart_idx + arg_length
    instruction_args = instruction_list[argsstart_idx:argsend_idx]

    # Output the operation's args, enclosed by square brackets
    out.append("[")
    out.append(
        decompile_process_logic_segment(
            instruction_args, argsstart_address, indent_level + 1
        )
    )
    out.append("\n" + _get_line_prefix(0x00, 0x00, indent_level) + "]")

    spc_instruction_length = (
        argsend_idx + OPERATION_STRUCT[spc_instruction]["footer_len"] - 1
    )
    current_address += spc_instruction_length * 4

    return "".join(out), current_address


def _decompile_SPC_block_op_CPT(
    instruction_list: list[int],
    starting_address: int,
    indent_level: int,
    spc_instruction: int,
) -> tuple[str, int]:
    """
    Special decompiliation routine for operations with sub-operations.

    Special routine for operations that are composed exclusively of
    sub-operations (e.g. CPT, CMP).

    Args:
        instruction_list: A list of instructions, starting with the SPC
            instruction to be decompiled and containing all of its
            (potential) sub-instructions.
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation
        spc_instruction:

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    out = []

    block_out, current_address = _decompile_SPC_block_op_default(
        instruction_list, starting_address, indent_level, spc_instruction
    )
    out.append("".join(block_out))

    blockstart_idx = ((current_address - starting_address) // 4) + 1
    # Last segment of the footer contains the end address for the operation
    blockend_address = 0x00FFFFFF & instruction_list[blockstart_idx - 1]
    blockend_idx = (blockend_address - starting_address) // 4
    block_size = blockend_idx - blockstart_idx
    # Last two segments are another footer, ignore them
    block_instruction_list = instruction_list[blockstart_idx : blockend_idx - 2]
    block_out = decompile_process_logic_segment(
        block_instruction_list, current_address + 4, indent_level + 1
    )
    out.append("".join(block_out))
    current_address += (block_size + 1) * 4

    return "".join(out), current_address


def _decompile_SPC_block_op(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a SPC block operation.

    Currently, this can be done two different ways depending on the operation.
    """
    spc_instruction = operand & 0x0000FFFF
    if spc_instruction in OPERATION_STRUCT:
        # These are the four instructions identified so far that use this
        # format. It might be nice to generalize this a bit?
        if (
            OPERATION_STRUCT[spc_instruction]["name"] == "CPT"
            or OPERATION_STRUCT[spc_instruction]["name"] == "CMP"
            or OPERATION_STRUCT[spc_instruction]["name"] == "FAL"
            or OPERATION_STRUCT[spc_instruction]["name"] == "FSC"
        ):
            return _decompile_SPC_block_op_CPT(
                instruction_list, starting_address, indent_level, spc_instruction
            )

        else:
            return _decompile_SPC_block_op_default(
                instruction_list, starting_address, indent_level, spc_instruction
            )

    return "???", starting_address


def _decompile_SPC_array_def(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles static array definitions.

    An array definition appears to include the data type size, size of
    dimensions 2, 1, and 0, and the number of nonzero dimensions.
    Currently, these arguments are not given labels.
    """
    return "ARRAY DEFINITION:", starting_address


def _decompile_SPC_function_ptr(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a function pointer indicator.

    This also disables name resolution on the argument it modifies.
    """
    out = []
    current_address = starting_address

    next_instruction = instruction_list[1]
    next_opcode = (next_instruction & 0xFF000000) >> 24
    out.append("FUNCTION PTR:")

    # If next operand is pointer, print it out, but without name resolution
    if LOGIC_OPCODE[next_opcode]["name"] == "PTR":
        current_address += 4
        out.append(
            "\n" + _get_line_prefix(current_address, next_instruction, indent_level)
        )
        out.append(
            _decompile_PTR(
                instruction_list[1:],
                current_address,
                indent_level,
                next_instruction & 0x00FFFFFF,
                resolve_operand=False,
            )[0]
        )

    return "".join(out), current_address


def _decompile_SPC_structure_type(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Decompiles a structure type indicator.
    """
    structure_type = operand & 0x0000FFFF
    if structure_type in STRUCTURE_TYPES:
        return STRUCTURE_TYPES[structure_type] + ":", starting_address

    return "UNKNOWN TYPE:", starting_address


def _decompile_SPC_default(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[str, int]:
    """
    Prints out the given name of the SPC extended opcode.
    """
    extended_opcode = (operand & 0xFFFF0000) >> 16
    if extended_opcode in EXTENDED_OPCODE:
        return EXTENDED_OPCODE[extended_opcode]["name"], starting_address

    return "???", starting_address


def _decompile_SPC(
    instruction_list: list[int], starting_address: int, indent_level: int, operand: int
) -> tuple[list[str], int]:
    """
    Decompiles the SPC instruction.

    This can can mean a lot of different things, but
    which mainly deals with multi-instruction operations.

    Args:
        instruction_list: A list of instructions, starting with the SPC
            instruction to be decompiled and containing all of its
            (potential) sub-instructions.
        starting_address: The address that this instruction starts at
        indent_level: The current level of indentation

    Returns:
        Tuple containing an array of strings that represents this instruction
        and the address at which the instruction and its sub-instructions end.
    """
    out = []

    # Choose which sub-function to call based on the extended opcode
    extended_opcode = (operand & 0xFFFF0000) >> 16
    if extended_opcode in EXTENDED_OPCODE:
        spc_dec = EXTENDED_OPCODE[extended_opcode]["dec"]  # Select function to call
    else:
        spc_dec = _decompile_SPC_default

    spc_out, current_address = spc_dec(
        instruction_list, starting_address, indent_level, operand
    )
    out.append(spc_out)

    return out, current_address


def _get_spc_arg_length2(next_instructions: list) -> tuple[int, int]:
    """
    Gets the argument list length of an operation.

    The argument length is either the fourth-highest hex digit, or contained
    in a separate block length instruction immediately following the operation
    if the argument list is longer than 15 elements.

    Args:
        next_instructions: The next instructions to evaluate
            (starting with the operation instruction itself).

    Returns:
        Tuple containing the argument length and how much to offset the
        argument length by.
    """
    arg_count = (next_instructions[0] & 0x000F0000) >> 16
    arg_offset = 0

    if len(next_instructions) == 2:
        next_opcode = (next_instructions[1] & 0xFFFF0000) >> 16
        # If the next instruction is a block length instruction,
        # use its operand as the length and offset the argument list by 1
        if (next_opcode in EXTENDED_OPCODE) and (
            EXTENDED_OPCODE[next_opcode]["name"] == "BLOCK LENGTH"
        ):
            arg_count += next_instructions[1] & 0x0000FFFF
            arg_offset = 1

    return arg_count, arg_offset


MODULE_SEGMENT_ADDRESS: Final[int] = 0x0C000000

# Type identifiers, used in certain SPC instructions
STRUCTURE_TYPES: Final[dict[int, str]] = {
    0x00C2: "ARRAY (SINT)",
    0x00C4: "ARRAY (DINT)",
    0x00CA: "ARRAY (REAL)",
    0x0FFA: "ALMA STRUCT",
    0x0FFB: "ALMD STRUCT",
}

# Operation codes
# These appear as the lower two bytes of certain SPC instructions, and denote
# multi-instruction operations
OPERATION_STRUCT: Final[dict[int, dict[str, str | int]]] = {
    0x8000: {
        "name": "ADD (DINT)",
        "header_len": 0,
        "footer_len": 2,
    },
    0x8001: {
        "name": "SUB (DINT)",
        "header_len": 0,
        "footer_len": 2,
    },
    0x8002: {
        "name": "MUL (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8003: {
        "name": "DIV (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8004: {
        "name": "SQR (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8005: {
        "name": "NEG (DINT)",
        "header_len": 0,
        "footer_len": 3,
    },
    0x8006: {
        "name": "CLR (DINT)",
        "header_len": 0,
        "footer_len": 2,
    },
    0x8007: {
        "name": "MOV (DINT)",
        "header_len": 0,
        "footer_len": 2,
    },
    0x8008: {
        "name": "ADD (REAL)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8009: {
        "name": "SUB (REAL)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x800A: {
        "name": "MUL (REAL)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x800B: {
        "name": "DIV (REAL)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x800C: {
        "name": "SQR (REAL)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x800D: {
        "name": "NEG (REAL)",
        "header_len": 0,
        "footer_len": 10,
    },
    0x800E: {
        "name": "CLR (REAL)",
        "header_len": 0,
        "footer_len": 2,
    },
    0x800F: {
        "name": "MOV (REAL)",
        "header_len": 0,
        "footer_len": 8,
    },
    0x8012: {
        "name": "ONS",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8013: {
        "name": "OSR",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8014: {
        "name": "OSF",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8016: {
        "name": "BTD",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8017: {
        "name": "FAL",
        "header_len": 5,
        "footer_len": 6,
    },
    0x8018: {
        "name": "FSC",
        "header_len": 5,
        "footer_len": 6,
    },
    0x801B: {
        "name": "EQU",
        "header_len": 0,
        "footer_len": 1,
    },
    0x801C: {
        "name": "NEQ",
        "header_len": 0,
        "footer_len": 1,
    },
    0x801D: {
        "name": "LES",
        "header_len": 0,
        "footer_len": 1,
    },
    0x801E: {
        "name": "LEQ",
        "header_len": 0,
        "footer_len": 1,
    },
    0x801F: {
        "name": "GRT",
        "header_len": 0,
        "footer_len": 1,
    },
    0x8020: {
        "name": "GEQ",
        "header_len": 0,
        "footer_len": 1,
    },
    0x8021: {
        "name": "LIM",
        "header_len": 0,
        "footer_len": 8,
    },
    0x8022: {
        "name": "MEQ",
        "header_len": 0,
        "footer_len": 3,
    },
    0x8023: {
        "name": "EQU (REAL)",
        "header_len": 0,
        "footer_len": 1,
    },
    0x8024: {
        "name": "NEQ (REAL)",
        "header_len": 0,
        "footer_len": 1,
    },
    0x8025: {
        "name": "LES (REAL)",
        "header_len": 0,
        "footer_len": 5,
    },
    0x8026: {
        "name": "LEQ (REAL)",
        "header_len": 0,
        "footer_len": 5,
    },
    0x8027: {
        "name": "GRT (REAL)",
        "header_len": 0,
        "footer_len": 5,
    },
    0x8028: {
        "name": "GEQ (REAL)",
        "header_len": 0,
        "footer_len": 5,
    },
    0x8029: {
        "name": "LIM (REAL)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x802A: {
        "name": "AND",
        "header_len": 0,
        "footer_len": 2,
    },
    0x802B: {
        "name": "OR",
        "header_len": 0,
        "footer_len": 2,
    },
    0x802C: {
        "name": "XOR",
        "header_len": 0,
        "footer_len": 2,
    },
    0x802D: {
        "name": "NOT",
        "header_len": 0,
        "footer_len": 3,
    },
    0x802E: {
        "name": "MVM",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8031: {
        "name": "JMP",
        "header_len": 1,
        "footer_len": 2,
    },
    0x8032: {
        "name": "LBL",
        "header_len": 0,
        "footer_len": 0,
    },
    0x8033: {
        "name": "FLL",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8036: {
        "name": "COP",
        "header_len": 3,
        "footer_len": 3,
    },
    0x803C: {
        "name": "FOR",
        "header_len": 5,
        "footer_len": 5,
    },
    0x803E: {
        "name": "REAL->SINT",
        "header_len": 3,
        "footer_len": 3,
    },
    0x803F: {
        "name": "REAL->INT",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8040: {
        "name": "REAL->DINT",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8041: {
        "name": "SINT->DINT",
        "header_len": 2,
        "footer_len": 4,
    },
    0x8042: {
        "name": "DINT->SINT",
        "header_len": 4,
        "footer_len": 3,
    },
    0x8045: {
        "name": "INT->DINT",
        "header_len": 2,
        "footer_len": 7,
    },
    0x8050: {
        "name": "BSL",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8051: {
        "name": "BSR",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8052: {
        "name": "FFL (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8053: {
        "name": "LFL (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8054: {
        "name": "FFU (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8055: {
        "name": "LFU (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8058: {
        "name": "CMP",
        "header_len": 4,
        "footer_len": 5,
    },
    0x8059: {
        "name": "CPT",
        "header_len": 4,
        "footer_len": 5,
    },
    0x805C: {
        "name": "SINT->REAL",
        "header_len": 2,
        "footer_len": 16,  # I have no idea why this is so long
    },
    0x805E: {
        "name": "DINT->REAL",
        "header_len": 4,
        "footer_len": 3,
    },
    0x807A: {
        "name": "JSR",
        "header_len": 4,
        "footer_len": 4,
    },
    0x807B: {
        "name": "SBR",
        "header_len": 3,
        "footer_len": 3,
    },
    0x807C: {
        "name": "RET",
        "header_len": 3,
        "footer_len": 3,
    },
    0x807D: {
        "name": "SQI",
        "header_len": 3,
        "footer_len": 3,
    },
    0x807E: {
        "name": "SQO",
        "header_len": 3,
        "footer_len": 3,
    },
    0x807F: {
        "name": "SQL",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8080: {
        "name": "AVE (DINT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8081: {
        "name": "SRT (DINT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8082: {
        "name": "AVE (REAL)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8083: {
        "name": "STD (DINT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8084: {
        "name": "STD (REAL)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x808C: {
        "name": "AVE (SINT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x808D: {
        "name": "AVE (INT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x808E: {
        "name": "STD (SINT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x808F: {
        "name": "STD (INT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8092: {
        "name": "SRT (SINT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8093: {
        "name": "SRT (INT)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8094: {
        "name": "SRT (REAL)",
        "header_len": 4,
        "footer_len": 4,
    },
    0x8106: {
        "name": "FFL (SINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    # 0x8107-0x8109 are likely SINT variants on FIFO/LIFO buffers
    0x80BF: {
        "name": "ACCESS IDX (SINT)",
        "header_len": 2,
        "footer_len": 8,
    },
    0x80C1: {
        "name": "ACCESS IDX (DINT)",
        "header_len": 2,
        "footer_len": 8,
    },
    0x80CE: {
        "name": "ABS (DINT)",
        "header_len": 0,
        "footer_len": 4,
    },
    0x80CF: {
        "name": "ABS (REAL)",
        "header_len": 0,
        "footer_len": 10,
    },
    0x80D0: {
        "name": "MOD (DINT)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x80D1: {
        "name": "MOD (REAL)",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8138: {
        "name": "CPS",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8139: {
        "name": "SIZE",
        "header_len": 3,
        "footer_len": 3,
    },
    0x813C: {
        "name": "SWPB",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8157: {
        "name": "COP",
        "header_len": 3,
        "footer_len": 3,
    },
    0x8158: {
        "name": "ALM",
        "header_len": 3,
        "footer_len": 1,
    },
    0x8159: {
        "name": "ALM END",
        "header_len": 0,
        "footer_len": 3,
    },
    0x8166: {
        "name": "ALM INPUT",
        "header_len": 0,
        "footer_len": 1,
    },
    0x8167: {
        "name": "ALM ARG",
        "header_len": 0,
        "footer_len": 7,
    },
    0x8175: {
        "name": "ALMD STRUC",
        "header_len": 1,
        "footer_len": 1,
    },
    0x8180: {
        "name": "ALMA STRUC",
        "header_len": 0,
        "footer_len": 1,
    },
    0x8186: {
        "name": "CPS",
        "header_len": 3,
        "footer_len": 3,
    },
}

# "Opcodes" that are in the second byte of the 0x00 "SPC" instruction
# These usually modify the meaning of the instructions following them
EXTENDED_OPCODE: Final[dict[int, dict[str, str | Callable]]] = {
    0x10: {"name": "???", "dec": _decompile_SPC_default},
    # Gives the type of next operand
    0x20: {"name": "STRUCTURE TYPE", "dec": _decompile_SPC_structure_type},
    0x21: {"name": "???", "dec": _decompile_SPC_default},
    # Represents sub-operations?
    0x30: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x31: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x32: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x33: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x34: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x35: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x36: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x37: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x38: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x39: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x3A: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x3B: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x3C: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x3D: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x3E: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x3F: {"name": "SUB BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    # Normal top-level operations
    0x40: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x41: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x42: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x43: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x44: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x45: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x46: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x47: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x48: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x49: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x4A: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x4B: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x4C: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x4D: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x4E: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x4F: {"name": "BLOCK OPERATION", "dec": _decompile_SPC_block_op},
    0x50: {"name": "NOP", "dec": _decompile_SPC_default},
    # Next operand is a function pointer
    0x60: {"name": "FUNCTION PTR", "dec": _decompile_SPC_function_ptr},
    0x70: {"name": "BLOCK LENGTH", "dec": _decompile_SPC_default},
    0x80: {"name": "???", "dec": _decompile_SPC_default},
    0x90: {"name": "???", "dec": _decompile_SPC_default},
    0xA0: {"name": "ARRAY DEFINITION", "dec": _decompile_SPC_array_def},
    0xB0: {"name": "???", "dec": _decompile_SPC_default},
}

LOGIC_OPCODE: Final[dict[int, dict[str, str | Callable]]] = {
    # Represents a "special" operation
    0x00: {
        "name": "SPC",
        "dec": _decompile_SPC,
    },
    0x17: {
        "name": "STR",
        "dec": _decompile_STR,
    },
    0x1A: {
        "name": "STR",
        "dec": _decompile_STR,
    },
    0x1B: {
        "name": "STR",
        "dec": _decompile_STR,
    },
    # Instruction block start
    0x34: {
        "name": "BLOCK",
        "dec": _decompile_BLOCK,
    },
    0x3F: {
        "name": "LOAD MEM",
        "dec": _decompile_LOADMEM,
    },
    # Examine if closed
    0x40: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    0x41: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    0x42: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    0x43: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    0x44: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    0x45: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    0x46: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    0x47: {
        "name": "XIC",
        "dec": _decompile_BIT_OP,
    },
    # Examine if open
    0x48: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    0x49: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    0x4A: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    0x4B: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    0x4C: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    0x4D: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    0x4E: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    0x4F: {
        "name": "XIO",
        "dec": _decompile_BIT_OP,
    },
    # Output latch
    0x50: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    0x51: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    0x52: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    0x53: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    0x54: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    0x55: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    0x56: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    0x57: {
        "name": "OTL",
        "dec": _decompile_BIT_OP,
    },
    # Output unlatch
    0x58: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    0x59: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    0x5A: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    0x5B: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    0x5C: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    0x5D: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    0x5E: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    0x5F: {
        "name": "OTU",
        "dec": _decompile_BIT_OP,
    },
    # These are all 8 long
    # Output energize
    0x60: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    0x61: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    0x62: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    0x63: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    0x64: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    0x65: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    0x66: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    0x67: {
        "name": "OTE",
        "dec": _decompile_BIT_OP,
    },
    # Timer/counter opcodes
    0x68: {"name": "TON", "dec": _decompile_TIMER},
    0x69: {"name": "TOF", "dec": _decompile_TIMER},
    0x6A: {"name": "RTO", "dec": _decompile_TIMER},
    0x6B: {"name": "RES", "dec": _decompile_TIMER},
    0x6C: {"name": "CTU", "dec": _decompile_TIMER},
    0x6D: {"name": "CTD", "dec": _decompile_TIMER},
    # Branch start
    0x70: {
        "name": "BST",
        "dec": _decompile_BST,
    },
    # Next branch (separates branches that branch at the same spot)
    0x71: {
        "name": "NXB",
        "dec": _decompile_NXB,
    },
    # 0x72 is something else to do with branches?
    # Branch end
    0x73: {
        "name": "BND",
        "dec": _decompile_BND,
    },
    # Denotes beginning of the rung
    0x78: {
        "name": "RUNGSTART",
        "dec": _decompile_RUNG,
    },
    # Rung ending
    0x7A: {
        "name": "RUNGEND",
        "dec": _decompile_RUNGEND,
    },
    # SINT arguments (this is maybe incorrect)
    0x80: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    0x81: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    0x82: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    0x83: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    0x84: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    0x85: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    0x86: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    0x87: {
        "name": "ARG (SINT)",
        "dec": _decompile_OPERAND,
    },
    # Constants
    0x8D: {
        "name": "CONST",
        "dec": _decompile_CONST,
    },
    # TODO: Find better names for these two - the term "WORD" can be confusing
    0x8E: {
        "name": "CONST (LOW WORD)",
        "dec": _decompile_CONST,
    },
    0x8F: {
        "name": "CONST (HIGH WORD)",
        "dec": _decompile_CONST,
    },
    # Represents a pointer to someplace in memory
    0x90: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x91: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x92: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x93: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x94: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x95: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x96: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x97: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x98: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x99: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x9A: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x9B: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x9C: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x9D: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x9E: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0x9F: {
        "name": "PTR",
        "dec": _decompile_PTR,
    },
    0xAC: {
        "name": "STR",
        "dec": _decompile_STR,
    },
    # Function arguments (TODO: figure out if these also use 0xc8-0xcf)
    0xC0: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xC1: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xC2: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xC3: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xC4: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xC5: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xC6: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xC7: {
        "name": "ARG (DINT)",
        "dec": _decompile_OPERAND,
    },
    0xE0: {
        "name": "?",
        "dec": _decompile_default,
    },
}


def instruction_buffer_to_instruction_list(instruction_buffer: list) -> list:
    """
    Converts an instruction buffer to an instruction list.

    Args:
        instruction_buffer: instruction buffer as little-endian formatted list of bytes

    Returns:
        Instruction list as properly formatted list of 32-bit integers
    """

    instruction_byte_list = list(zip(*(iter(instruction_buffer),) * 4))
    instruction_list = [
        unpack_dint(bytes(instruction)) & 0xFFFFFFFF
        for instruction in instruction_byte_list
    ]
    return instruction_list


def _resolve_token_name(
    token_address: int, symbol_list: list[tuple], template_data: dict
) -> str:
    """
    Returns the name of the token at the specified memory address.

    If name cannot be resolved, returns the memory address of the token.

    Args:
        token_address: the memory address of the token
        symbol_list: a list of tuples: (address, symbol)
        template_data: a data structure representing all template data

    Returns:
        The name of the token
    """
    # TODO: only works with exact offset matches. doesn't work with multibyte types yet
    symbol_list.append((0, None))
    symbol = max(symbol for symbol in symbol_list if symbol[0] <= token_address)[1]
    if symbol is None:
        return f"0x{token_address:0>8x}"

    token_offset = token_address - symbol[3]

    if token_offset == 0:  # Don"t print the offset if it's zero
        token_name = symbol[1]
    else:
        token_name = f"{symbol[1]}+0x{token_offset & 0xFFFFFFFF:0>8x}"

    symbol_type = symbol[2]
    token_type = symbol_type & 0x0FFF
    # token_type_dimension = (symbol_type & 0x6000) >> 13
    is_structure_type = ((symbol_type & 0x8000) >> 15) == 1

    if is_structure_type and (token_type in template_data):
        token_template = template_data[token_type]
        if token_offset in token_template["Structure"]:
            field_name = token_template["Structure"][token_offset]["Name"]
            token_name = f"{symbol[1]}.{field_name}"

    return token_name


def _resolve_all_token_names(
    data: str, symbol_list: LayoutType, template_data: dict
) -> str:
    """
    Returns the original string with all token names resolved.

    Args
        data: a string with unresolved token names
        symbol_list:

    Returns:
        The original string with all token names resolved
    """
    data_split = data.split("@")  # odd indices are tokens to process

    for token_idx in range(1, len(data_split), 2):  # process every token
        token = int(data_split[token_idx], 0)
        token_name = _resolve_token_name(token, symbol_list, template_data)
        data_split[token_idx] = token_name
    return "".join(data_split)


def decompile_process_logic_segment(
    instruction_list: list[int], starting_address: int, indent_level: int = 0
) -> str:
    """
    Decompiles a segment of process logic.

    Decompiles a segment of process logic by calling each instruction's
    decompile method. Note that each decompile call may consume more than
    one instruction and may recursively call this function.

    Args:
        instruction_list: The list of instructions to decompile. It is implicitly
          assumed that if any operation is in the list, the list also contains
          all of the instructions required by its decompiliation function.
        starting_address: The address of the first instruction in the list
        indent_level: The indentation level to use

    Returns:
        A string representing the decompiliation of the given instructions
    """
    out = []
    current_address = starting_address
    ending_address = starting_address + (len(instruction_list) * 4)

    while current_address < ending_address:
        instruction_start_idx = (current_address - starting_address) // 4
        instruction = instruction_list[instruction_start_idx]
        # Write the address and instruction hex out before each instruction
        out.append("\n" + _get_line_prefix(current_address, instruction, indent_level))

        opcode = (instruction & 0xFF000000) >> 24
        operand = instruction & 0x00FFFFFF
        # Run the instruction's decompile function, if it has one, and set current
        # address to the returned ending address of the instruction
        if opcode in LOGIC_OPCODE:
            block_out, current_address = LOGIC_OPCODE[opcode]["dec"](
                instruction_list[instruction_start_idx:],
                current_address,
                indent_level,
                operand,
            )
            out.append("".join(block_out))
        # Advance to instruction after the end of the last one
        current_address += 4

    return "".join(out)


# NOTE(cegoes): According to one of Greg's commits, these 2 functions aren't really doing anything.
# However, removing them caused issues for him, since I think they're being called
# from PEAT. However, the result isn"t being used for anything. Just leave the alone for now.
# NOTE(cegoes, 4/19/2018): this included disassemble_process_logic I think
def disassemble_instruction(instruction: int) -> str:
    """
    Obtains the human-readable instruction from the bytecode instruction.

    Args:
        instruction: uint byte-code instruction

    Returns:
        String representing human-readable disassembled instruction
    """
    opcode = (instruction & 0xFF000000) >> 24
    operand = instruction & 0x00FFFFFF

    disassembled_instruction = "?"
    if opcode in LOGIC_OPCODE:
        opcode_name = LOGIC_OPCODE[opcode]["name"]  # noqa: F841
        disassemble_func = LOGIC_OPCODE[opcode]["dec"]
        disassembled_instruction = disassemble_func(opcode, operand)
    return disassembled_instruction
