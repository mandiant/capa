import string
import struct

from capa.features.common import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN


def _bb_has_tight_loop(f, bb):
    """
    parse tight loops, true if last instruction in basic block branches to bb start
    """
    return bb.offset in f.blockrefs[bb.offset] if bb.offset in f.blockrefs else False


def extract_bb_tight_loop(f, bb):
    """check basic block for tight loop indicators"""
    if _bb_has_tight_loop(f, bb):
        yield Characteristic("tight loop"), bb.offset


def _bb_has_stackstring(f, bb):
    """
    extract potential stackstring creation, using the following heuristics:
      - basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for instr in bb.getInstructions():
        if is_mov_imm_to_stack(instr):
            count += get_printable_len(instr.getDetailed())
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def get_operands(smda_ins):
    return [o.strip() for o in smda_ins.operands.split(",")]


def extract_stackstring(f, bb):
    """check basic block for stackstring indicators"""
    if _bb_has_stackstring(f, bb):
        yield Characteristic("stack string"), bb.offset


def is_mov_imm_to_stack(smda_ins):
    """
    Return if instruction moves immediate onto stack
    """
    if not smda_ins.mnemonic.startswith("mov"):
        return False

    try:
        dst, src = get_operands(smda_ins)
    except ValueError:
        # not two operands
        return False

    try:
        int(src, 16)
    except ValueError:
        return False

    if not any(regname in dst for regname in ["ebp", "rbp", "esp", "rsp"]):
        return False

    return True


def is_printable_ascii(chars):
    return all(c < 127 and chr(c) in string.printable for c in chars)


def is_printable_utf16le(chars):
    if all(c == 0x00 for c in chars[1::2]):
        return is_printable_ascii(chars[::2])


def get_printable_len(instr):
    """
    Return string length if all operand bytes are ascii or utf16-le printable

    Works on a capstone instruction
    """
    # should have exactly two operands for mov immediate
    if len(instr.operands) != 2:
        return 0

    op_value = instr.operands[1].value.imm

    if instr.imm_size == 1:
        chars = struct.pack("<B", op_value & 0xFF)
    elif instr.imm_size == 2:
        chars = struct.pack("<H", op_value & 0xFFFF)
    elif instr.imm_size == 4:
        chars = struct.pack("<I", op_value & 0xFFFFFFFF)
    elif instr.imm_size == 8:
        chars = struct.pack("<Q", op_value & 0xFFFFFFFFFFFFFFFF)
    else:
        raise ValueError("Unhandled operand data type 0x%x." % instr.imm_size)

    if is_printable_ascii(chars):
        return instr.imm_size
    if is_printable_utf16le(chars):
        return instr.imm_size // 2

    return 0


def extract_features(f, bb):
    """
    extract features from the given basic block.

    args:
      f (smda.common.SmdaFunction): the function from which to extract features
      bb (smda.common.SmdaBasicBlock): the basic block to process.

    yields:
      Tuple[Feature, int]: the features and their location found in this basic block.
    """
    yield BasicBlock(), bb.offset
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, va in bb_handler(f, bb):
            yield feature, va


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_stackstring,
)
