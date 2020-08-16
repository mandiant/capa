import string
import struct
import logging

from lancelot import (
    FLOW_VA,
    OPERAND_SIZE,
    OPERAND_TYPE,
    MEMORY_OPERAND_BASE,
    OPERAND_TYPE_MEMORY,
    OPERAND_TYPE_IMMEDIATE,
    IMMEDIATE_OPERAND_VALUE,
)

from capa.features import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN

logger = logging.getLogger(__name__)


def extract_bb_tight_loop(ws, bb):
    """ check basic block for tight loop indicators """
    if bb.address in map(lambda flow: flow[FLOW_VA], bb.successors):
        yield Characteristic("tight loop"), bb.address


def is_mov_imm_to_stack(insn):
    if not insn.mnemonic.startswith("mov"):
        return False

    try:
        dst, src = insn.operands
    except ValueError:
        # not two operands
        return False

    if src[OPERAND_TYPE] != OPERAND_TYPE_IMMEDIATE:
        return False

    if src[IMMEDIATE_OPERAND_VALUE] < 0:
        return False

    if dst[OPERAND_TYPE] != OPERAND_TYPE_MEMORY:
        return False

    if dst[MEMORY_OPERAND_BASE] not in ("ebp", "rbp", "esp", "rsp"):
        return False

    return True


def is_printable_ascii(chars):
    return all(c < 127 and chr(c) in string.printable for c in chars)


def is_printable_utf16le(chars):
    if all(c == b"\x00" for c in chars[1::2]):
        return is_printable_ascii(chars[::2])


def get_printable_len(operand):
    """
    Return string length if all operand bytes are ascii or utf16-le printable
    """
    operand_size = operand[OPERAND_SIZE]
    if operand_size == 8:
        chars = struct.pack("<B", operand[IMMEDIATE_OPERAND_VALUE])
    elif operand_size == 16:
        chars = struct.pack("<H", operand[IMMEDIATE_OPERAND_VALUE])
    elif operand_size == 32:
        chars = struct.pack("<I", operand[IMMEDIATE_OPERAND_VALUE])
    elif operand_size == 64:
        chars = struct.pack("<Q", operand[IMMEDIATE_OPERAND_VALUE])
    else:
        raise ValueError("unexpected operand size: " + str(operand_size))

    if is_printable_ascii(chars):
        return operand_size / 8
    if is_printable_utf16le(chars):
        return operand_size / 16

    return 0


def _bb_has_stackstring(ws, bb):
    """
    extract potential stackstring creation, using the following heuristics:
      - basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for insn in bb.instructions:
        if is_mov_imm_to_stack(insn):
            # add number of operand bytes
            src = insn.operands[1]
            count += get_printable_len(src)

        if count > MIN_STACKSTRING_LEN:
            return True

    return False


def extract_stackstring(ws, bb):
    """ check basic block for stackstring indicators """
    if _bb_has_stackstring(ws, bb):
        yield Characteristic("stack string"), bb.address


def extract_basic_block_features(ws, bb):
    yield BasicBlock(), bb.address
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, va in bb_handler(ws, bb):
            yield feature, va


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_stackstring,
)
