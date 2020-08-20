# Copyright (C) 2020 FireEye, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: https://github.com/fireeye/capa/blob/master/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import string
import struct

from capa.features import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN


# TODO: Avoid this duplication (this code is in __init__ as well)
def block_offset(bb):
    return bb.lines[0].offset


def extract_bb_tight_loop(bb):
    """ check basic block for tight loop indicators """
    if any(c.loc_key == bb.loc_key for c in bb.bto):
        yield Characteristic("tight loop"), block_offset(bb)


def is_mov_imm_to_stack(instr):
    """
    Return if instruction moves immediate onto stack
    """
    if not instr.name.startswith("MOV"):
        return False

    try:
        dst, src = instr.args
    except ValueError:
        # not two operands
        return False

    if not src.is_int():
        return False

    if not dst.is_mem():
        return False

    # should detect things like `@8[ESP + 0x8]` and `EBP` and not fail in other cases
    if any(register in str(dst) for register in ["EBP", "RBP", "ESP", "RSP"]):
        return True

    return False


def is_printable_ascii(chars):
    if sys.version_info >= (3, 0):
        return all(c < 127 and chr(c) in string.printable for c in chars)
    else:
        return all(ord(c) < 127 and c in string.printable for c in chars)


def is_printable_utf16le(chars):
    if all(c == b"\x00" for c in chars[1::2]):
        return is_printable_ascii(chars[::2])


def get_printable_len(insn):
    """
    Return string length if all operand bytes are ascii or utf16-le printable
    """
    dst, src = insn.args

    if not src.is_int():
        return ValueError("unexpected operand type")

    if not dst.is_mem():
        return ValueError("unexpected operand type")

    if isinstance(src.arg, int):
        val = src.arg
    else:
        val = src.arg.arg

    size = (val.bit_length() + 7) // 8

    if size == 0:
        return 0
    elif size == 1:
        chars = struct.pack("<B", val)
    elif size == 2:
        chars = struct.pack("<H", val)
    elif size == 4:
        chars = struct.pack("<I", val)
    elif size == 8:
        chars = struct.pack("<Q", val)

    if is_printable_ascii(chars):
        return size

    if is_printable_utf16le(chars):
        return size / 2

    return 0


def extract_stackstring(bb):
    """ check basic block for stackstring indicators """
    count = 0
    for line in bb.lines:
        if is_mov_imm_to_stack(line):
            count += get_printable_len(line)
        if count > MIN_STACKSTRING_LEN:
            yield Characteristic("stack string"), block_offset(bb)
            return


def extract_features(bb):
    """
    extract features from the given basic block.
    args:
      bb (miasm.core.asmblock.AsmBlock): the basic block to process.
    yields:
      Feature, set[VA]: the features and their location found in this basic block.
    """
    yield BasicBlock(), block_offset(bb)
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, va in bb_handler(bb):
            yield feature, va


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_stackstring,
)
