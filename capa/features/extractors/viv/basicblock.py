# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import string
import struct
from typing import Tuple, Iterator

import envi
import envi.archs.i386.disasm

from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle


def interface_extract_basic_block_XXX(f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse features from the given basic block.

    args:
      f: the function to process.
      bb: the basic block to process.

    yields:
      (Feature, Address): the feature and the address at which its found.
    """
    raise NotImplementedError


def _bb_has_tight_loop(f, bb):
    """
    parse tight loops, true if last instruction in basic block branches to bb start
    """
    if len(bb.instructions) > 0:
        for bva, bflags in bb.instructions[-1].getBranches():
            if bflags & envi.BR_COND:
                if bva == bb.va:
                    return True

    return False


def extract_bb_tight_loop(f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """check basic block for tight loop indicators"""
    if _bb_has_tight_loop(f, bb.inner):
        yield Characteristic("tight loop"), bb.address


def _bb_has_stackstring(f, bb):
    """
    extract potential stackstring creation, using the following heuristics:
      - basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for instr in bb.instructions:
        if is_mov_imm_to_stack(instr):
            # add number of operand bytes
            src = instr.getOperands()[1]
            count += get_printable_len(src)
        if count > MIN_STACKSTRING_LEN:
            return True

    return False


def extract_stackstring(f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """check basic block for stackstring indicators"""
    if _bb_has_stackstring(f, bb.inner):
        yield Characteristic("stack string"), bb.address


def is_mov_imm_to_stack(instr: envi.archs.i386.disasm.i386Opcode) -> bool:
    """
    Return if instruction moves immediate onto stack
    """
    if not instr.mnem.startswith("mov"):
        return False

    try:
        dst, src = instr.getOperands()
    except ValueError:
        # not two operands
        return False

    if not src.isImmed():
        return False

    if not isinstance(dst, envi.archs.i386.disasm.i386SibOper) and not isinstance(
        dst, envi.archs.i386.disasm.i386RegMemOper
    ):
        return False

    if not dst.reg:
        return False

    rname = dst._dis_regctx.getRegisterName(dst.reg)
    if rname not in ["ebp", "rbp", "esp", "rsp"]:
        return False

    return True


def get_printable_len(oper: envi.archs.i386.disasm.i386ImmOper) -> int:
    """
    Return string length if all operand bytes are ascii or utf16-le printable
    """
    if oper.tsize == 1:
        chars = struct.pack("<B", oper.imm)
    elif oper.tsize == 2:
        chars = struct.pack("<H", oper.imm)
    elif oper.tsize == 4:
        chars = struct.pack("<I", oper.imm)
    elif oper.tsize == 8:
        chars = struct.pack("<Q", oper.imm)
    else:
        raise ValueError(f"unexpected oper.tsize: {oper.tsize}")

    if is_printable_ascii(chars):
        return oper.tsize
    elif is_printable_utf16le(chars):
        return oper.tsize / 2
    else:
        return 0


def is_printable_ascii(chars: bytes) -> bool:
    try:
        chars_str = chars.decode("ascii")
    except UnicodeDecodeError:
        return False
    else:
        return all(c in string.printable for c in chars_str)


def is_printable_utf16le(chars: bytes) -> bool:
    if all(c == 0x0 for c in chars[1::2]):
        return is_printable_ascii(chars[::2])
    return False


def extract_features(f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    extract features from the given basic block.

    args:
      f (viv_utils.Function): the function from which to extract features
      bb (viv_utils.BasicBlock): the basic block to process.

    yields:
      Tuple[Feature, int]: the features and their location found in this basic block.
    """
    yield BasicBlock(), AbsoluteVirtualAddress(bb.inner.va)
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(f, bb):
            yield feature, addr


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_stackstring,
)
