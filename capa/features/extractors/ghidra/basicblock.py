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

import ghidra
from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator

import capa.features.extractors.ghidra.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle

currentProgram: ghidra.program.database.ProgramDB
monitor: ghidra.util.task.TaskMonitor
listing = currentProgram.getListing()


def get_printable_len(op) -> int:
    """Return string length if all operand bytes are ascii or utf16-le printable"""
    op_val = capa.features.extractors.ida.helpers.mask_op_val(op)

    if op.dtype == idaapi.dt_byte:
        chars = struct.pack("<B", op_val)
    elif op.dtype == idaapi.dt_word:
        chars = struct.pack("<H", op_val)
    elif op.dtype == idaapi.dt_dword:
        chars = struct.pack("<I", op_val)
    elif op.dtype == idaapi.dt_qword:
        chars = struct.pack("<Q", op_val)
    else:
        raise ValueError(f"Unhandled operand data type 0x{op.dtype:x}.")

    def is_printable_ascii(chars_: bytes):
        return all(c < 127 and chr(c) in string.printable for c in chars_)

    def is_printable_utf16le(chars_: bytes):
        if all(c == 0x00 for c in chars_[1::2]):
            return is_printable_ascii(chars_[::2])

    if is_printable_ascii(chars):
        return idaapi.get_dtype_size(op.dtype)

    if is_printable_utf16le(chars):
        return idaapi.get_dtype_size(op.dtype) // 2

    return 0


def is_mov_imm_to_stack(insn) -> bool:
    """verify instruction moves immediate onto stack"""
    if insn.getMnemonicString() != "MOV":
        return False

    if not helpers.is_op_stack_var(insn.ea, 0):
        return False

    if not insn.get_canon_mnem().startswith("mov"):
        return False

    return True


def bb_contains_stackstring(bb) -> bool:
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for insn in listing.getInstructions(bb, True):
        if is_mov_imm_to_stack(insn):
            count += get_printable_len(insn.Op2)
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def _bb_has_tight_loop(bb):
    """
    parse tight loops, true if last instruction in basic block branches to bb start
    """
    last_insn = listing.getInstructionAt(block.getMaxAddress().add(-0x1)) # all last insns are TERMINATOR

    if last_insn:
        if last_insn.getFlowType().isJump():
            if last_insn.getOpObjects(0)[0].getOffset() == bb.getMinAddress().getOffset():
                return True

    return False


def extract_bb_tight_loop(bb) -> Iterator[Tuple[Feature, Address]]:
    """check basic block for tight loop indicators"""
    if _bb_has_tight_loop(bb):
        yield Characteristic("tight loop"), AbsoluteVirtualAddress(bb.getMinAddress().getOffset()) 


def extract_features(bb) -> Iterator[Tuple[Feature, Address]]:
    """
    extract features from the given basic block.

    args:
      bb (viv_utils.BasicBlock): the basic block to process.

    yields:
      Tuple[Feature, int]: the features and their location found in this basic block.
    """
    yield BasicBlock(), AbsoluteVirtualAddress(bb.getMinAddress().getOffset())
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(bb):
            yield feature, addr


def main():
    features = []
    for fhandle in capa.features.extractors.ghidra.helpers.get_function_symbols():
        for bb in SimpleBlockIterator(BasicBlockModel(currentProgram), fhandle.getBody(), monitor):
            features.extend(list(extract_features(bb)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
