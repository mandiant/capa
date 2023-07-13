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
from ghidra.program.model.lang import OperandType
from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator

import capa.features.extractors.ghidra.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN

currentProgram: ghidra.program.database.ProgramDB
monitor: ghidra.util.task.TaskMonitor
listing = currentProgram.getListing()


def get_printable_len(op: ghidra.program.model.scalar.Scalar) -> int:
    """Return string length if all operand bytes are ascii or utf16-le printable"""
    op_bit_len = op.bitLength()
    op_val = op.getValue()

    if op_bit_len == 8:
        chars = struct.pack("<B", op_val & 0xFF)
    elif op_bit_len == 16:
        chars = struct.pack("<H", op_val & 0xFFFF)
    elif op_bit_len == 32:
        chars = struct.pack("<I", op_val & 0xFFFFFFFF)
    elif op_bit_len == 64:
        chars = struct.pack("<Q", op_val & 0xFFFFFFFFFFFFFFFF)
    else:
        raise ValueError(f"Unhandled operand data type 0x{op_bit_len:x}.")

    def is_printable_ascii(chars_: bytes):
        return all(c < 127 and chr(c) in string.printable for c in chars_)

    def is_printable_utf16le(chars_: bytes):
        if all(c == 0x00 for c in chars_[1::2]):
            return is_printable_ascii(chars_[::2])

    if is_printable_ascii(chars):
        return int(op_bit_len / 8)

    if is_printable_utf16le(chars):
        return int(op_bit_len / 8)

    return 0


def is_mov_imm_to_stack(insn: ghidra.program.database.code.InstructionDB) -> bool:
    """verify instruction moves immediate onto stack"""

    # Ghidra will Bitwise OR the OperandTypes to assign multiple
    # i.e., the first operand is a stackvar (dynamically allocated),
    # and the second is a scalar value (single int/char/float/etc.)
    mov_its_ops = [(OperandType.ADDRESS | OperandType.DYNAMIC), OperandType.SCALAR]

    # MOV dword ptr [EBP + local_*], 0x65
    if insn.getMnemonicString() == "MOV":
        for i in range(2):
            if insn.getOperandType(i) != mov_its_ops[i]:
                return False
        return True

    return False


def bb_contains_stackstring(bb: ghidra.program.model.block.CodeBlock) -> bool:
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for insn in listing.getInstructions(bb, True):
        if is_mov_imm_to_stack(insn):
            count += get_printable_len(insn.getOpObjects(1)[0])
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def _bb_has_tight_loop(bb: ghidra.program.model.block.CodeBlock):
    """
    parse tight loops, true if last instruction in basic block branches to bb start
    """
    last_insn = listing.getInstructionAt(bb.getMaxAddress().add(-0x1))  # all last insns are TERMINATOR

    if last_insn:
        if last_insn.getFlowType().isJump():
            if last_insn.getOpObjects(0)[0].getOffset() == bb.getMinAddress().getOffset():
                return True

    return False


def extract_bb_stackstring(bb: ghidra.program.model.block.CodeBlock) -> Iterator[Tuple[Feature, Address]]:
    """extract stackstring indicators from basic block"""
    if bb_contains_stackstring(bb):
        yield Characteristic("stack string"), AbsoluteVirtualAddress(bb.getMinAddress().getOffset())


def extract_bb_tight_loop(bb: ghidra.program.model.block.CodeBlock) -> Iterator[Tuple[Feature, Address]]:
    """check basic block for tight loop indicators"""
    if _bb_has_tight_loop(bb):
        yield Characteristic("tight loop"), AbsoluteVirtualAddress(bb.getMinAddress().getOffset())


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)


def extract_features(bb: ghidra.program.model.block.CodeBlock) -> Iterator[Tuple[Feature, Address]]:
    """
    extract features from the given basic block.

    args:
        bb: the basic block to process.

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
