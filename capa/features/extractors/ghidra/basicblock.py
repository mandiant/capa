# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
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

import capa.features.extractors.ghidra.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle


def get_printable_len(op: ghidra.program.model.scalar.Scalar) -> int:
    """Return string length if all operand bytes are ascii or utf16-le printable"""
    op_bit_len = op.bitLength()
    op_byte_len = op_bit_len // 8
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
        return op_byte_len

    if is_printable_utf16le(chars):
        return op_byte_len

    return 0


def is_mov_imm_to_stack(insn: ghidra.program.database.code.InstructionDB) -> bool:
    """verify instruction moves immediate onto stack"""

    # Ghidra will Bitwise OR the OperandTypes to assign multiple
    # i.e., the first operand is a stackvar (dynamically allocated),
    # and the second is a scalar value (single int/char/float/etc.)
    mov_its_ops = [(OperandType.ADDRESS | OperandType.DYNAMIC), OperandType.SCALAR]
    found = False

    # MOV dword ptr [EBP + local_*], 0x65
    if insn.getMnemonicString().startswith("MOV"):
        found = all(insn.getOperandType(i) == mov_its_ops[i] for i in range(2))

    return found


def bb_contains_stackstring(bb: ghidra.program.model.block.CodeBlock) -> bool:
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for insn in currentProgram().getListing().getInstructions(bb, True):  # type: ignore [name-defined] # noqa: F821
        if is_mov_imm_to_stack(insn):
            count += get_printable_len(insn.getScalar(1))
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def _bb_has_tight_loop(bb: ghidra.program.model.block.CodeBlock):
    """
    parse tight loops, true if last instruction in basic block branches to bb start
    """
    # Reverse Ordered, first InstructionDB
    last_insn = currentProgram().getListing().getInstructions(bb, False).next()  # type: ignore [name-defined] # noqa: F821

    if last_insn.getFlowType().isJump():
        return last_insn.getAddress(0) == bb.getMinAddress()

    return False


def extract_bb_stackstring(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract stackstring indicators from basic block"""
    bb: ghidra.program.model.block.CodeBlock = bbh.inner

    if bb_contains_stackstring(bb):
        yield Characteristic("stack string"), bbh.address


def extract_bb_tight_loop(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """check basic block for tight loop indicators"""
    bb: ghidra.program.model.block.CodeBlock = bbh.inner

    if _bb_has_tight_loop(bb):
        yield Characteristic("tight loop"), bbh.address


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)


def extract_features(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    extract features from the given basic block.

    args:
        bb: the basic block to process.

    yields:
      Tuple[Feature, int]: the features and their location found in this basic block.
    """
    yield BasicBlock(), bbh.address
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(fh, bbh):
            yield feature, addr


def main():
    features = []
    from capa.features.extractors.ghidra.extractor import GhidraFeatureExtractor

    for fh in GhidraFeatureExtractor().get_functions():
        for bbh in capa.features.extractors.ghidra.helpers.get_function_blocks(fh):
            features.extend(list(extract_features(fh, bbh)))

    import pprint

    pprint.pprint(features)  # noqa: T203


if __name__ == "__main__":
    main()
