# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import string
import struct
from typing import Tuple, Iterator

from binaryninja import Function, Variable
from binaryninja import BasicBlock as BinjaBasicBlock
from binaryninja import (
    BinaryView,
    VariableSourceType,
    MediumLevelILSetVar,
    MediumLevelILOperation,
    MediumLevelILInstruction,
)

from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle


def get_printable_len(il: MediumLevelILSetVar) -> int:
    """Return string length if all operand bytes are ascii or utf16-le printable"""
    width = il.dest.type.width
    value = il.src.value.value

    if width == 1:
        chars = struct.pack("<B", value & 0xFF)
    elif width == 2:
        chars = struct.pack("<H", value & 0xFFFF)
    elif width == 4:
        chars = struct.pack("<I", value & 0xFFFFFFFF)
    elif width == 8:
        chars = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    else:
        return 0

    def is_printable_ascii(chars_: bytes):
        return all(c < 127 and chr(c) in string.printable for c in chars_)

    def is_printable_utf16le(chars_: bytes):
        if all(c == 0x00 for c in chars_[1::2]):
            return is_printable_ascii(chars_[::2])

    if is_printable_ascii(chars):
        return width

    if is_printable_utf16le(chars):
        return width // 2

    return 0


def is_mov_imm_to_stack(il: MediumLevelILInstruction) -> bool:
    """verify instruction moves immediate onto stack"""
    if il.operation != MediumLevelILOperation.MLIL_SET_VAR:
        return False

    if il.src.operation != MediumLevelILOperation.MLIL_CONST:
        return False

    if not il.dest.source_type == VariableSourceType.StackVariableSourceType:
        return False

    return True


def bb_contains_stackstring(f: Function, bb: BinjaBasicBlock) -> bool:
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    mlil_bbs = [mlil_bb for mlil_bb in bb.function.mlil_basic_blocks if mlil_bb.source_block.start == bb.start]
    for mlil_bb in mlil_bbs:
        for il in mlil_bb:
            if is_mov_imm_to_stack(il):
                count += get_printable_len(il)
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def extract_bb_stackstring(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract stackstring indicators from basic block"""
    bb: BinjaBasicBlock = bbh.inner
    if bb_contains_stackstring(fh.inner, bbh.inner):
        yield Characteristic("stack string"), bbh.address


def extract_bb_tight_loop(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract tight loop indicators from a basic block"""
    bb: BinjaBasicBlock = bbh.inner
    for edge in bb.outgoing_edges:
        if edge.target.start == bb.start:
            yield Characteristic("tight loop"), bbh.address


def extract_features(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract basic block features"""
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(fh, bbh):
            yield feature, addr
    yield BasicBlock(), bbh.address


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)


def main():
    if len(sys.argv) < 2:
        return

    import pprint

    from binaryninja import BinaryViewType

    bv: BinaryView = BinaryViewType.get_view_of_file(sys.argv[1])
    if bv is None:
        return

    features = []
    for f in bv.functions:
        fh = FunctionHandle(address=AbsoluteVirtualAddress(f.start), inner=f)
        for bb in f.basic_blocks:
            bbh = BBHandle(address=AbsoluteVirtualAddress(bb.start), inner=bb)
            features.extend(list(extract_features(fh, bbh)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
