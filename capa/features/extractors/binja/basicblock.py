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

from binaryninja import Function, Settings
from binaryninja import BasicBlock as BinjaBasicBlock
from binaryninja import (
    BinaryView,
    SymbolType,
    RegisterValueType,
    VariableSourceType,
    MediumLevelILSetVar,
    MediumLevelILOperation,
    MediumLevelILBasicBlock,
    MediumLevelILInstruction,
)

from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle

use_const_outline: bool = False
settings: Settings = Settings()
if settings.contains("analysis.outlining.builtins") and settings.get_bool("analysis.outlining.builtins"):
    use_const_outline = True


def get_printable_len_ascii(s: bytes) -> int:
    """Return string length if all operand bytes are ascii or utf16-le printable"""
    count = 0
    for c in s:
        if c == 0:
            return count
        if c < 127 and chr(c) in string.printable:
            count += 1
    return count


def get_printable_len_wide(s: bytes) -> int:
    """Return string length if all operand bytes are ascii or utf16-le printable"""
    if all(c == 0x00 for c in s[1::2]):
        return get_printable_len_ascii(s[::2])
    return 0


def get_stack_string_len(f: Function, il: MediumLevelILInstruction) -> int:
    bv: BinaryView = f.view

    if il.operation != MediumLevelILOperation.MLIL_CALL:
        return 0

    target = il.dest
    if target.operation not in [MediumLevelILOperation.MLIL_CONST, MediumLevelILOperation.MLIL_CONST_PTR]:
        return 0

    addr = target.value.value
    sym = bv.get_symbol_at(addr)
    if not sym or sym.type != SymbolType.LibraryFunctionSymbol:
        return 0

    if sym.name not in ["__builtin_strncpy", "__builtin_strcpy", "__builtin_wcscpy"]:
        return 0

    if len(il.params) < 2:
        return 0

    dest = il.params[0]
    if dest.operation in [MediumLevelILOperation.MLIL_ADDRESS_OF, MediumLevelILOperation.MLIL_VAR]:
        var = dest.src
    else:
        return 0

    if var.source_type != VariableSourceType.StackVariableSourceType:
        return 0

    src = il.params[1]
    if src.value.type != RegisterValueType.ConstantDataAggregateValue:
        return 0

    s = f.get_constant_data(RegisterValueType.ConstantDataAggregateValue, src.value.value)
    return max(get_printable_len_ascii(bytes(s)), get_printable_len_wide(bytes(s)))


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

    if il.dest.source_type != VariableSourceType.StackVariableSourceType:
        return False

    return True


def bb_contains_stackstring(f: Function, bb: MediumLevelILBasicBlock) -> bool:
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for il in bb:
        if use_const_outline:
            count += get_stack_string_len(f, il)
        else:
            if is_mov_imm_to_stack(il):
                count += get_printable_len(il)

    if count > MIN_STACKSTRING_LEN:
        return True
    return False


def extract_bb_stackstring(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract stackstring indicators from basic block"""
    bb: Tuple[BinjaBasicBlock, MediumLevelILBasicBlock] = bbh.inner
    if bb[1] is not None and bb_contains_stackstring(fh.inner, bb[1]):
        yield Characteristic("stack string"), bbh.address


def extract_bb_tight_loop(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract tight loop indicators from a basic block"""
    bb: Tuple[BinjaBasicBlock, MediumLevelILBasicBlock] = bbh.inner
    for edge in bb[0].outgoing_edges:
        if edge.target.start == bb[0].start:
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
