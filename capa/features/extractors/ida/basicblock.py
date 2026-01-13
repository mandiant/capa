# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import string
import struct
from typing import Iterator

import idaapi
from ida_domain import Database

import capa.features.extractors.ida.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.basicblock import BasicBlock
from capa.features.extractors.ida import helpers
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle


def get_printable_len(op: idaapi.op_t) -> int:
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


def is_mov_imm_to_stack(db: Database, insn: idaapi.insn_t) -> bool:
    """verify instruction moves immediate onto stack"""
    if insn.Op2.type != idaapi.o_imm:
        return False

    if not helpers.is_op_stack_var(insn.ea, 0):
        return False

    mnem = db.instructions.get_mnemonic(insn)
    if not mnem.startswith("mov"):
        return False

    return True


def bb_contains_stackstring(db: Database, f: idaapi.func_t, bb: idaapi.BasicBlock) -> bool:
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for insn in capa.features.extractors.ida.helpers.get_instructions_in_range(db, bb.start_ea, bb.end_ea):
        if is_mov_imm_to_stack(db, insn):
            count += get_printable_len(insn.Op2)
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def extract_bb_stackstring(db: Database, fh: FunctionHandle, bbh: BBHandle) -> Iterator[tuple[Feature, Address]]:
    """extract stackstring indicators from basic block"""
    if bb_contains_stackstring(db, fh.inner, bbh.inner):
        yield Characteristic("stack string"), bbh.address


def extract_bb_tight_loop(db: Database, fh: FunctionHandle, bbh: BBHandle) -> Iterator[tuple[Feature, Address]]:
    """extract tight loop indicators from a basic block"""
    if capa.features.extractors.ida.helpers.is_basic_block_tight_loop(db, bbh.inner):
        yield Characteristic("tight loop"), bbh.address


def extract_features(db: Database, fh: FunctionHandle, bbh: BBHandle) -> Iterator[tuple[Feature, Address]]:
    """extract basic block features"""
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(db, fh, bbh):
            yield feature, addr
    yield BasicBlock(), bbh.address


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)
