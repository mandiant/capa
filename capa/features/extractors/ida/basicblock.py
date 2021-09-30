# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import string
import struct

import idaapi

import capa.features.extractors.ida.helpers
from capa.features.common import Characteristic
from capa.features.basicblock import BasicBlock
from capa.features.extractors.ida import helpers
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN


def get_printable_len(op):
    """Return string length if all operand bytes are ascii or utf16-le printable

    args:
        op (IDA op_t)
    """
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
        raise ValueError("Unhandled operand data type 0x%x." % op.dtype)

    def is_printable_ascii(chars):
        return all(c < 127 and chr(c) in string.printable for c in chars)

    def is_printable_utf16le(chars):
        if all(c == 0x00 for c in chars[1::2]):
            return is_printable_ascii(chars[::2])

    if is_printable_ascii(chars):
        return idaapi.get_dtype_size(op.dtype)

    if is_printable_utf16le(chars):
        return idaapi.get_dtype_size(op.dtype) // 2

    return 0


def is_mov_imm_to_stack(insn):
    """verify instruction moves immediate onto stack

    args:
        insn (IDA insn_t)
    """
    if insn.Op2.type != idaapi.o_imm:
        return False

    if not helpers.is_op_stack_var(insn.ea, 0):
        return False

    if not insn.get_canon_mnem().startswith("mov"):
        return False

    return True


def bb_contains_stackstring(f, bb):
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    count = 0
    for insn in capa.features.extractors.ida.helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
        if is_mov_imm_to_stack(insn):
            count += get_printable_len(insn.Op2)
        if count > MIN_STACKSTRING_LEN:
            return True
    return False


def extract_bb_stackstring(f, bb):
    """extract stackstring indicators from basic block

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    if bb_contains_stackstring(f, bb):
        yield Characteristic("stack string"), bb.start_ea


def extract_bb_tight_loop(f, bb):
    """extract tight loop indicators from a basic block

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    if capa.features.extractors.ida.helpers.is_basic_block_tight_loop(bb):
        yield Characteristic("tight loop"), bb.start_ea


def extract_features(f, bb):
    """extract basic block features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
    """
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for (feature, ea) in bb_handler(f, bb):
            yield feature, ea
    yield BasicBlock(), bb.start_ea


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    extract_bb_stackstring,
)


def main():
    features = []
    for f in helpers.get_functions(skip_thunks=True, skip_libs=True):
        for bb in idaapi.FlowChart(f, flags=idaapi.FC_PREDS):
            features.extend(list(extract_features(f, bb)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
