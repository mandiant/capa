# Copyright 2023 Google LLC
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
from typing import Iterator

from binaryninja import (
    Function,
    BinaryView,
    SymbolType,
    ILException,
    RegisterValueType,
    VariableSourceType,
    LowLevelILOperation,
    MediumLevelILOperation,
    MediumLevelILBasicBlock,
    MediumLevelILInstruction,
)

from capa.features.file import FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.binja.helpers import get_llil_instr_at_addr
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(fh: FunctionHandle):
    """extract callers to a function"""
    func: Function = fh.inner

    for caller in func.caller_sites:
        # Everything that is a code reference to the current function is considered a caller, which actually includes
        # many other references that are NOT a caller. For example, an instruction `push function_start` will also be
        # considered a caller to the function
        llil = get_llil_instr_at_addr(func.view, caller.address)
        if (llil is None) or llil.operation not in [
            LowLevelILOperation.LLIL_CALL,
            LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
            LowLevelILOperation.LLIL_JUMP,
            LowLevelILOperation.LLIL_TAILCALL,
        ]:
            continue

        if llil.dest.operation not in [
            LowLevelILOperation.LLIL_CONST,
            LowLevelILOperation.LLIL_CONST_PTR,
        ]:
            continue

        address = llil.dest.constant
        if address != func.start:
            continue

        yield Characteristic("calls to"), AbsoluteVirtualAddress(caller.address)


def extract_function_loop(fh: FunctionHandle):
    """extract loop indicators from a function"""
    func: Function = fh.inner

    edges = []

    # construct control flow graph
    for bb in func.basic_blocks:
        for edge in bb.outgoing_edges:
            edges.append((bb.start, edge.target.start))

    if loops.has_loop(edges):
        yield Characteristic("loop"), fh.address


def extract_recursive_call(fh: FunctionHandle):
    """extract recursive function call"""
    func: Function = fh.inner
    bv: BinaryView = func.view
    if bv is None:
        return

    for ref in bv.get_code_refs(func.start):
        if ref.function == func:
            yield Characteristic("recursive call"), fh.address


def extract_function_name(fh: FunctionHandle):
    """extract function names (e.g., symtab names)"""
    func: Function = fh.inner
    bv: BinaryView = func.view
    if bv is None:
        return

    for sym in bv.get_symbols(func.start):
        if sym.type not in [SymbolType.LibraryFunctionSymbol, SymbolType.FunctionSymbol]:
            continue

        name = sym.short_name
        yield FunctionName(name), sym.address
        if name.startswith("_"):
            # some linkers may prefix linked routines with a `_` to avoid name collisions.
            # extract features for both the mangled and un-mangled representations.
            # e.g. `_fwrite` -> `fwrite`
            # see: https://stackoverflow.com/a/2628384/87207
            yield FunctionName(name[1:]), sym.address


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
    if not sym or sym.type not in [SymbolType.LibraryFunctionSymbol, SymbolType.SymbolicFunctionSymbol]:
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


def bb_contains_stackstring(f: Function, bb: MediumLevelILBasicBlock) -> bool:
    """check basic block for stackstring indicators

    true if basic block contains enough moves of constant bytes to the stack
    """
    count = 0
    for il in bb:
        count += get_stack_string_len(f, il)
        if count > MIN_STACKSTRING_LEN:
            return True

    return False


def extract_stackstring(fh: FunctionHandle):
    """extract stackstring indicators"""
    func: Function = fh.inner
    bv: BinaryView = func.view
    if bv is None:
        return

    try:
        mlil = func.mlil
    except ILException:
        return

    for block in mlil.basic_blocks:
        if bb_contains_stackstring(func, block):
            yield Characteristic("stack string"), block.source_block.start


def extract_features(fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (
    extract_function_calls_to,
    extract_function_loop,
    extract_recursive_call,
    extract_function_name,
    extract_stackstring,
)
