# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Iterator

from binaryninja import Function, BinaryView, SymbolType

from capa.features.file import FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(fh: FunctionHandle):
    """extract callers to a function"""
    func: Function = fh.inner

    caller: int
    for caller in fh.ctx["call_graph"]["calls_to"].get(func.start, []):
        if caller == func.start:
            continue

        yield Characteristic("calls to"), AbsoluteVirtualAddress(caller)


def extract_function_calls_from(fh: FunctionHandle):
    """extract callers from a function"""
    func: Function = fh.inner

    callee: int
    for callee in fh.ctx["call_graph"]["calls_from"].get(func.start, []):
        if callee == func.start:
            continue

        yield Characteristic("calls from"), AbsoluteVirtualAddress(callee)


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

    caller: int
    for caller in fh.ctx["call_graph"]["calls_to"].get(func.start, []):
        if caller == func.start:
            yield Characteristic("recursive call"), fh.address
            return


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


def extract_features(fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (
    extract_function_calls_to,
    extract_function_calls_from,
    extract_function_loop,
    extract_recursive_call,
    extract_function_name,
)
