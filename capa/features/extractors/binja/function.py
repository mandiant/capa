# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
from typing import Tuple, Iterator

from binaryninja import Function, BinaryView, LowLevelILOperation

from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(fh: FunctionHandle):
    """extract callers to a function"""
    func: Function = fh.inner
    bv: BinaryView = func.view

    for caller in func.caller_sites:
        # Everything that is a code reference to the current function is considered a caller, which actually includes
        # many other references that are NOT a caller. For example, an instruction `push function_start` will also be
        # considered a caller to the function
        if caller.llil.operation in [
            LowLevelILOperation.LLIL_CALL,
            LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
            LowLevelILOperation.LLIL_JUMP,
            LowLevelILOperation.LLIL_TAILCALL,
        ]:
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


def extract_features(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop, extract_recursive_call)


def main():
    """ """
    if len(sys.argv) < 2:
        return

    from binaryninja import BinaryViewType

    from capa.features.extractors.binja.extractor import BinjaFeatureExtractor

    bv: BinaryView = BinaryViewType.get_view_of_file(sys.argv[1])
    if bv is None:
        return

    features = []
    extractor = BinjaFeatureExtractor(bv)
    for fh in extractor.get_functions():
        features.extend(list(extract_features(fh)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
