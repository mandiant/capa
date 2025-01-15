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

from typing import Iterator

import ghidra
from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator

import capa.features.extractors.ghidra.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(fh: FunctionHandle):
    """extract callers to a function"""
    f: ghidra.program.database.function.FunctionDB = fh.inner
    for ref in f.getSymbol().getReferences():
        if ref.getReferenceType().isCall():
            yield Characteristic("calls to"), AbsoluteVirtualAddress(ref.getFromAddress().getOffset())


def extract_function_loop(fh: FunctionHandle):
    f: ghidra.program.database.function.FunctionDB = fh.inner

    edges = []
    for block in SimpleBlockIterator(BasicBlockModel(currentProgram()), f.getBody(), monitor()):  # type: ignore [name-defined] # noqa: F821
        dests = block.getDestinations(monitor())  # type: ignore [name-defined] # noqa: F821
        s_addrs = block.getStartAddresses()

        while dests.hasNext():  # For loop throws Python TypeError
            for addr in s_addrs:
                edges.append((addr.getOffset(), dests.next().getDestinationAddress().getOffset()))

    if loops.has_loop(edges):
        yield Characteristic("loop"), AbsoluteVirtualAddress(f.getEntryPoint().getOffset())


def extract_recursive_call(fh: FunctionHandle):
    f: ghidra.program.database.function.FunctionDB = fh.inner

    for func in f.getCalledFunctions(monitor()):  # type: ignore [name-defined] # noqa: F821
        if func.getEntryPoint().getOffset() == f.getEntryPoint().getOffset():
            yield Characteristic("recursive call"), AbsoluteVirtualAddress(f.getEntryPoint().getOffset())


def extract_features(fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop, extract_recursive_call)


def main():
    """ """
    features = []
    for fhandle in capa.features.extractors.ghidra.helpers.get_function_symbols():
        features.extend(list(extract_features(fhandle)))

    import pprint

    pprint.pprint(features)  # noqa: T203


if __name__ == "__main__":
    main()
