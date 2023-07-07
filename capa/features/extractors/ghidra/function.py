# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Tuple, Iterator

import ghidra 
from ghidra.program.model.block import BasicBlockModel

import capa.features.extractors.ghidra.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.base_extractor import FunctionHandle

currentProgram: ghidra.program.database.ProgramDB

def extract_function_calls_to(fh: ghidra.program.model.symbol.Symbol):
    """extract callers to a function"""
    for ref in fh.getReferences():
        if ref.getReferenceType().isCall():
            yield Characteristic("calls to"), AbsoluteVirtualAddress(ref.getFromAddress().getOffset())


def extract_function_loop(fh: ghidra.program.model.symbol.Symbol):

    edges = []
    model = BasicBlockModel(currentProgram) # does not allow overlap, so we have to iterate ourself
    monitor = getMonitor()
    block = model.getCodeBlockAt(fh.getAddress(), monitor)
    dests = block.getDestinations(monitor)

    # For loop throws an error, must treat as an iterator
    while dests.hasNext():
        dest = dests.next()
        for addr in block.getStartAddresses():
            edges.append((addr.getOffset(), dest.getDestinationAddress().getOffset()))

        dblock = dest.getDestinationBlock()
        dblock_dests = dblock.getDestinations(monitor)
        while dblock_dests.hasNext():
            ddblock = dblock_dests.next()
            for addr in dblock.getStartAddresses():
                edges.append((addr.getOffset(), ddblock.getDestinationAddress().getOffset()))

    import pprint
    pprint.pprint(edges)

    if loops.has_loop(edges):
        yield Characteristic("loop"), fh.getAddress().getOffset()


def extract_recursive_call(fh: ghidra.program.model.symbol.Symbol):
    yield Characteristic("recursive call"), fh.getAddress().getOffset()


def extract_features(fh: ghidra.program.model.symbol.Symbol) -> Iterator[Tuple[Feature, Address]]:
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

    pprint.pprint(features)


if __name__ == "__main__":
    main()
