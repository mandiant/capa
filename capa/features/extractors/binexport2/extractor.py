# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Dict, List, Tuple, Iterator

import capa.features.extractors.elf
import capa.features.extractors.common
import capa.features.extractors.binexport2.file
import capa.features.extractors.binexport2.insn
import capa.features.extractors.binexport2.function
import capa.features.extractors.binexport2.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.binexport2 import FunctionContext, BasicBlockContext, InstructionContext
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2


class BinExport2FeatureExtractor(StaticFeatureExtractor):
    def __init__(self, be2: BinExport2, buf: bytes):
        super().__init__(hashes=SampleHashes.from_bytes(buf))
        self.be2 = be2
        self.buf = buf

        self.address_by_instruction_index: Dict[int, int] = {}
        self.flow_graph_index_by_function_index: Dict[int, int] = {}
        self.function_index_by_address: Dict[int, int] = {}

        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(list(capa.features.extractors.common.extract_format(self.buf)))
        self.global_features.extend(list(capa.features.extractors.common.extract_os(self.buf)))
        self.global_features.extend(list(capa.features.extractors.common.extract_arch(self.buf)))

        self._index_instruction_addresses()
        self._index_basic_blocks_by_function()

        print("base address", hex(self.get_base_address()))
        ba = self.get_base_address()
        for v in self.be2.call_graph.vertex:
            if v.mangled_name:
                print(hex(v.address - ba), v.mangled_name)

    def get_base_address(self):
        # TODO: assume the lowest address is the base address.
        # this works as long as BinExport doesn't record other
        # libraries mapped into memory.
        base_address = min(map(lambda s: s.address, self.be2.section))
        return AbsoluteVirtualAddress(base_address)

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.binexport2.file.extract_features(self.be2, self.buf)

    def get_functions(self) -> Iterator[FunctionHandle]:
        for function_index in self.flow_graph_index_by_function_index.keys():
            vertex = self.be2.call_graph.vertex[function_index]
            yield FunctionHandle(
                AbsoluteVirtualAddress(vertex.address), inner=FunctionContext(self.be2, function_index)
            )

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.binexport2.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        fhi: FunctionContext = fh.inner
        flow_graph_index = self.flow_graph_index_by_function_index[fhi.function_index]
        flow_graph = self.be2.flow_graph[flow_graph_index]

        for basic_block_index in flow_graph.basic_block_index:
            bb = self.be2.basic_block[basic_block_index]
            yield BBHandle(
                address=AbsoluteVirtualAddress(self.address_by_instruction_index[bb.instruction_index[0].begin_index]),
                inner=BasicBlockContext(self.be2, basic_block_index),
            )

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        # TODO(wb): 1755
        yield from ()

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        bbi: BasicBlockContext = bbh.inner
        bb: BinExport2.BasicBlock = self.be2.basic_block[bbi.basic_block_index]
        for instruction_index in range(bb.instruction_index[0].begin_index, bb.instruction_index[0].end_index):
            yield InsnHandle(
                address=AbsoluteVirtualAddress(self.address_by_instruction_index[instruction_index]),
                inner=InstructionContext(self.be2, instruction_index),
            )

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.binexport2.insn.extract_features(fh, bbh, ih)

    def _index_instruction_addresses(self):
        address = 0
        next_address = 0
        for instruction_index, instruction in enumerate(self.be2.instruction):
            if instruction.HasField("address"):
                address = instruction.address
                next_address = address + len(instruction.raw_bytes)
            else:
                address = next_address
                next_address += len(instruction.raw_bytes)

            self.address_by_instruction_index[instruction_index] = address

    def _index_basic_blocks_by_function(self):
        function_index_from_address = {}

        for index, vertex in enumerate(self.be2.call_graph.vertex):
            function_index_from_address[vertex.address] = index

        for flow_graph_index, flow_graph in enumerate(self.be2.flow_graph):
            basic_block_entry_point = self.be2.basic_block[flow_graph.entry_basic_block_index]
            basic_block_address = self.address_by_instruction_index[
                basic_block_entry_point.instruction_index[0].begin_index
            ]

            if basic_block_address not in function_index_from_address:
                continue

            function_index = function_index_from_address[basic_block_address]

            self.flow_graph_index_by_function_index[function_index] = flow_graph_index
