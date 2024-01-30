# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Dict, List, Tuple, Iterator

import capa.features.extractors.elf
import capa.features.extractors.common
import capa.features.extractors.binexport2.file
import capa.features.extractors.binexport2.insn
import capa.features.extractors.binexport2.function
import capa.features.extractors.binexport2.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.binexport2 import BinExport2Index, FunctionContext, BasicBlockContext, InstructionContext
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


class BinExport2Analysis:
    def __init__(self, be2: BinExport2, idx: BinExport2Index, buf: bytes):
        self.be2 = be2
        self.idx = idx
        self.buf = buf

        # from virtual address to call graph vertex representing the import
        self.thunks: Dict[int, int] = {}

    def _find_got_thunks(self):
        if self.be2.meta_information.architecture_name != "aarch64":
            logger.debug("skipping GOT thunk analysis on non-aarch64")
            return

        if not self.buf.startswith(capa.features.extractors.common.MATCH_ELF):
            logger.debug("skipping GOT thunk analysis on non-ELF")
            return

        for vertex_index, vertex in enumerate(self.be2.call_graph.vertex):
            if not vertex.HasField("address"):
                continue

            if not vertex.HasField("mangled_name"):
                continue

            if BinExport2.CallGraph.Vertex.Type.IMPORTED != vertex.type:
                continue

            if len(self.idx.callers_by_vertex_index[vertex_index]) != 1:
                # find imports with a single caller,
                # which should be the thunk
                continue

            maybe_thunk_vertex_index = self.idx.callers_by_vertex_index[vertex_index][0]
            maybe_thunk_vertex = self.be2.call_graph.vertex[maybe_thunk_vertex_index]
            maybe_thunk_address = maybe_thunk_vertex.address

            maybe_thunk_flow_graph_index = self.idx.flow_graph_index_by_address[maybe_thunk_address]
            maybe_thunk_flow_graph = self.be2.flow_graph[maybe_thunk_flow_graph_index]

            if len(maybe_thunk_flow_graph.basic_block_index) != 1:
                # should have a single basic block
                continue

            maybe_thunk_basic_block = self.be2.basic_block[maybe_thunk_flow_graph.entry_basic_block_index]
            if len(list(self.idx.instruction_indices(maybe_thunk_basic_block))) != 4:
                # thunk should look like these four instructions.
                # fstat:
                # 000008b0  adrp    x16, 0x11000
                # 000008b4  ldr     x17, [x16, #0xf88]  {fstat}
                # 000008b8  add     x16, x16, #0xf88  {fstat}
                # 000008bc  br      x17
                # which relies on the disassembler to recognize the target of the call/br
                # to go to the GOT/external symbol.
                continue

            thunk_address = maybe_thunk_address
            thunk_name = vertex.mangled_name
            logger.debug("found GOT thunk: 0x%x -> %s", thunk_address, thunk_name)

            self.thunks[thunk_address] = vertex_index


class BinExport2FeatureExtractor(StaticFeatureExtractor):
    def __init__(self, be2: BinExport2, buf: bytes):
        super().__init__(hashes=SampleHashes.from_bytes(buf))
        self.be2 = be2
        self.buf = buf
        self.idx = BinExport2Index(self.be2)
        self.analysis = BinExport2Analysis(self.be2, self.idx, self.buf)

        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(list(capa.features.extractors.common.extract_format(self.buf)))
        self.global_features.extend(list(capa.features.extractors.common.extract_os(self.buf)))
        self.global_features.extend(list(capa.features.extractors.common.extract_arch(self.buf)))

        # TODO: assert supported file formats, arches
        # and gradually relax restrictions as they're tested.

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
        for flow_graph_index, flow_graph in enumerate(self.be2.flow_graph):
            entry_basic_block_index = flow_graph.entry_basic_block_index
            flow_graph_address = self.idx.basic_block_address_by_index[entry_basic_block_index]
            yield FunctionHandle(
                AbsoluteVirtualAddress(flow_graph_address),
                inner=FunctionContext(self.be2, self.idx, self.analysis, flow_graph_index),
            )

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.binexport2.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        fhi: FunctionContext = fh.inner
        flow_graph_index = fhi.flow_graph_index
        flow_graph = self.be2.flow_graph[flow_graph_index]

        for basic_block_index in flow_graph.basic_block_index:
            basic_block_address = self.idx.basic_block_address_by_index[basic_block_index]
            yield BBHandle(
                address=AbsoluteVirtualAddress(basic_block_address),
                inner=BasicBlockContext(basic_block_index),
            )

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.binexport2.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        bbi: BasicBlockContext = bbh.inner
        basic_block: BinExport2.BasicBlock = self.be2.basic_block[bbi.basic_block_index]
        for instruction_index in self.idx.instruction_indices(basic_block):
            instruction_address = self.idx.instruction_address_by_index[instruction_index]
            yield InsnHandle(
                address=AbsoluteVirtualAddress(instruction_address),
                inner=InstructionContext(instruction_index),
            )

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.binexport2.insn.extract_features(fh, bbh, ih)
