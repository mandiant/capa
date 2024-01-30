# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
Proto files generated via protobuf v24.4:

    protoc --python_out=. --mypy_out=. binexport2.proto
"""
import os
import logging
from typing import Any, Dict, List, Iterator
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def get_binexport2(sample: Path) -> BinExport2:
    be2 = BinExport2()
    be2.ParseFromString(sample.read_bytes())
    return be2


def get_sample_from_binexport2(be2: BinExport2) -> Path:
    # also search in same directory as input
    # for files with the given sha256,
    # starting with files with a similar prefix as given.
    # TODO(wb): 1755

    # $CAPA_SAMPLE_DIR/<sha256>
    base = Path(os.environ.get("CAPA_SAMPLES_DIR", "."))

    sha256 = be2.meta_information.executable_id.lower()

    logger.debug("searching for sample in: %s", base)
    path = base / sha256
    if path.exists():
        return path
    else:
        raise ValueError("cannot find sample")


class BinExport2Index:
    def __init__(self, be2: BinExport2):
        self.be2 = be2

        self.callers_by_vertex_index: Dict[int, List[int]] = defaultdict(list)
        self.callees_by_vertex_index: Dict[int, List[int]] = defaultdict(list)

        # note: flow graph != call graph (vertex)
        self.flow_graph_index_by_address: Dict[int, int] = {}
        self.basic_block_index_by_address: Dict[int, int] = {}
        self.basic_block_address_by_index: Dict[int, int] = {}
        self.instruction_index_by_address: Dict[int, int] = {}
        self.instruction_address_by_index: Dict[int, int] = {}

        # edges that come from the given basic block
        self.source_edges_by_basic_block_index: Dict[int, List[BinExport2.FlowGraph.Edge]] = defaultdict(list)
        # edges that end up at the given basic block
        self.target_edges_by_basic_block_index: Dict[int, List[BinExport2.FlowGraph.Edge]] = defaultdict(list)

        self.vertex_index_by_address: Dict[int, int] = {}

        self.data_reference_index_by_source_instruction_index: Dict[int, List[int]] = defaultdict(list)
        self.data_reference_index_by_target_address: Dict[int, List[int]] = defaultdict(list)

        self._index_vertex_edges()
        self._index_instruction_addresses()
        self._index_flow_graph_nodes()
        self._index_flow_graph_edges()
        self._index_call_graph_vertices()
        self._index_data_references()

    def _index_vertex_edges(self):
        for edge in self.be2.call_graph.edge:
            if not edge.source_vertex_index:
                continue
            if not edge.target_vertex_index:
                continue

            self.callers_by_vertex_index[edge.target_vertex_index].append(edge.source_vertex_index)
            self.callees_by_vertex_index[edge.source_vertex_index].append(edge.target_vertex_index)

    def _index_instruction_addresses(self):
        instruction_address = 0
        for instruction_index, instruction in enumerate(self.be2.instruction):
            if instruction.HasField("address"):
                instruction_address = instruction.address

            self.instruction_index_by_address[instruction_address] = instruction_index
            self.instruction_address_by_index[instruction_index] = instruction_address

            assert instruction.HasField("raw_bytes")
            instruction_address += len(instruction.raw_bytes)

    def _index_flow_graph_nodes(self):
        for flow_graph_index, flow_graph in enumerate(self.be2.flow_graph):
            for basic_block_index in flow_graph.basic_block_index:
                basic_block = self.be2.basic_block[basic_block_index]
                for instruction_index in self.instruction_indices(basic_block):
                    basic_block_address = self.instruction_address_by_index[instruction_index]
                    self.basic_block_index_by_address[basic_block_address] = basic_block_index
                    self.basic_block_address_by_index[basic_block_index] = basic_block_address

            entry_basic_block = self.be2.basic_block[flow_graph.entry_basic_block_index]
            entry_instruction_index = next(self.instruction_indices(entry_basic_block))
            entry_instruction_address = self.instruction_address_by_index[entry_instruction_index]
            function_address = entry_instruction_address
            self.flow_graph_index_by_address[function_address] = flow_graph_index

    def _index_flow_graph_edges(self):
        for flow_graph in self.be2.flow_graph:
            for edge in flow_graph.edge:
                if not edge.HasField("source_basic_block_index") or not edge.HasField("target_basic_block_index"):
                    continue

                self.source_edges_by_basic_block_index[edge.source_basic_block_index].append(edge)
                self.target_edges_by_basic_block_index[edge.target_basic_block_index].append(edge)

    def _index_call_graph_vertices(self):
        for vertex_index, vertex in enumerate(self.be2.call_graph.vertex):
            if not vertex.HasField("address"):
                continue

            vertex_address = vertex.address
            self.vertex_index_by_address[vertex_address] = vertex_index

    def _index_data_references(self):
        for data_reference_index, data_reference in enumerate(self.be2.data_reference):
            self.data_reference_index_by_source_instruction_index[data_reference.instruction_index].append(
                data_reference_index
            )
            self.data_reference_index_by_target_address[data_reference.address].append(data_reference_index)

    @staticmethod
    def instruction_indices(basic_block: BinExport2.BasicBlock) -> Iterator[int]:
        for index_range in basic_block.instruction_index:
            if not index_range.HasField("end_index"):
                yield index_range.begin_index
                continue
            else:
                yield from range(index_range.begin_index, index_range.end_index)

    def get_function_name_by_vertex(self, vertex_index: int) -> str:
        vertex = self.be2.call_graph.vertex[vertex_index]
        name = f"sub_{vertex.address:x}"
        if vertex.HasField("mangled_name"):
            name = vertex.mangled_name

        if vertex.HasField("demangled_name"):
            name = vertex.demangled_name

        return name

    def get_function_name_by_address(self, address: int) -> str:
        if address not in self.vertex_index_by_address:
            return ""

        vertex_index = self.vertex_index_by_address[address]
        return self.get_function_name_by_vertex(vertex_index)


@dataclass
class FunctionContext:
    be2: BinExport2
    idx: BinExport2Index
    # TODO: typing
    analysis: Any
    flow_graph_index: int


@dataclass
class BasicBlockContext:
    basic_block_index: int


@dataclass
class InstructionContext:
    instruction_index: int
