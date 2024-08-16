# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import List, Tuple, Iterator

from capa.features.file import FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.binexport2 import BinExport2Index, FunctionContext
from capa.features.extractors.base_extractor import FunctionHandle
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2


def extract_function_calls_to(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner

    be2: BinExport2 = fhi.ctx.be2
    idx: BinExport2Index = fhi.ctx.idx

    flow_graph_index: int = fhi.flow_graph_index
    flow_graph_address: int = idx.flow_graph_address_by_index[flow_graph_index]
    vertex_index: int = idx.vertex_index_by_address[flow_graph_address]

    for caller_index in idx.callers_by_vertex_index[vertex_index]:
        caller: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[caller_index]
        caller_address: int = caller.address
        yield Characteristic("calls to"), AbsoluteVirtualAddress(caller_address)


def extract_function_loop(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner

    be2: BinExport2 = fhi.ctx.be2

    flow_graph_index: int = fhi.flow_graph_index
    flow_graph: BinExport2.FlowGraph = be2.flow_graph[flow_graph_index]

    edges: List[Tuple[int, int]] = []
    for edge in flow_graph.edge:
        edges.append((edge.source_basic_block_index, edge.target_basic_block_index))

    if loops.has_loop(edges):
        yield Characteristic("loop"), fh.address


def extract_function_name(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner

    be2: BinExport2 = fhi.ctx.be2
    idx: BinExport2Index = fhi.ctx.idx
    flow_graph_index: int = fhi.flow_graph_index

    flow_graph_address: int = idx.flow_graph_address_by_index[flow_graph_index]
    vertex_index: int = idx.vertex_index_by_address[flow_graph_address]
    vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[vertex_index]

    if vertex.HasField("mangled_name"):
        yield FunctionName(vertex.mangled_name), fh.address


def extract_features(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop, extract_function_name)
