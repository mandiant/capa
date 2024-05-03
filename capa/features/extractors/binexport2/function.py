# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Tuple, Iterator

from capa.features.file import FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.binexport2 import FunctionContext
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(fh: FunctionHandle):
    fhi: FunctionContext = fh.inner

    be2 = fhi.ctx.be2
    idx = fhi.ctx.idx

    flow_graph_index = fhi.flow_graph_index
    flow_graph_address = idx.flow_graph_address_by_index[flow_graph_index]
    vertex_index = idx.vertex_index_by_address[flow_graph_address]

    for caller_index in idx.callers_by_vertex_index[vertex_index]:
        caller = be2.call_graph.vertex[caller_index]
        caller_address = caller.address
        yield Characteristic("calls to"), AbsoluteVirtualAddress(caller_address)


def extract_function_loop(fh: FunctionHandle):
    fhi: FunctionContext = fh.inner

    be2 = fhi.ctx.be2

    flow_graph_index = fhi.flow_graph_index
    flow_graph = be2.flow_graph[flow_graph_index]

    for edge in flow_graph.edge:
        if edge.is_back_edge:
            yield Characteristic("loop"), fh.address
            break


def extract_function_name(fh: FunctionHandle):
    fhi: FunctionContext = fh.inner

    be2 = fhi.ctx.be2
    idx = fhi.ctx.idx
    flow_graph_index = fhi.flow_graph_index

    flow_graph_address = idx.flow_graph_address_by_index[flow_graph_index]
    vertex_index = idx.vertex_index_by_address[flow_graph_address]
    vertex = be2.call_graph.vertex[vertex_index]

    if vertex.HasField("mangled_name"):
        yield FunctionName(vertex.mangled_name), fh.address


def extract_features(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop, extract_function_name)
