# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Tuple, Iterator

from capa.features.file import FunctionName
from capa.features.common import Feature
from capa.features.address import Address
from capa.features.extractors.binexport2 import FunctionContext
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(fh: FunctionHandle):
    # TODO(wb): 1755
    yield from ()


def extract_function_loop(fh: FunctionHandle):
    # TODO(wb): 1755
    yield from ()


def extract_recursive_call(fh: FunctionHandle):
    # TODO(wb): 1755
    yield from ()


def extract_function_name(fh: FunctionHandle):
    fhi: FunctionContext = fh.inner

    be2 = fhi.ctx.be2
    idx = fhi.ctx.idx
    analysis = fhi.ctx.analysis

    flow_graph_index = fhi.flow_graph_index

    flow_graph_address = idx.flow_graph_address_by_index[flow_graph_index]
    vertex_index = idx.vertex_index_by_address[flow_graph_address]
    vertex = be2.call_graph.vertex[vertex_index]

    if vertex.HasField("mangled_name"):
        yield FunctionName(vertex.mangled_name), fh.address
    elif flow_graph_address in analysis.thunks:
        thunk_vertex_index = analysis.thunks[flow_graph_address]
        thunk_vertex = be2.call_graph.vertex[thunk_vertex_index]
        if thunk_vertex.HasField("mangled_name"):
            yield FunctionName(thunk_vertex.mangled_name), fh.address


def extract_features(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop, extract_recursive_call, extract_function_name)
