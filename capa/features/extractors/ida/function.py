# Copyright 2020 Google LLC
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

import idaapi
import idautils

import capa.features.extractors.ida.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(fh: FunctionHandle):
    """extract callers to a function"""
    for ea in idautils.CodeRefsTo(fh.inner.start_ea, True):
        yield Characteristic("calls to"), AbsoluteVirtualAddress(ea)


def extract_function_loop(fh: FunctionHandle):
    """extract loop indicators from a function"""
    f: idaapi.func_t = fh.inner
    edges = []

    # construct control flow graph
    for bb in idaapi.FlowChart(f):
        for succ in bb.succs():
            edges.append((bb.start_ea, succ.start_ea))

    if loops.has_loop(edges):
        yield Characteristic("loop"), fh.address


def extract_recursive_call(fh: FunctionHandle):
    """extract recursive function call"""
    if capa.features.extractors.ida.helpers.is_function_recursive(fh.inner):
        yield Characteristic("recursive call"), fh.address


def extract_features(fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop, extract_recursive_call)
