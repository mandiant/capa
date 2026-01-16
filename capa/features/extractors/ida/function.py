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
from ida_domain import Database

import capa.features.extractors.ida.helpers
from capa.features.file import FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(db: Database, fh: FunctionHandle):
    """extract callers to a function"""
    for ea in db.xrefs.code_refs_to_ea(fh.inner.start_ea):
        yield Characteristic("calls to"), AbsoluteVirtualAddress(ea)


def extract_function_loop(db: Database, fh: FunctionHandle):
    """extract loop indicators from a function"""
    f: idaapi.func_t = fh.inner
    edges = []

    # construct control flow graph
    flowchart = db.functions.get_flowchart(f)
    for bb in flowchart:
        for succ in bb.succs():
            edges.append((bb.start_ea, succ.start_ea))

    if loops.has_loop(edges):
        yield Characteristic("loop"), fh.address


def extract_recursive_call(db: Database, fh: FunctionHandle):
    """extract recursive function call"""
    if capa.features.extractors.ida.helpers.is_function_recursive(db, fh.inner):
        yield Characteristic("recursive call"), fh.address


def extract_function_name(db: Database, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    ea = fh.inner.start_ea
    name = db.names.get_at(ea)
    if not name or name.startswith("sub_"):
        # skip default names, like "sub_401000"
        return

    yield FunctionName(name), fh.address
    if name.startswith("_"):
        # some linkers may prefix linked routines with a `_` to avoid name collisions.
        # extract features for both the mangled and un-mangled representations.
        # e.g. `_fwrite` -> `fwrite`
        # see: https://stackoverflow.com/a/2628384/87207
        yield FunctionName(name[1:]), fh.address


def extract_function_alternative_names(db: Database, fh: FunctionHandle):
    """Get all alternative names for an address."""
    for aname in capa.features.extractors.ida.helpers.get_function_alternative_names(db, fh.inner.start_ea):
        yield FunctionName(aname), fh.address


def extract_features(db: Database, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(db, fh):
            yield feature, addr


FUNCTION_HANDLERS = (
    extract_function_calls_to,
    extract_function_loop,
    extract_recursive_call,
    extract_function_name,
    extract_function_alternative_names,
)
