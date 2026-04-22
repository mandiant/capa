# Copyright 2022 Google LLC
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


from __future__ import annotations

import logging
from typing import Iterator

from dncil.cil.opcode import FlowControl

from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.extractors.base_extractor import FunctionHandle

logger = logging.getLogger(__name__)


def extract_function_calls_to(fh: FunctionHandle) -> Iterator[tuple[Characteristic, Address]]:
    """extract callers to a function"""
    for dest in fh.ctx["calls_to"]:
        yield Characteristic("calls to"), dest


def extract_function_calls_from(fh: FunctionHandle) -> Iterator[tuple[Characteristic, Address]]:
    """extract callers from a function"""
    for src in fh.ctx["calls_from"]:
        yield Characteristic("calls from"), src


def extract_recursive_call(fh: FunctionHandle) -> Iterator[tuple[Characteristic, Address]]:
    """extract recursive function call"""
    if fh.address in fh.ctx["calls_to"]:
        yield Characteristic("recursive call"), fh.address


def extract_function_loop(fh: FunctionHandle) -> Iterator[tuple[Characteristic, Address]]:
    """extract loop indicators from a function"""
    for insn in fh.inner.instructions:
        if insn.opcode.flow_control not in (
            FlowControl.Branch,
            FlowControl.Cond_Branch,
        ):
            continue

        if isinstance(insn.operand, list):
            targets = insn.operand
        elif isinstance(insn.operand, int):
            targets = [insn.operand]
        else:
            continue

        for target in targets:
            if target < insn.offset:
                yield Characteristic("loop"), fh.address
                return


def extract_features(fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (
    extract_function_calls_to,
    extract_function_calls_from,
    extract_recursive_call,
    extract_function_loop,
)
