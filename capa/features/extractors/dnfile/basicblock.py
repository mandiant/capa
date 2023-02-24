# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Tuple, Iterator

from dncil.cil.instruction import Instruction

from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.basicblock import BasicBlock
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle


def extract_bb_stackstring(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract stackstring indicators from basic block"""
    raise NotImplementedError


def extract_bb_tight_loop(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract tight loop indicators from a basic block"""
    first: Instruction = bbh.inner.instructions[0]
    last: Instruction = bbh.inner.instructions[-1]

    if any((last.is_br(), last.is_cond_br(), last.is_leave())):
        if last.operand == first.offset:
            yield Characteristic("tight loop"), bbh.address


def extract_features(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract basic block features"""
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(fh, bbh):
            yield feature, addr
    yield BasicBlock(), bbh.address


BASIC_BLOCK_HANDLERS = (
    extract_bb_tight_loop,
    # extract_bb_stackstring,
)
