# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import List, Tuple, Iterator

from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.basicblock import BasicBlock
from capa.features.extractors.binexport2 import FunctionContext, BasicBlockContext
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2


def extract_bb_tight_loop(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    bbi: BasicBlockContext = bbh.inner

    idx = fhi.ctx.idx

    basic_block_index: int = bbi.basic_block_index
    target_edges: List[BinExport2.FlowGraph.Edge] = idx.target_edges_by_basic_block_index[basic_block_index]
    if basic_block_index in (e.source_basic_block_index for e in target_edges):
        basic_block_address: int = idx.get_basic_block_address(basic_block_index)
        yield Characteristic("tight loop"), AbsoluteVirtualAddress(basic_block_address)


def extract_features(fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract basic block features"""
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(fh, bbh):
            yield feature, addr
    yield BasicBlock(), bbh.address


BASIC_BLOCK_HANDLERS = (extract_bb_tight_loop,)
