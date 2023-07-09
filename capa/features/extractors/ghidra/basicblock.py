# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import string
import struct
from typing import Tuple, Iterator

import ghidra
from ghidra.program.model.block import BasicBlockModel

import capa.features.extractors.ghidra.helpers
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.basicblock import BasicBlock
from capa.features.extractors.helpers import MIN_STACKSTRING_LEN
from capa.features.extractors.base_extractor import BBHandle, FunctionHandle

currentProgram: ghidra.program.database.ProgramDB
monitor = getMonitor() # type: ignore [name-defined]


def _bb_has_tight_loop(bb):
    """
    parse tight loops, true if last instruction in basic block branches to bb start
    """
    listing = currentProgram.getListing()
    last_insn = listing.getInstructionAt(block.getMaxAddress().add(-0x1)) # all last insns are TERMINATOR

    if last_insn:
        if last_insn.getFlowType().isJump():
            if last_insn.getOpObjects(0)[0].getOffset() == bb.getMinAddress().getOffset():
                return True

    return False


def extract_bb_tight_loop(bb) -> Iterator[Tuple[Feature, Address]]:
    """check basic block for tight loop indicators"""
    if _bb_has_tight_loop(bb):
        yield Characteristic("tight loop"), AbsoluteVirtualAddress(bb.getMinAddress().getOffset()) 


def extract_features(bb) -> Iterator[Tuple[Feature, Address]]:
    """
    extract features from the given basic block.

    args:
      f (viv_utils.Function): the function from which to extract features
      bb (viv_utils.BasicBlock): the basic block to process.

    yields:
      Tuple[Feature, int]: the features and their location found in this basic block.
    """
    yield BasicBlock(), AbsoluteVirtualAddress(bb.getMinAddress().getOffset())
    for bb_handler in BASIC_BLOCK_HANDLERS:
        for feature, addr in bb_handler(f, bb):
            yield feature, addr


def main():
    features = []
    model = BasicBlockModel(currentProgram)
    for fhandle in capa.features.extractors.ghidra.helpers.get_function_symbols():
        for bb in model.getCodeBlocksContaining(fhandle.getBody(), monitor):
            features.extend(list(extract_features(bb)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
