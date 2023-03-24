# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import List, Tuple, Iterator

import binaryninja as binja

import capa.features.extractors.elf
import capa.features.extractors.binja.file
import capa.features.extractors.binja.insn
import capa.features.extractors.binja.global_
import capa.features.extractors.binja.function
import capa.features.extractors.binja.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class BinjaFeatureExtractor(FeatureExtractor):
    def __init__(self, bv: binja.BinaryView):
        super().__init__()
        self.bv = bv
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.binja.file.extract_file_format(self.bv))
        self.global_features.extend(capa.features.extractors.binja.global_.extract_os(self.bv))
        self.global_features.extend(capa.features.extractors.binja.global_.extract_arch(self.bv))

    def get_base_address(self):
        return AbsoluteVirtualAddress(self.bv.start)

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.binja.file.extract_features(self.bv)

    def get_functions(self) -> Iterator[FunctionHandle]:
        for f in self.bv.functions:
            yield FunctionHandle(address=AbsoluteVirtualAddress(f.start), inner=f)

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.binja.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        f: binja.Function = fh.inner
        # Set up a MLIL basic block dict look up to associate the disassembly basic block with its MLIL basic block
        mlil_lookup = {}
        for mlil_bb in f.mlil.basic_blocks:
            mlil_lookup[mlil_bb.source_block.start] = mlil_bb

        for bb in f.basic_blocks:
            mlil_bb = None
            if bb.start in mlil_lookup:
                mlil_bb = mlil_lookup[bb.start]

            yield BBHandle(address=AbsoluteVirtualAddress(bb.start), inner=(bb, mlil_bb))

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.binja.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        import capa.features.extractors.binja.helpers as binja_helpers

        bb: Tuple[binja.BasicBlock, binja.MediumLevelILBasicBlock] = bbh.inner
        addr = bb[0].start

        for text, length in bb[0]:
            insn = binja_helpers.DisassemblyInstruction(addr, length, text)
            yield InsnHandle(address=AbsoluteVirtualAddress(addr), inner=insn)
            addr += length

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.binja.insn.extract_features(fh, bbh, ih)
