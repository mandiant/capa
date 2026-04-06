# Copyright 2023 Google LLC
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

import binaryninja as binja

import capa.features.extractors.elf
import capa.features.extractors.binja.file
import capa.features.extractors.binja.insn
import capa.features.extractors.binja.global_
import capa.features.extractors.binja.function
import capa.features.extractors.binja.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)


class BinjaFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, bv: binja.BinaryView):
        super().__init__(hashes=SampleHashes.from_bytes(bv.file.raw.read(0, bv.file.raw.length)))
        self.bv = bv
        self.global_features: list[tuple[Feature, Address]] = []
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

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.binja.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        f: binja.Function = fh.inner
        for bb in f.basic_blocks:
            yield BBHandle(address=AbsoluteVirtualAddress(bb.start), inner=bb)

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.binja.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        import capa.features.extractors.binja.helpers as binja_helpers

        bb: binja.BasicBlock = bbh.inner
        addr = bb.start

        for text, length in bb:
            insn = binja_helpers.DisassemblyInstruction(addr, length, text)
            yield InsnHandle(address=AbsoluteVirtualAddress(addr), inner=insn)
            addr += length

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.binja.insn.extract_features(fh, bbh, ih)
