# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Iterator
from collections import defaultdict

import binaryninja as binja
from binaryninja import Function, BinaryView, SymbolType, ILException, RegisterValueType, LowLevelILOperation

import capa.perf
import capa.features.extractors.elf
import capa.features.extractors.binja.file
import capa.features.extractors.binja.insn
import capa.features.extractors.binja.global_
import capa.features.extractors.binja.helpers
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

logger = logging.getLogger(__name__)


class BinjaFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, bv: binja.BinaryView):
        super().__init__(hashes=SampleHashes.from_bytes(bv.file.raw.read(0, bv.file.raw.length)))
        self.bv = bv
        self.global_features: list[tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.binja.file.extract_file_format(self.bv))
        self.global_features.extend(capa.features.extractors.binja.global_.extract_os(self.bv))
        self.global_features.extend(capa.features.extractors.binja.global_.extract_arch(self.bv))

        with capa.perf.timing("binary ninja: computing call graph"):
            self._call_graph = self._build_call_graph()

    def get_base_address(self):
        return AbsoluteVirtualAddress(self.bv.start)

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.binja.file.extract_features(self.bv)

    def _build_call_graph(self):
        # from function address to function addresses
        calls_from: defaultdict[int, set[int]] = defaultdict(set)
        calls_to: defaultdict[int, set[int]] = defaultdict(set)

        f: Function
        for f in self.bv.functions:
            for caller in f.callers:
                calls_from[caller.start].add(f.start)
                calls_to[f.start].add(caller.start)

        call_graph = {
            "calls_to": calls_to,
            "calls_from": calls_from,
        }

        return call_graph

    def get_functions(self) -> Iterator[FunctionHandle]:
        for f in self.bv.functions:
            yield FunctionHandle(address=AbsoluteVirtualAddress(f.start), inner=f, ctx={"call_graph": self._call_graph})

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.binja.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        f: binja.Function = fh.inner
        # Set up a MLIL basic block dict look up to associate the disassembly basic block with its MLIL basic block
        mlil_lookup = {}
        try:
            mlil = f.mlil
        except ILException:
            return

        if mlil is None:
            return

        for mlil_bb in mlil.basic_blocks:
            mlil_lookup[mlil_bb.source_block.start] = mlil_bb

        for bb in f.basic_blocks:
            mlil_bb = mlil_lookup.get(bb.start)

            yield BBHandle(address=AbsoluteVirtualAddress(bb.start), inner=(bb, mlil_bb))

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.binja.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        f: binja.Function = fh.inner

        bb: binja.BasicBlock
        mlbb: binja.MediumLevelILBasicBlock
        bb, mlbb = bbh.inner

        addr: int = bb.start
        for text, length in bb:
            llil = f.get_llils_at(addr)
            insn = capa.features.extractors.binja.helpers.DisassemblyInstruction(addr, length, text, llil)
            yield InsnHandle(address=AbsoluteVirtualAddress(addr), inner=insn)
            addr += length

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.binja.insn.extract_features(fh, bbh, ih)
