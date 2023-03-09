# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import List, Tuple, Iterator

import viv_utils
import viv_utils.flirt

import capa.features.extractors.common
import capa.features.extractors.viv.file
import capa.features.extractors.viv.insn
import capa.features.extractors.viv.global_
import capa.features.extractors.viv.function
import capa.features.extractors.viv.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, FeatureExtractor

logger = logging.getLogger(__name__)


class VivisectFeatureExtractor(FeatureExtractor):
    def __init__(self, vw, path, os):
        super().__init__()
        self.vw = vw
        self.path = path
        with open(self.path, "rb") as f:
            self.buf = f.read()

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.viv.file.extract_file_format(self.buf))
        self.global_features.extend(capa.features.extractors.common.extract_os(self.buf, os))
        self.global_features.extend(capa.features.extractors.viv.global_.extract_arch(self.vw))

    def get_base_address(self):
        # assume there is only one file loaded into the vw
        return AbsoluteVirtualAddress(list(self.vw.filemeta.values())[0]["imagebase"])

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.viv.file.extract_features(self.vw, self.buf)

    def get_functions(self) -> Iterator[FunctionHandle]:
        for va in sorted(self.vw.getFunctions()):
            yield FunctionHandle(address=AbsoluteVirtualAddress(va), inner=viv_utils.Function(self.vw, va))

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.viv.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        f: viv_utils.Function = fh.inner
        for bb in f.basic_blocks:
            yield BBHandle(address=AbsoluteVirtualAddress(bb.va), inner=bb)

    def extract_basic_block_features(self, fh: FunctionHandle, bbh) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.viv.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        bb: viv_utils.BasicBlock = bbh.inner
        for insn in bb.instructions:
            yield InsnHandle(address=AbsoluteVirtualAddress(insn.va), inner=insn)

    def extract_insn_features(
        self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.viv.insn.extract_features(fh, bbh, ih)

    def is_library_function(self, addr):
        return viv_utils.flirt.is_library_function(self.vw, addr)

    def get_function_name(self, addr):
        return viv_utils.get_function_name(self.vw, addr)
