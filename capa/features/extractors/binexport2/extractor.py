# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import List, Tuple, Iterator, Any

import capa.features.extractors.elf
import capa.features.extractors.binexport2.file
import capa.features.extractors.binexport2.insn
import capa.features.extractors.binexport2.global_
import capa.features.extractors.binexport2.function
import capa.features.extractors.binexport2.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)


# TODO(wb): 1755
TODOType = Any


class BinExport2FeatureExtractor(StaticFeatureExtractor):
    def __init__(self, be2: TODOType, buf: TODOType):
        super().__init__(hashes=SampleHashes.from_bytes(buf))
        self.be2 = be2
        self.buf = buf
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.binexport2.file.extract_file_format(self.be2, self.buf))
        self.global_features.extend(capa.features.extractors.binexport2.global_.extract_os(self.be2))
        self.global_features.extend(capa.features.extractors.binexport2.global_.extract_arch(self.be2))

    def get_base_address(self):
        # TODO(wb): 1755
        return AbsoluteVirtualAddress(0x0)

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.binexport2.file.extract_features(self.be2, self.buf)

    def get_functions(self) -> Iterator[FunctionHandle]:
        # TODO(wb): 1755
        yield from ()

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.binexport2.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        # TODO(wb): 1755
        yield from ()

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.binexport2.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        # TODO(wb): 1755
        yield from ()

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.binexport2.insn.extract_features(fh, bbh, ih)
