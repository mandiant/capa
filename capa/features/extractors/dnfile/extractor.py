# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import List, Tuple, Iterator

import dnfile

import capa.features.extractors
import capa.features.extractors.dnfile.file
import capa.features.extractors.dnfile.insn
from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address, DNTokenAddress, DNTokenOffsetAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, FeatureExtractor
from capa.features.extractors.dnfile.helpers import get_dotnet_managed_method_bodies


class DnfileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super(DnfileFeatureExtractor, self).__init__()
        self.pe: dnfile.dnPE = dnfile.dnPE(path)

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.dotnetfile.extract_file_os(pe=self.pe))
        self.global_features.extend(capa.features.extractors.dotnetfile.extract_file_arch(pe=self.pe))

    def get_base_address(self):
        return NO_ADDRESS

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.dnfile.file.extract_features(self.pe)

    def get_functions(self) -> Iterator[FunctionHandle]:
        for token, f in get_dotnet_managed_method_bodies(self.pe):
            yield FunctionHandle(address=DNTokenAddress(token), inner=f, ctx={"pe": self.pe})

    def extract_function_features(self, f):
        # TODO
        yield from []

    def get_basic_blocks(self, f) -> Iterator[BBHandle]:
        # each dotnet method is considered 1 basic block
        yield BBHandle(
            address=f.address,
            inner=f.inner,
        )

    def extract_basic_block_features(self, fh, bbh):
        # we don't support basic block features
        yield from []

    def get_instructions(self, fh, bbh):
        for insn in bbh.inner.instructions:
            yield InsnHandle(
                address=DNTokenOffsetAddress(bbh.address, insn.offset - (fh.inner.offset + fh.inner.header_size)),
                inner=insn,
            )

    def extract_insn_features(self, fh, bbh, ih) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.dnfile.insn.extract_features(fh, bbh, ih)
