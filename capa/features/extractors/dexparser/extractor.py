# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import logging
from typing import List, Tuple, Iterator
from pathlib import Path

import dexparser

import capa.features.extractors
import capa.features.extractors.dexfile
from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)

logger = logging.getLogger(__name__)


class DexparserFeatureExtractorCache:
    def __init__(self, dex: dexparser.DEXParser):
        self.dex = dex


class DexparserFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, path: Path):
        self.dex = dexparser.DEXParser(filedir=str(path))
        super().__init__(hashes=SampleHashes.from_bytes(path.read_bytes()))

        self.cache = DexparserFeatureExtractorCache(self.dex)

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.dexfile.extract_file_format())
        self.global_features.extend(capa.features.extractors.dexfile.extract_file_os(dex=self.dex))
        self.global_features.extend(capa.features.extractors.dexfile.extract_file_arch(dex=self.dex))

    def todo(self):
        import inspect

        logger.debug("[DexparserFeatureExtractor:TODO] " + inspect.stack()[1].function)

    def get_base_address(self):
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from self.global_features

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        return self.todo()
        yield

    def get_functions(self) -> Iterator[FunctionHandle]:
        return self.todo()
        yield

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        return self.todo()
        yield

    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        return self.todo()
        yield

    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        return self.todo()
        yield

    def get_instructions(self, f: FunctionHandle, bb: BBHandle) -> Iterator[InsnHandle]:
        return self.todo()
        yield

    def extract_insn_features(
        self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        return self.todo()
        yield
