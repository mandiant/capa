# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Tuple, Iterator
from pathlib import Path

from dexparser import DEXParser

from capa.features.common import OS, FORMAT_DEX, OS_ANDROID, ARCH_DALVIK, Arch, Format, Feature
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.base_extractor import SampleHashes, StaticFeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_format(**kwargs) -> Iterator[Tuple[Format, Address]]:
    yield Format(FORMAT_DEX), NO_ADDRESS


FILE_HANDLERS = (extract_file_format,)


def extract_file_features(dex: DEXParser) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(dex=dex):  # type: ignore
            yield feature, addr


def extract_file_os(**kwargs) -> Iterator[Tuple[OS, Address]]:
    yield OS(OS_ANDROID), NO_ADDRESS


def extract_file_arch(**kwargs) -> Iterator[Tuple[Arch, Address]]:
    yield Arch(ARCH_DALVIK), NO_ADDRESS


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


def extract_global_features(dex: DEXParser) -> Iterator[Tuple[Feature, Address]]:
    for handler in GLOBAL_HANDLERS:
        for feature, va in handler(dex=dex):  # type: ignore
            yield feature, va


class DexFileFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, path: Path):
        super().__init__(hashes=SampleHashes.from_bytes(path.read_bytes()))
        self.path: Path = path
        self.dex = DEXParser(filedir=str(path))

    def get_base_address(self):
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from extract_global_features(self.dex)

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from extract_file_features(self.dex)

    def get_functions(self):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")

    def extract_function_features(self, f):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")

    def get_basic_blocks(self, f):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")

    def extract_basic_block_features(self, f, bb):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")

    def get_instructions(self, f, bb):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")

    def extract_insn_features(self, f, bb, insn):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")

    def is_library_function(self, va):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")

    def get_function_name(self, va):
        raise NotImplementedError("DexFileFeatureExtractor can only be used to extract file features")
