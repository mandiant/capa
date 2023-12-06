# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import struct
import logging
from typing import List, Tuple, Iterator, TypedDict
from pathlib import Path
from dataclasses import dataclass

from dexparser import DEXParser

from capa.features.common import OS, FORMAT_DEX, OS_ANDROID, ARCH_DALVIK, Arch, Format, Feature
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)

logger = logging.getLogger(__name__)


def extract_file_format(**kwargs) -> Iterator[Tuple[Format, Address]]:
    yield Format(FORMAT_DEX), NO_ADDRESS


FILE_HANDLERS = (extract_file_format,)


def extract_file_features(dex: DEXParser) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(dex=dex):  # type: ignore
            yield feature, addr


# Reference: https://source.android.com/docs/core/runtime/dex-format


class DexProtoId(TypedDict):
    shorty_idx: int
    return_type_idx: int
    param_off: int


class DexMethodId(TypedDict):
    class_idx: int
    proto_idx: int
    name_idx: int


class DexFieldId(TypedDict):
    class_idx: int
    type_idx: int
    name_idx: int


class DexClassDef(TypedDict):
    class_idx: int
    access_flags: int
    superclass_idx: int
    interfaces_off: int
    source_file_idx: int
    annotations_off: int
    class_data_off: int
    static_values_off: int


class DexFieldDef(TypedDict):
    diff: int
    access_flags: int


class DexMethodDef(TypedDict):
    diff: int
    access_flags: int
    code_off: int


class DexClass(TypedDict):
    static_fields: List[DexFieldDef]
    instance_fields: List[DexFieldDef]
    direct_methods: List[DexMethodDef]
    virtual_methods: List[DexMethodDef]


class DexAnnotation(TypedDict):
    visibility: int
    type_idx_diff: int
    size_diff: int
    name_idx_diff: int
    value_type: int
    encoded_value: int


class DexMethodAddress(int, Address):
    def __new__(cls, index: int):
        return int.__new__(cls, index)

    def __repr__(self):
        return f"DexMethodAddress(index={int(self)})"

    def __str__(self) -> str:
        return repr(self)

    def __hash__(self):
        return int.__hash__(self)


@dataclass
class DexAnalyzedMethod:
    address: DexMethodAddress
    class_type: str
    name: str
    shorty_descriptor: str
    return_type: str
    parameters: List[str]


class DexAnalysis:
    def __init__(self, dex: DEXParser):
        self.dex = dex
        self.strings: List[str] = dex.get_strings()
        self.type_ids: List[int] = dex.get_typeids()
        self.method_ids: List[DexMethodId] = dex.get_methods()
        self.proto_ids: List[DexProtoId] = dex.get_protoids()
        self.field_ids: List[DexFieldId] = dex.get_fieldids()
        self.class_defs: List[DexClassDef] = dex.get_classdef_data()

        # Only available after analysis
        self.methods: List[DexAnalyzedMethod] = []

    def analyze_code(self):
        # Loop over the classes and analyze them
        # self.classes: List[DexClass] = dex.get_class_data(offset=-1)
        # self.annotations: List[DexAnnotation] = dex.get_annotations(offset=-1)
        # self.static_values: List[int] = dex.get_static_values(offset=-1)

        self._analyze_methods()

    def _analyze_methods(self):
        for index, method in enumerate(self.method_ids):
            proto = self.proto_ids[method["proto_idx"]]
            parameters = []

            param_off = proto["param_off"]
            if param_off != 0:
                size = struct.unpack("<L", self.dex.data[param_off : param_off + 4])[0]
                for i in range(size):
                    type_idx = struct.unpack("<H", self.dex.data[param_off + 4 + i * 2 : param_off + 6 + i * 2])[0]
                    param_type = self.strings[self.type_ids[type_idx]]
                    parameters.append(param_type)

            self.methods.append(
                DexAnalyzedMethod(
                    address=DexMethodAddress(index),
                    class_type=self.strings[self.type_ids[method["class_idx"]]],
                    name=self.strings[method["name_idx"]],
                    shorty_descriptor=self.strings[proto["shorty_idx"]],
                    return_type=self.strings[self.type_ids[proto["return_type_idx"]]],
                    parameters=parameters,
                )
            )


class DexFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, path: Path, *, code_analysis: bool):
        super().__init__(hashes=SampleHashes.from_bytes(path.read_bytes()))
        self.path: Path = path
        self.code_analysis = code_analysis
        self.dex = DEXParser(filedir=str(path))
        self.analysis = DexAnalysis(self.dex)

        # Perform more expensive code analysis only when requested
        if self.code_analysis:
            self.analysis.analyze_code()

    def todo(self):
        import inspect

        message = "[DexparserFeatureExtractor:TODO] " + inspect.stack()[1].function
        logger.debug(message)

    def get_base_address(self):
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        # These are hardcoded global features
        yield Format(FORMAT_DEX), NO_ADDRESS
        yield OS(OS_ANDROID), NO_ADDRESS
        yield Arch(ARCH_DALVIK), NO_ADDRESS

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from extract_file_features(self.dex)

    def is_library_function(self, addr: Address) -> bool:
        # exclude androidx stuff?
        return super().is_library_function(addr)

    def get_functions(self) -> Iterator[FunctionHandle]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")

        for index in range(len(self.analysis.methods)):
            yield FunctionHandle(DexMethodAddress(index), self.analysis)

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")
        return self.todo()
        yield

    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")
        return self.todo()
        yield

    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")
        return self.todo()
        yield

    def get_instructions(self, f: FunctionHandle, bb: BBHandle) -> Iterator[InsnHandle]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")
        return self.todo()
        yield

    def extract_insn_features(
        self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")
        return self.todo()
        yield
