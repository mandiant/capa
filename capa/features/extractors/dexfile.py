# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import struct
import logging
from typing import Set, Dict, List, Tuple, Iterator, Optional, TypedDict
from pathlib import Path
from dataclasses import dataclass

import dexparser.disassembler as disassembler
from dexparser import DEXParser, uleb128_value

from capa.features.file import Import, FunctionName
from capa.features.common import (
    OS,
    FORMAT_DEX,
    OS_ANDROID,
    ARCH_DALVIK,
    Arch,
    Class,
    Format,
    String,
    Feature,
    Namespace,
)
from capa.features.address import NO_ADDRESS, Address, DexClassAddress, DexMethodAddress, FileOffsetAddress
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)

logger = logging.getLogger(__name__)


# Reference: https://source.android.com/docs/core/runtime/dex-format


class DexProtoId(TypedDict):
    shorty_idx: int
    return_type_idx: int
    param_off: int


class DexMethodId(TypedDict):
    class_idx: int
    proto_idx: int
    name_idx: int


@dataclass
class DexAnalyzedMethod:
    class_type: str
    name: str
    shorty_descriptor: str
    return_type: str
    parameters: List[str]
    id_offset: int = 0
    code_offset: int = 0
    access_flags: Optional[int] = None

    @property
    def address(self):
        # NOTE: Some methods do not have code, in that case we use the method_id offset
        if self.has_code:
            return self.code_offset
        else:
            return self.id_offset

    @property
    def has_code(self):
        # NOTE: code_offset is zero if the method is abstract/native or not defined in a class
        return self.code_offset != 0

    @property
    def has_definition(self):
        # NOTE: access_flags is only known if the method is defined in a class
        return self.access_flags is not None

    @property
    def qualified_name(self):
        return f"{self.class_type}::{self.name}"


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


class DexClassData(TypedDict):
    static_fields: List[DexFieldDef]
    instance_fields: List[DexFieldDef]
    direct_methods: List[DexMethodDef]
    virtual_methods: List[DexMethodDef]


@dataclass
class DexAnalyzedClass:
    offset: int
    class_type: str
    superclass_type: str
    interfaces: List[str]
    source_file: str
    data: Optional[DexClassData]


class DexAnnotation(TypedDict):
    visibility: int
    type_idx_diff: int
    size_diff: int
    name_idx_diff: int
    value_type: int
    encoded_value: int


class DexAnalysis:
    def get_strings(self):
        # NOTE: Copied from dexparser, upstream later

        strings: List[Tuple[int, bytes]] = []
        string_ids_off = self.dex.header_data["string_ids_off"]

        for i in range(self.dex.header_data["string_ids_size"]):
            offset = struct.unpack("<L", self.dex.data[string_ids_off + (i * 4) : string_ids_off + (i * 4) + 4])[0]
            c_size, size_offset = uleb128_value(self.dex.data, offset)
            c_char = self.dex.data[offset + size_offset : offset + size_offset + c_size]
            strings.append((offset, c_char))

        return strings

    def __init__(self, dex: DEXParser):
        self.dex = dex

        self.strings = self.get_strings()
        self.strings_utf8: List[str] = []
        for _, data in self.strings:
            # NOTE: This is technically incorrect
            # Reference: https://source.android.com/devices/tech/dalvik/dex-format#mutf-8
            self.strings_utf8.append(data.decode("utf-8", errors="backslashreplace"))

        self.type_ids: List[int] = dex.get_typeids()
        self.method_ids: List[DexMethodId] = dex.get_methods()
        self.proto_ids: List[DexProtoId] = dex.get_protoids()
        self.field_ids: List[DexFieldId] = dex.get_fieldids()
        self.class_defs: List[DexClassDef] = dex.get_classdef_data()

        self._is_analyzing = True
        self.used_classes: Set[str] = set()
        self.classes = self._analyze_classes()
        self.methods = self._analyze_methods()
        self.methods_by_address: Dict[int, DexAnalyzedMethod] = {m.address: m for m in self.methods}

        self.namespaces: Set[str] = set()
        for class_type in self.used_classes:
            idx = class_type.rfind(".")
            if idx != -1:
                self.namespaces.add(class_type[:idx])

        for class_type in self.classes:
            self.used_classes.remove(class_type)

        # Only available after code analysis
        self._is_analyzing = False

    def analyze_code(self):
        # Loop over the classes and analyze them
        # self.classes: List[DexClass] = self.dex.get_class_data(offset=-1)
        # self.annotations: List[DexAnnotation] = dex.get_annotations(offset=-1)
        # self.static_values: List[int] = dex.get_static_values(offset=-1)
        pass

    def get_string(self, index: int) -> str:
        return self.strings_utf8[index]

    def _decode_descriptor(self, descriptor: str) -> str:
        first = descriptor[0]
        if first == "L":
            pretty = descriptor[1:-1].replace("/", ".")
            if self._is_analyzing:
                self.used_classes.add(pretty)
        elif first == "[":
            pretty = self._decode_descriptor(descriptor[1:]) + "[]"
        else:
            pretty = disassembler.type_descriptor[first]
        return pretty

    def get_pretty_type(self, index: int) -> str:
        if index == 0xFFFFFFFF:
            return "<NO_INDEX>"
        descriptor = self.get_string(self.type_ids[index])
        return self._decode_descriptor(descriptor)

    def _analyze_classes(self):
        classes: Dict[str, DexAnalyzedClass] = {}
        offset = self.dex.header_data["class_defs_off"]
        for index, clazz in enumerate(self.class_defs):
            class_type = self.get_pretty_type(clazz["class_idx"])

            # Superclass
            superclass_idx = clazz["superclass_idx"]
            if superclass_idx != 0xFFFFFFFF:
                superclass_type = self.get_pretty_type(superclass_idx)
            else:
                superclass_type = ""

            # Interfaces
            interfaces = []
            interfaces_offset = clazz["interfaces_off"]
            if interfaces_offset != 0:
                size = struct.unpack("<L", self.dex.data[interfaces_offset : interfaces_offset + 4])[0]
                for i in range(size):
                    type_idx = struct.unpack(
                        "<H", self.dex.data[interfaces_offset + 4 + i * 2 : interfaces_offset + 6 + i * 2]
                    )[0]
                    interface_type = self.get_pretty_type(type_idx)
                    interfaces.append(interface_type)

            # Source file
            source_file_idx = clazz["source_file_idx"]
            if source_file_idx != 0xFFFFFFFF:
                source_file = self.get_string(source_file_idx)
            else:
                source_file = ""

            # Data
            data_offset = clazz["class_data_off"]
            if data_offset != 0:
                data = self.dex.get_class_data(data_offset)
            else:
                data = None

            classes[class_type] = DexAnalyzedClass(
                offset=offset + index * 32,
                class_type=class_type,
                superclass_type=superclass_type,
                interfaces=interfaces,
                source_file=source_file,
                data=data,
            )
        return classes

    def _analyze_methods(self):
        methods: List[DexAnalyzedMethod] = []
        for method_id in self.method_ids:
            proto = self.proto_ids[method_id["proto_idx"]]
            parameters = []

            param_off = proto["param_off"]
            if param_off != 0:
                size = struct.unpack("<L", self.dex.data[param_off : param_off + 4])[0]
                for i in range(size):
                    type_idx = struct.unpack("<H", self.dex.data[param_off + 4 + i * 2 : param_off + 6 + i * 2])[0]
                    param_type = self.get_pretty_type(type_idx)
                    parameters.append(param_type)

            methods.append(
                DexAnalyzedMethod(
                    class_type=self.get_pretty_type(method_id["class_idx"]),
                    name=self.get_string(method_id["name_idx"]),
                    shorty_descriptor=self.get_string(proto["shorty_idx"]),
                    return_type=self.get_pretty_type(proto["return_type_idx"]),
                    parameters=parameters,
                )
            )

        # Fill in the missing method data
        for clazz in self.classes.values():
            if clazz.data is None:
                continue

            for method_def in clazz.data["direct_methods"]:
                diff = method_def["diff"]
                methods[diff].access_flags = method_def["access_flags"]
                methods[diff].code_offset = method_def["code_off"]

            for method_def in clazz.data["virtual_methods"]:
                diff = method_def["diff"]
                methods[diff].access_flags = method_def["access_flags"]
                methods[diff].code_offset = method_def["code_off"]

        # Fill in the missing code offsets with fake data
        offset = self.dex.header_data["method_ids_off"]
        for index, method in enumerate(methods):
            method.id_offset = offset + index * 8

        return methods

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield Format(FORMAT_DEX), NO_ADDRESS

        for i in range(len(self.strings)):
            yield String(self.strings_utf8[i]), FileOffsetAddress(self.strings[i][0])

        for method in self.methods:
            if method.has_definition:
                yield FunctionName(method.qualified_name), DexMethodAddress(method.address)
            else:
                yield Import(method.qualified_name), DexMethodAddress(method.address)

        for namespace in self.namespaces:
            yield Namespace(namespace), NO_ADDRESS

        for clazz in self.classes.values():
            yield Class(clazz.class_type), DexClassAddress(clazz.offset)

        for class_type in self.used_classes:
            yield Class(class_type), NO_ADDRESS


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
        yield from self.analysis.extract_file_features()

    def is_library_function(self, addr: Address) -> bool:
        assert isinstance(addr, DexMethodAddress)
        method = self.analysis.methods_by_address[addr]
        # exclude androidx/kotlin stuff?
        return not method.has_definition

    def get_function_name(self, addr: Address) -> str:
        assert isinstance(addr, DexMethodAddress)
        method = self.analysis.methods_by_address[addr]
        return method.qualified_name

    def get_functions(self) -> Iterator[FunctionHandle]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")

        for method in self.analysis.methods:
            yield FunctionHandle(DexMethodAddress(method.address), method)

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")
        method: DexAnalyzedMethod = f.inner
        if method.has_code:
            return self.todo()
            yield

    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        if not self.code_analysis:
            raise Exception("code analysis is disabled")
        method: DexAnalyzedMethod = f.inner
        if method.has_code:
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
