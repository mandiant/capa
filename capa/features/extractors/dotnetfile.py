# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Tuple, Iterator
from pathlib import Path

import dnfile
import pefile

import capa.features.extractors.helpers
from capa.features.file import Import, FunctionName
from capa.features.common import (
    OS,
    OS_ANY,
    ARCH_ANY,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    FORMAT_DOTNET,
    Arch,
    Class,
    Format,
    String,
    Feature,
    Namespace,
    Characteristic,
)
from capa.features.address import NO_ADDRESS, Address, DNTokenAddress
from capa.features.extractors.dnfile.types import DnType
from capa.features.extractors.base_extractor import SampleHashes, StaticFeatureExtractor
from capa.features.extractors.dnfile.helpers import (
    iter_dotnet_table,
    is_dotnet_mixed_mode,
    get_dotnet_managed_imports,
    get_dotnet_managed_methods,
    resolve_nested_typedef_name,
    resolve_nested_typeref_name,
    calculate_dotnet_token_value,
    get_dotnet_unmanaged_imports,
    get_dotnet_nested_class_table_index,
)

logger = logging.getLogger(__name__)


def extract_file_format(**kwargs) -> Iterator[Tuple[Format, Address]]:
    yield Format(FORMAT_DOTNET), NO_ADDRESS
    yield Format(FORMAT_PE), NO_ADDRESS


def extract_file_import_names(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Import, Address]]:
    for method in get_dotnet_managed_imports(pe):
        # like System.IO.File::OpenRead
        yield Import(str(method)), DNTokenAddress(method.token)

    for imp in get_dotnet_unmanaged_imports(pe):
        # like kernel32.CreateFileA
        for name in capa.features.extractors.helpers.generate_symbols(imp.module, imp.method, include_dll=True):
            yield Import(name), DNTokenAddress(imp.token)


def extract_file_function_names(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[FunctionName, Address]]:
    for method in get_dotnet_managed_methods(pe):
        yield FunctionName(str(method)), DNTokenAddress(method.token)


def extract_file_namespace_features(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Namespace, Address]]:
    """emit namespace features from TypeRef and TypeDef tables"""

    # namespaces may be referenced multiple times, so we need to filter
    namespaces = set()

    for _, typedef in iter_dotnet_table(pe, dnfile.mdtable.TypeDef.number):
        # emit internal .NET namespaces
        assert isinstance(typedef, dnfile.mdtable.TypeDefRow)
        namespaces.add(str(typedef.TypeNamespace))

    for _, typeref in iter_dotnet_table(pe, dnfile.mdtable.TypeRef.number):
        # emit external .NET namespaces
        assert isinstance(typeref, dnfile.mdtable.TypeRefRow)
        namespaces.add(str(typeref.TypeNamespace))

    # namespaces may be empty, discard
    namespaces.discard("")

    for namespace in namespaces:
        # namespace do not have an associated token, so we yield 0x0
        yield Namespace(namespace), NO_ADDRESS


def extract_file_class_features(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Class, Address]]:
    """emit class features from TypeRef and TypeDef tables"""
    nested_class_table = get_dotnet_nested_class_table_index(pe)

    for rid, typedef in iter_dotnet_table(pe, dnfile.mdtable.TypeDef.number):
        # emit internal .NET classes
        assert isinstance(typedef, dnfile.mdtable.TypeDefRow)

        typedefnamespace, typedefname = resolve_nested_typedef_name(nested_class_table, rid, typedef, pe)

        token = calculate_dotnet_token_value(dnfile.mdtable.TypeDef.number, rid)
        yield Class(DnType.format_name(typedefname, namespace=typedefnamespace)), DNTokenAddress(token)

    for rid, typeref in iter_dotnet_table(pe, dnfile.mdtable.TypeRef.number):
        # emit external .NET classes
        assert isinstance(typeref, dnfile.mdtable.TypeRefRow)

        typerefnamespace, typerefname = resolve_nested_typeref_name(typeref.ResolutionScope.row_index, typeref, pe)

        token = calculate_dotnet_token_value(dnfile.mdtable.TypeRef.number, rid)
        yield Class(DnType.format_name(typerefname, namespace=typerefnamespace)), DNTokenAddress(token)


def extract_file_os(**kwargs) -> Iterator[Tuple[OS, Address]]:
    yield OS(OS_ANY), NO_ADDRESS


def extract_file_arch(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Arch, Address]]:
    # to distinguish in more detail, see https://stackoverflow.com/a/23614024/10548020
    # .NET 4.5 added option: any CPU, 32-bit preferred
    assert pe.net is not None
    assert pe.net.Flags is not None

    if pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
        yield Arch(ARCH_I386), NO_ADDRESS
    elif not pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        yield Arch(ARCH_AMD64), NO_ADDRESS
    else:
        yield Arch(ARCH_ANY), NO_ADDRESS


def extract_file_strings(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[String, Address]]:
    yield from capa.features.extractors.common.extract_file_strings(pe.__data__)


def extract_file_mixed_mode_characteristic_features(
    pe: dnfile.dnPE, **kwargs
) -> Iterator[Tuple[Characteristic, Address]]:
    if is_dotnet_mixed_mode(pe):
        yield Characteristic("mixed mode"), NO_ADDRESS


def extract_file_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(pe=pe):  # type: ignore
            yield feature, addr


FILE_HANDLERS = (
    extract_file_import_names,
    extract_file_function_names,
    extract_file_strings,
    extract_file_format,
    extract_file_mixed_mode_characteristic_features,
    extract_file_namespace_features,
    extract_file_class_features,
)


def extract_global_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, Address]]:
    for handler in GLOBAL_HANDLERS:
        for feature, va in handler(pe=pe):  # type: ignore
            yield feature, va


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


class DotnetFileFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, path: Path):
        super().__init__(hashes=SampleHashes.from_bytes(path.read_bytes()))
        self.path: Path = path
        self.pe: dnfile.dnPE = dnfile.dnPE(str(path))

    def get_base_address(self):
        return NO_ADDRESS

    def get_entry_point(self) -> int:
        # self.pe.net.Flags.CLT_NATIVE_ENTRYPOINT
        #  True: native EP: Token
        #  False: managed EP: RVA
        assert self.pe.net is not None
        assert self.pe.net.struct is not None

        return self.pe.net.struct.EntryPointTokenOrRva

    def extract_global_features(self):
        yield from extract_global_features(self.pe)

    def extract_file_features(self):
        yield from extract_file_features(self.pe)

    def is_dotnet_file(self) -> bool:
        return bool(self.pe.net)

    def is_mixed_mode(self) -> bool:
        return is_dotnet_mixed_mode(self.pe)

    def get_runtime_version(self) -> Tuple[int, int]:
        assert self.pe.net is not None
        assert self.pe.net.struct is not None
        assert self.pe.net.struct.MajorRuntimeVersion is not None
        assert self.pe.net.struct.MinorRuntimeVersion is not None

        return self.pe.net.struct.MajorRuntimeVersion, self.pe.net.struct.MinorRuntimeVersion

    def get_meta_version_string(self) -> str:
        assert self.pe.net is not None
        assert self.pe.net.metadata is not None
        assert self.pe.net.metadata.struct is not None
        assert self.pe.net.metadata.struct.Version is not None

        vbuf = self.pe.net.metadata.struct.Version
        assert isinstance(vbuf, bytes)

        return vbuf.rstrip(b"\x00").decode("utf-8")

    def get_functions(self):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def extract_function_features(self, f):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def get_basic_blocks(self, f):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def extract_basic_block_features(self, f, bb):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def get_instructions(self, f, bb):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def extract_insn_features(self, f, bb, insn):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def is_library_function(self, va):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def get_function_name(self, va):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")
