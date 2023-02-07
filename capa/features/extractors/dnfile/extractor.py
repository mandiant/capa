# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import Dict, List, Tuple, Union, Iterator, Optional

import dnfile
from dncil.cil.opcode import OpCodes

import capa.features.extractors
import capa.features.extractors.dotnetfile
import capa.features.extractors.dnfile.file
import capa.features.extractors.dnfile.insn
import capa.features.extractors.dnfile.function
from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address, DNTokenAddress, DNTokenOffsetAddress
from capa.features.extractors.dnfile.types import DnType, DnUnmanagedMethod
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, FeatureExtractor
from capa.features.extractors.dnfile.helpers import (
    get_dotnet_types,
    get_dotnet_fields,
    get_dotnet_managed_imports,
    get_dotnet_managed_methods,
    get_dotnet_unmanaged_imports,
    get_dotnet_managed_method_bodies,
)


class DnFileFeatureExtractorCache:
    def __init__(self, pe: dnfile.dnPE):
        self.imports: Dict[int, Union[DnType, DnUnmanagedMethod]] = {}
        self.native_imports: Dict[int, Union[DnType, DnUnmanagedMethod]] = {}
        self.methods: Dict[int, Union[DnType, DnUnmanagedMethod]] = {}
        self.fields: Dict[int, Union[DnType, DnUnmanagedMethod]] = {}
        self.types: Dict[int, Union[DnType, DnUnmanagedMethod]] = {}

        for import_ in get_dotnet_managed_imports(pe):
            self.imports[import_.token] = import_
        for native_import in get_dotnet_unmanaged_imports(pe):
            self.native_imports[native_import.token] = native_import
        for method in get_dotnet_managed_methods(pe):
            self.methods[method.token] = method
        for field in get_dotnet_fields(pe):
            self.fields[field.token] = field
        for type_ in get_dotnet_types(pe):
            self.types[type_.token] = type_

    def get_import(self, token: int) -> Optional[Union[DnType, DnUnmanagedMethod]]:
        return self.imports.get(token, None)

    def get_native_import(self, token: int) -> Optional[Union[DnType, DnUnmanagedMethod]]:
        return self.native_imports.get(token, None)

    def get_method(self, token: int) -> Optional[Union[DnType, DnUnmanagedMethod]]:
        return self.methods.get(token, None)

    def get_field(self, token: int) -> Optional[Union[DnType, DnUnmanagedMethod]]:
        return self.fields.get(token, None)

    def get_type(self, token: int) -> Optional[Union[DnType, DnUnmanagedMethod]]:
        return self.types.get(token, None)


class DnfileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super().__init__()
        self.pe: dnfile.dnPE = dnfile.dnPE(path)

        # pre-compute .NET token lookup tables; each .NET method has access to this cache for feature extraction
        # most relevant at instruction scope
        self.token_cache: DnFileFeatureExtractorCache = DnFileFeatureExtractorCache(self.pe)

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.dotnetfile.extract_file_format())
        self.global_features.extend(capa.features.extractors.dotnetfile.extract_file_os(pe=self.pe))
        self.global_features.extend(capa.features.extractors.dotnetfile.extract_file_arch(pe=self.pe))

    def get_base_address(self):
        return NO_ADDRESS

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.dnfile.file.extract_features(self.pe)

    def get_functions(self) -> Iterator[FunctionHandle]:
        # create a method lookup table
        methods: Dict[Address, FunctionHandle] = {}
        for token, method in get_dotnet_managed_method_bodies(self.pe):
            fh: FunctionHandle = FunctionHandle(
                address=DNTokenAddress(token),
                inner=method,
                ctx={"pe": self.pe, "calls_from": set(), "calls_to": set(), "cache": self.token_cache},
            )

            # method tokens should be unique
            assert fh.address not in methods.keys()
            methods[fh.address] = fh

        # calculate unique calls to/from each method
        for fh in methods.values():
            for insn in fh.inner.instructions:
                if insn.opcode not in (
                    OpCodes.Call,
                    OpCodes.Callvirt,
                    OpCodes.Jmp,
                    OpCodes.Newobj,
                ):
                    continue

                address: DNTokenAddress = DNTokenAddress(insn.operand.value)

                # record call to destination method; note: we only consider MethodDef methods for destinations
                dest: Optional[FunctionHandle] = methods.get(address, None)
                if dest is not None:
                    dest.ctx["calls_to"].add(fh.address)

                # record call from source method; note: we record all unique calls from a MethodDef method, not just
                # those calls to other MethodDef methods e.g. calls to imported MemberRef methods
                fh.ctx["calls_from"].add(address)

        yield from methods.values()

    def extract_function_features(self, fh) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.dnfile.function.extract_features(fh)

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
