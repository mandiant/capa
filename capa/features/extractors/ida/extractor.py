# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Iterator

import idaapi

import capa.ida.helpers
import capa.features.extractors.elf
import capa.features.extractors.ida.file
import capa.features.extractors.ida.insn
import capa.features.extractors.ida.global_
import capa.features.extractors.ida.function
import capa.features.extractors.ida.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)


class IdaFeatureExtractor(StaticFeatureExtractor):
    def __init__(self):
        super().__init__(
            hashes=SampleHashes(
                md5=capa.ida.helpers.retrieve_input_file_md5(),
                sha1="(unknown)",
                sha256=capa.ida.helpers.retrieve_input_file_sha256(),
            )
        )
        self.global_features: list[tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.ida.file.extract_file_format())
        self.global_features.extend(capa.features.extractors.ida.global_.extract_os())
        self.global_features.extend(capa.features.extractors.ida.global_.extract_arch())

    def get_base_address(self):
        return AbsoluteVirtualAddress(idaapi.get_imagebase())

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.ida.file.extract_features()

    def get_functions(self) -> Iterator[FunctionHandle]:
        import capa.features.extractors.ida.helpers as ida_helpers

        # ignore library functions and thunk functions as identified by IDA
        yield from ida_helpers.get_functions(skip_thunks=True, skip_libs=True)

    @staticmethod
    def get_function(ea: int) -> FunctionHandle:
        f = idaapi.get_func(ea)
        return FunctionHandle(address=AbsoluteVirtualAddress(f.start_ea), inner=f)

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.ida.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        import capa.features.extractors.ida.helpers as ida_helpers

        for bb in ida_helpers.get_function_blocks(fh.inner):
            yield BBHandle(address=AbsoluteVirtualAddress(bb.start_ea), inner=bb)

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.ida.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        import capa.features.extractors.ida.helpers as ida_helpers

        for insn in ida_helpers.get_instructions_in_range(bbh.inner.start_ea, bbh.inner.end_ea):
            yield InsnHandle(address=AbsoluteVirtualAddress(insn.ea), inner=insn)

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.ida.insn.extract_features(fh, bbh, ih)
