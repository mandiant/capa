# Copyright 2023 Google LLC
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

import weakref
import contextlib
from typing import Iterator

import capa.features.extractors.ghidra.file
import capa.features.extractors.ghidra.insn
import capa.features.extractors.ghidra.global_
import capa.features.extractors.ghidra.helpers as ghidra_helpers
import capa.features.extractors.ghidra.function
import capa.features.extractors.ghidra.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)


class GhidraFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, ctx_manager=None, tmpdir=None):
        self.ctx_manager = ctx_manager
        self.tmpdir = tmpdir

        super().__init__(
            SampleHashes(
                md5=ghidra_helpers.get_current_program().getExecutableMD5(),
                # ghidra doesn't expose this hash.
                # https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
                #
                # the hashes are stored in the database, not computed on the fly,
                # so it's probably not trivial to add SHA1.
                sha1="",
                sha256=ghidra_helpers.get_current_program().getExecutableSHA256(),
            )
        )

        self.global_features: list[tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.ghidra.file.extract_file_format())
        self.global_features.extend(capa.features.extractors.ghidra.global_.extract_os())
        self.global_features.extend(capa.features.extractors.ghidra.global_.extract_arch())
        self.imports = ghidra_helpers.get_file_imports()
        self.externs = ghidra_helpers.get_file_externs()
        self.fakes = ghidra_helpers.map_fake_import_addrs()

        # Register cleanup to run when the extractor is garbage collected or when the program exits.
        # We use weakref.finalize instead of __del__ to avoid issues with reference cycles and
        # to ensure deterministic cleanup on interpreter shutdown.
        if self.ctx_manager or self.tmpdir:
            weakref.finalize(self, cleanup, self.ctx_manager, self.tmpdir)

    def get_base_address(self):
        return AbsoluteVirtualAddress(ghidra_helpers.get_current_program().getImageBase().getOffset())

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.ghidra.file.extract_features()

    def get_functions(self) -> Iterator[FunctionHandle]:

        for fhandle in ghidra_helpers.get_function_symbols():
            fh: FunctionHandle = FunctionHandle(
                address=AbsoluteVirtualAddress(fhandle.getEntryPoint().getOffset()),
                inner=fhandle,
                ctx={"imports_cache": self.imports, "externs_cache": self.externs, "fakes_cache": self.fakes},
            )
            yield fh

    @staticmethod
    def get_function(addr: int) -> FunctionHandle:

        func = ghidra_helpers.get_flat_api().getFunctionContaining(ghidra_helpers.get_flat_api().toAddr(addr))
        return FunctionHandle(address=AbsoluteVirtualAddress(func.getEntryPoint().getOffset()), inner=func)

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.ghidra.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:

        yield from ghidra_helpers.get_function_blocks(fh)

    def get_next_basic_blocks(self, bb: BBHandle):
        # not implemented yet
        return []

    def get_basic_block_size(self, bb: BBHandle):
        # not implemented yet
        return 0

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.ghidra.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:

        yield from ghidra_helpers.get_insn_in_range(bbh)

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.ghidra.insn.extract_features(fh, bbh, ih)


def cleanup(ctx_manager, tmpdir):
    if ctx_manager:
        with contextlib.suppress(Exception):
            ctx_manager.__exit__(None, None, None)
    if tmpdir:
        with contextlib.suppress(Exception):
            tmpdir.cleanup()
