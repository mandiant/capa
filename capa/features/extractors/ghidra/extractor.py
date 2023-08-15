# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import List, Tuple, Iterator

import capa.features.extractors.ghidra.file
import capa.features.extractors.ghidra.insn
import capa.features.extractors.ghidra.global_
import capa.features.extractors.ghidra.function
import capa.features.extractors.ghidra.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, FeatureExtractor

currentProgram = currentProgram()  # type: ignore # noqa: F821
currentAddress = currentAddress()  # type: ignore # noqa: F821


class GhidraFeatureExtractor(FeatureExtractor):
    def __init__(self):
        super().__init__()
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.ghidra.file.extract_file_format())
        self.global_features.extend(capa.features.extractors.ghidra.global_.extract_os())
        self.global_features.extend(capa.features.extractors.ghidra.global_.extract_arch())

    def get_base_address(self):
        return AbsoluteVirtualAddress(currentProgram.getImageBase().getOffset())  # type: ignore [name-defined] # noqa: F821

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.ghidra.file.extract_features()

    def get_functions(self) -> Iterator[FunctionHandle]:
        import capa.features.extractors.ghidra.helpers as ghidra_helpers

        yield from ghidra_helpers.get_function_symbols()

    @staticmethod
    def get_function(addr: int) -> FunctionHandle:
        get_addr = currentAddress.getAddress(hex(addr))  # type: ignore [name-defined] # noqa: F821
        func = getFunctionContaining(get_addr)  # type: ignore [name-defined] # noqa: F821
        return FunctionHandle(address=AbsoluteVirtualAddress(func.getAddress().getOffset()), inner=func)

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ghidra.function.extract_features(fh)

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        import capa.features.extractors.ghidra.helpers as ghidra_helpers

        yield from ghidra_helpers.get_function_blocks(fh)

    def extract_basic_block_features(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ghidra.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        import capa.features.extractors.ghidra.helpers as ghidra_helpers

        yield from ghidra_helpers.get_insn_in_range(bbh)

    def extract_insn_features(self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle):
        yield from capa.features.extractors.ghidra.insn.extract_features(fh, bbh, ih)
