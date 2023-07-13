# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import List, Tuple

import ghidra

import capa.features.extractors.ghidra.global_
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import FeatureExtractor

currentProgram: ghidra.program.database.ProgramDB


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
