import logging
import contextlib
from typing import List, Tuple, Iterator

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
        return AbsoluteVirtualAddress(currentProgram.getImageBase().getOffset())

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.ghidra.file.extract_features()
