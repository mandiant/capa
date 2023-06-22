import logging
import contextlib
from typing import Tuple, Iterator

import capa.features.extractors.ghidra.global_
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import FeatureExtractor


class GhidraFeatureExtractor(FeatureExtractor):
    def __init__(self):
        super().__init__()
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.ghidra.global_.extract_os())
        self.global_features.extend(capa.features.extractors.ghidra.global_.extract_arch())
