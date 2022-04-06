from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Tuple

if TYPE_CHECKING:
    from capa.features.common import Feature

import dnfile

import capa.features.extractors
import capa.features.extractors.dotnet.file
import capa.features.extractors.dotnet.insn
from capa.features.extractors.base_extractor import FeatureExtractor
from capa.features.extractors.dotnet.helpers import get_dotnet_methods


class DnfileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super(DnfileFeatureExtractor, self).__init__()
        self.pe: dnfile.dnPE = dnfile.dnPE(path)

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features: List[Tuple[Feature, int]] = []
        self.global_features.extend(capa.features.extractors.dnfile_.extract_file_os(pe=self.pe))
        self.global_features.extend(capa.features.extractors.dnfile_.extract_file_arch(pe=self.pe))

    def get_base_address(self):
        return 0x0

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.dotnet.file.extract_features(self.pe)

    def get_functions(self):
        ctx = {}
        ctx["pe"] = self.pe

        for f in get_dotnet_methods(self.pe):
            setattr(f, "ctx", ctx)
            yield f

    def extract_function_features(self, f):
        # TODO
        yield from []

    def get_basic_blocks(self, f):
        # each dotnet method is considered 1 basic block
        yield f

    def extract_basic_block_features(self, f, bb):
        # we don't support basic block features
        yield from []

    def get_instructions(self, f, bb):
        # each dotnet method is considered 1 basic block
        yield from f.instructions

    def extract_insn_features(self, f, bb, insn):
        yield from capa.features.extractors.dotnet.insn.extract_features(f, bb, insn)
