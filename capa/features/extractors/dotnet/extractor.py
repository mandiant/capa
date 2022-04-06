from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dnfile import dnPE

import dncil
import dnfile

import capa.features.extractors.dotnet.file
import capa.features.extractors.dotnet.insn
import capa.features.extractors.dotnet.function

from capa.features.extractors.dotnet import get_dotnet_methods
from capa.features.extractors.base_extractor import FeatureExtractor


class DnfileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super(DnfileFeatureExtractor, self).__init__()
        self.global_features = []

        self.pe: dnPE = dnfile.dnPE(path)

    def get_base_address(self):
        raise NotImplementedError()

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        raise NotImplementedError()

    def get_functions(self):
        ctx = {}
        ctx["pe"] = self.pe

        for method in get_dotnet_methods(self.pe):
            setattr(method, "ctx", ctx)
            yield method

    def extract_function_features(self, f):
        raise NotImplementedError()

    def get_basic_blocks(self, f):
        # we don't support basic blocks for dotnet and treat each method as one large basic block
        return f

    def extract_basic_block_features(self, f, bb):
        # we don't support basic block features for dotnet
        return

    def get_instructions(self, f, bb):
        # we don't support basic blocks for dotnet and treat each method as one large basic block
        yield from f.instructions

    def extract_insn_features(self, f, bb, insn):
        yield from capa.features.extractors.dotnet.insn.extract_features(f, bb, insn)