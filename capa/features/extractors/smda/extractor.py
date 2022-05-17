from typing import List, Tuple

from smda.common.SmdaReport import SmdaReport

import capa.features.extractors.common
import capa.features.extractors.smda.file
import capa.features.extractors.smda.insn
import capa.features.extractors.smda.global_
import capa.features.extractors.smda.function
import capa.features.extractors.smda.basicblock
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class SmdaFeatureExtractor(FeatureExtractor):
    def __init__(self, smda_report: SmdaReport, path):
        super(SmdaFeatureExtractor, self).__init__()
        self.smda_report = smda_report
        self.path = path
        with open(self.path, "rb") as f:
            self.buf = f.read()

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(capa.features.extractors.common.extract_os(self.buf))
        self.global_features.extend(capa.features.extractors.smda.global_.extract_arch(self.smda_report))

    def get_base_address(self):
        return AbsoluteVirtualAddress(self.smda_report.base_addr)

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.smda.file.extract_features(self.smda_report, self.buf)

    def get_functions(self):
        for function in self.smda_report.getFunctions():
            yield FunctionHandle(address=AbsoluteVirtualAddress(function.offset), inner=function)

    def extract_function_features(self, fh):
        yield from capa.features.extractors.smda.function.extract_features(fh)

    def get_basic_blocks(self, fh):
        for bb in fh.inner.getBlocks():
            yield BBHandle(address=AbsoluteVirtualAddress(bb.offset), inner=bb)

    def extract_basic_block_features(self, fh, bbh):
        yield from capa.features.extractors.smda.basicblock.extract_features(fh, bbh)

    def get_instructions(self, fh, bbh):
        for smda_ins in bbh.inner.getInstructions():
            yield InsnHandle(address=AbsoluteVirtualAddress(smda_ins.offset), inner=smda_ins)

    def extract_insn_features(self, fh, bbh, ih):
        yield from capa.features.extractors.smda.insn.extract_features(fh, bbh, ih)
