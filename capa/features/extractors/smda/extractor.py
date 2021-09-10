from smda.common.SmdaReport import SmdaReport

import capa.features.extractors.common
import capa.features.extractors.smda.file
import capa.features.extractors.smda.insn
import capa.features.extractors.smda.global_
import capa.features.extractors.smda.function
import capa.features.extractors.smda.basicblock
from capa.features.extractors.base_extractor import FeatureExtractor


class SmdaFeatureExtractor(FeatureExtractor):
    def __init__(self, smda_report: SmdaReport, path):
        super(SmdaFeatureExtractor, self).__init__()
        self.smda_report = smda_report
        self.path = path
        with open(self.path, "rb") as f:
            self.buf = f.read()

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features = []
        self.global_features.extend(capa.features.extractors.common.extract_os(self.buf))
        self.global_features.extend(capa.features.extractors.smda.global_.extract_arch(self.smda_report))

    def get_base_address(self):
        return self.smda_report.base_addr

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.smda.file.extract_features(self.smda_report, self.buf)

    def get_functions(self):
        for function in self.smda_report.getFunctions():
            yield function

    def extract_function_features(self, f):
        yield from capa.features.extractors.smda.function.extract_features(f)

    def get_basic_blocks(self, f):
        for bb in f.getBlocks():
            yield bb

    def extract_basic_block_features(self, f, bb):
        yield from capa.features.extractors.smda.basicblock.extract_features(f, bb)

    def get_instructions(self, f, bb):
        for smda_ins in bb.getInstructions():
            yield smda_ins

    def extract_insn_features(self, f, bb, insn):
        yield from capa.features.extractors.smda.insn.extract_features(f, bb, insn)
