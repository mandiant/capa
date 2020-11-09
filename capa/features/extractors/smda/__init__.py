import sys
import types

from smda.common.SmdaReport import SmdaReport
from smda.common.SmdaInstruction import SmdaInstruction

import capa.features.extractors.smda.file
import capa.features.extractors.smda.insn
import capa.features.extractors.smda.function
import capa.features.extractors.smda.basicblock
from capa.main import UnsupportedRuntimeError
from capa.features.extractors import FeatureExtractor


class SmdaFeatureExtractor(FeatureExtractor):
    def __init__(self, smda_report: SmdaReport, path):
        super(SmdaFeatureExtractor, self).__init__()
        if sys.version_info < (3, 0):
            raise UnsupportedRuntimeError("SMDA should only be used with Python 3.")
        self.smda_report = smda_report
        self.path = path

    def get_base_address(self):
        return self.smda_report.base_addr

    def extract_file_features(self):
        for feature, va in capa.features.extractors.smda.file.extract_features(self.smda_report, self.path):
            yield feature, va

    def get_functions(self):
        for function in self.smda_report.getFunctions():
            yield function

    def extract_function_features(self, f):
        for feature, va in capa.features.extractors.smda.function.extract_features(f):
            yield feature, va

    def get_basic_blocks(self, f):
        for bb in f.getBlocks():
            yield bb

    def extract_basic_block_features(self, f, bb):
        for feature, va in capa.features.extractors.smda.basicblock.extract_features(f, bb):
            yield feature, va

    def get_instructions(self, f, bb):
        for smda_ins in bb.getInstructions():
            yield smda_ins

    def extract_insn_features(self, f, bb, insn):
        for feature, va in capa.features.extractors.smda.insn.extract_features(f, bb, insn):
            yield feature, va
