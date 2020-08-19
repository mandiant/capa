# Copyright (C) 2020 FireEye, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: https://github.com/fireeye/capa/blob/master/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import miasm.analysis.binary

import capa.features.extractors.miasm.file
from capa.features.extractors import FeatureExtractor


class MiasmFeatureExtractor(FeatureExtractor):
    def __init__(self, buf):
        super(MiasmFeatureExtractor, self).__init__()
        self.buf = buf
        self.container = miasm.analysis.binary.Container.from_string(buf)
        self.pe = self.container.executable

    def get_base_address(self):
        return self.container.entry_point

    def extract_file_features(self):
        for feature, va in capa.features.extractors.miasm.file.extract_file_features(self.buf, self.pe):
            yield feature, va

    def get_functions(self):
        raise NotImplementedError()

    def extract_function_features(self, f):
        raise NotImplementedError()

    def get_basic_blocks(self, f):
        raise NotImplementedError()

    def extract_basic_block_features(self, f, bb):
        raise NotImplementedError()

    def get_instructions(self, f, bb):
        raise NotImplementedError()

    def extract_insn_features(self, f, bb, insn):
        raise NotImplementedError()
