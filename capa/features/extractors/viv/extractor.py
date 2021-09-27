# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging

import viv_utils
import viv_utils.flirt

import capa.features.extractors.common
import capa.features.extractors.viv.file
import capa.features.extractors.viv.insn
import capa.features.extractors.viv.global_
import capa.features.extractors.viv.function
import capa.features.extractors.viv.basicblock
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class InstructionHandle:
    """this acts like a vivisect.Opcode but with an __int__() method"""

    def __init__(self, inner):
        self._inner = inner

    def __int__(self):
        return self.va

    def __getattr__(self, name):
        return getattr(self._inner, name)


class VivisectFeatureExtractor(FeatureExtractor):
    def __init__(self, vw, path):
        super(VivisectFeatureExtractor, self).__init__()
        self.vw = vw
        self.path = path
        with open(self.path, "rb") as f:
            self.buf = f.read()

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features = []
        self.global_features.extend(capa.features.extractors.common.extract_os(self.buf))
        self.global_features.extend(capa.features.extractors.viv.global_.extract_arch(self.vw))

    def get_base_address(self):
        # assume there is only one file loaded into the vw
        return list(self.vw.filemeta.values())[0]["imagebase"]

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self):
        yield from capa.features.extractors.viv.file.extract_features(self.vw, self.buf)

    def get_functions(self):
        for va in sorted(self.vw.getFunctions()):
            yield viv_utils.Function(self.vw, va)

    def extract_function_features(self, f):
        yield from capa.features.extractors.viv.function.extract_features(f)

    def get_basic_blocks(self, f):
        return f.basic_blocks

    def extract_basic_block_features(self, f, bb):
        yield from capa.features.extractors.viv.basicblock.extract_features(f, bb)

    def get_instructions(self, f, bb):
        for insn in bb.instructions:
            yield InstructionHandle(insn)

    def extract_insn_features(self, f, bb, insn):
        yield from capa.features.extractors.viv.insn.extract_features(f, bb, insn)

    def is_library_function(self, va):
        return viv_utils.flirt.is_library_function(self.vw, va)

    def get_function_name(self, va):
        return viv_utils.get_function_name(self.vw, va)
