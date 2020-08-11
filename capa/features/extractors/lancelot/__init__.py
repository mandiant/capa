# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging

import lancelot

import capa.features.extractors
import capa.features.extractors.lancelot.file
import capa.features.extractors.lancelot.insn
import capa.features.extractors.lancelot.function
import capa.features.extractors.lancelot.basicblock

__all__ = ["file", "function", "basicblock", "insn"]
logger = logging.getLogger(__name__)


class BB(object):
    """extend the lancelot.BasicBlock with an __int__ method to access the address"""

    def __init__(self, ws, bb):
        super(BB, self).__init__()
        self.ws = ws
        self.address = bb.address
        self.length = bb.length
        self.predecessors = bb.predecessors
        self.successors = bb.successors

    def __int__(self):
        return self.address

    @property
    def instructions(self):
        va = self.address
        while va < self.address + self.length:
            try:
                insn = self.ws.read_insn(va)
            except ValueError:
                logger.warning("failed to read instruction at 0x%x", va)
                return

            yield insn
            va += insn.length


class LancelotFeatureExtractor(capa.features.extractors.FeatureExtractor):
    def __init__(self, buf):
        super(LancelotFeatureExtractor, self).__init__()
        self.buf = buf
        self.ws = lancelot.from_bytes(buf)
        self.ctx = {}

    def get_base_address(self):
        return self.ws.base_address

    def extract_file_features(self):
        for feature, va in capa.features.extractors.lancelot.file.extract_file_features(self.buf):
            yield feature, va

    def get_functions(self):
        for va in self.ws.get_functions():
            yield va

    def extract_function_features(self, f):
        for feature, va in capa.features.extractors.lancelot.function.extract_function_features(self.ws, f):
            yield feature, va

    def get_basic_blocks(self, f):
        try:
            cfg = self.ws.build_cfg(f)
        except:
            logger.warning("failed to build CFG for 0x%x", f)
            return
        else:
            for bb in cfg.basic_blocks.values():
                yield BB(self.ws, bb)

    def extract_basic_block_features(self, f, bb):
        for feature, va in capa.features.extractors.lancelot.basicblock.extract_basic_block_features(self.ws, bb):
            yield feature, va

    def get_instructions(self, f, bb):
        return bb.instructions

    def extract_insn_features(self, f, bb, insn):
        for feature, va in capa.features.extractors.lancelot.insn.extract_insn_features(self, f, bb, insn):
            yield feature, va
