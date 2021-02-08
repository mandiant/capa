# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import types

import viv_utils

import capa.features.extractors
import capa.features.extractors.viv.file
import capa.features.extractors.viv.insn
import capa.features.extractors.viv.function
import capa.features.extractors.viv.basicblock
from capa.features.extractors import FeatureExtractor

__all__ = ["file", "function", "basicblock", "insn"]


def get_va(self):
    try:
        # vivisect type
        return self.va
    except AttributeError:
        pass

    raise TypeError()


def add_va_int_cast(o):
    """
    dynamically add a cast-to-int (`__int__`) method to the given object
    that returns the value of the `.va` property.

    this bit of skullduggery lets use cast viv-utils objects as ints.
    the correct way of doing this is to update viv-utils (or subclass the objects here).
    """
    setattr(o, "__int__", types.MethodType(get_va, o))
    return o


class VivisectFeatureExtractor(FeatureExtractor):
    def __init__(self, vw, path):
        super(VivisectFeatureExtractor, self).__init__()
        self.vw = vw
        self.path = path

    def get_base_address(self):
        # assume there is only one file loaded into the vw
        return list(self.vw.filemeta.values())[0]["imagebase"]

    def extract_file_features(self):
        for feature, va in capa.features.extractors.viv.file.extract_features(self.vw, self.path):
            yield feature, va

    def get_functions(self):
        for va in sorted(self.vw.getFunctions()):
            yield add_va_int_cast(viv_utils.Function(self.vw, va))

    def extract_function_features(self, f):
        for feature, va in capa.features.extractors.viv.function.extract_features(f):
            yield feature, va

    def get_basic_blocks(self, f):
        for bb in f.basic_blocks:
            yield add_va_int_cast(bb)

    def extract_basic_block_features(self, f, bb):
        for feature, va in capa.features.extractors.viv.basicblock.extract_features(f, bb):
            yield feature, va

    def get_instructions(self, f, bb):
        for insn in bb.instructions:
            yield add_va_int_cast(insn)

    def extract_insn_features(self, f, bb, insn):
        for feature, va in capa.features.extractors.viv.insn.extract_features(f, bb, insn):
            yield feature, va
