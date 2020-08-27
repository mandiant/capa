# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import types

import idaapi

import capa.features.extractors.ida.file
import capa.features.extractors.ida.insn
import capa.features.extractors.ida.function
import capa.features.extractors.ida.basicblock
from capa.features.extractors import FeatureExtractor


def get_ea(self):
    """ """
    if isinstance(self, (idaapi.BasicBlock, idaapi.func_t)):
        return self.start_ea
    if isinstance(self, idaapi.insn_t):
        return self.ea
    raise TypeError


def add_ea_int_cast(o):
    """
    dynamically add a cast-to-int (`__int__`) method to the given object
    that returns the value of the `.ea` property.
    this bit of skullduggery lets use cast viv-utils objects as ints.
    the correct way of doing this is to update viv-utils (or subclass the objects here).
    """
    if sys.version_info[0] >= 3:
        setattr(o, "__int__", types.MethodType(get_ea, o))
    else:
        setattr(o, "__int__", types.MethodType(get_ea, o, type(o)))
    return o


class IdaFeatureExtractor(FeatureExtractor):
    def __init__(self):
        super(IdaFeatureExtractor, self).__init__()

    def get_base_address(self):
        return idaapi.get_imagebase()

    def extract_file_features(self):
        for (feature, ea) in capa.features.extractors.ida.file.extract_features():
            yield feature, ea

    def get_functions(self):
        import capa.features.extractors.ida.helpers as ida_helpers

        # data structure shared across functions yielded here.
        # useful for caching analysis relevant across a single workspace.
        ctx = {}

        # ignore library functions and thunk functions as identified by IDA
        for f in ida_helpers.get_functions(skip_thunks=True, skip_libs=True):
            setattr(f, "ctx", ctx)
            yield add_ea_int_cast(f)

    @staticmethod
    def get_function(ea):
        f = idaapi.get_func(ea)
        setattr(f, "ctx", {})
        return add_ea_int_cast(f)

    def extract_function_features(self, f):
        for (feature, ea) in capa.features.extractors.ida.function.extract_features(f):
            yield feature, ea

    def get_basic_blocks(self, f):
        for bb in capa.features.extractors.ida.helpers.get_function_blocks(f):
            yield add_ea_int_cast(bb)

    def extract_basic_block_features(self, f, bb):
        for (feature, ea) in capa.features.extractors.ida.basicblock.extract_features(f, bb):
            yield feature, ea

    def get_instructions(self, f, bb):
        import capa.features.extractors.ida.helpers as ida_helpers

        for insn in ida_helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
            yield add_ea_int_cast(insn)

    def extract_insn_features(self, f, bb, insn):
        for (feature, ea) in capa.features.extractors.ida.insn.extract_features(f, bb, insn):
            yield feature, ea
