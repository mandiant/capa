import sys
import types

import idaapi

import capa.features.extractors.ida.file
import capa.features.extractors.ida.insn
import capa.features.extractors.ida.function
import capa.features.extractors.ida.basicblock

from capa.features.extractors import FeatureExtractor


def get_va(self):
    if isinstance(self, idaapi.BasicBlock):
        return self.start_ea

    if isinstance(self, idaapi.func_t):
        return self.start_ea

    if isinstance(self, idaapi.insn_t):
        return self.ea

    raise TypeError


def add_va_int_cast(o):
    """
    dynamically add a cast-to-int (`__int__`) method to the given object
    that returns the value of the `.va` property.
    this bit of skullduggery lets use cast viv-utils objects as ints.
    the correct way of doing this is to update viv-utils (or subclass the objects here).
    """

    if sys.version_info >= (3, 0):
        setattr(o, "__int__", types.MethodType(get_va, o))
    else:
        setattr(o, "__int__", types.MethodType(get_va, o, type(o)))
    return o


class IdaFeatureExtractor(FeatureExtractor):
    def __init__(self):
        super(IdaFeatureExtractor, self).__init__()

    def get_base_address(self):
        return idaapi.get_imagebase()

    def extract_file_features(self):
        for feature, va in capa.features.extractors.ida.file.extract_features():
            yield feature, va

    def get_functions(self):
        import capa.features.extractors.ida.helpers as ida_helpers
        for f in ida_helpers.get_functions(ignore_thunks=True, ignore_libs=True):
            yield add_va_int_cast(f)

    def extract_function_features(self, f):
        for feature, va in capa.features.extractors.ida.function.extract_features(f):
            yield feature, va

    def get_basic_blocks(self, f):
        for bb in idaapi.FlowChart(f, flags=idaapi.FC_PREDS):
            yield add_va_int_cast(bb)

    def extract_basic_block_features(self, f, bb):
        for feature, va in capa.features.extractors.ida.basicblock.extract_features(f, bb):
            yield feature, va

    def get_instructions(self, f, bb):
        import capa.features.extractors.ida.helpers as ida_helpers
        for insn in ida_helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
            yield add_va_int_cast(insn)

    def extract_insn_features(self, f, bb, insn):
        for feature, va in capa.features.extractors.ida.insn.extract_features(f, bb, insn):
            yield feature, va
