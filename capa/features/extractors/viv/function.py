# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import vivisect.const

from capa.features import Characteristic
from capa.features.extractors import loops


def interface_extract_function_XXX(f):
    """
    parse features from the given function.

    args:
      f (viv_utils.Function): the function to process.

    yields:
      (Feature, int): the feature and the address at which its found.
    """
    yield NotImplementedError("feature"), NotImplementedError("virtual address")


def get_switches(vw):
    """
    caching accessor to vivisect workspace switch constructs.
    """
    if "switches" in vw.metadata:
        return vw.metadata["switches"]
    else:
        # addresses of switches in the program
        switches = set()

        for case_va, _ in filter(lambda t: "case" in t[1], vw.getNames()):
            # assume that the xref to a case location is a switch construct
            for switch_va, _, _, _ in vw.getXrefsTo(case_va):
                switches.add(switch_va)

        vw.metadata["switches"] = switches
        return switches


def get_functions_with_switch(vw):
    if "functions_with_switch" in vw.metadata:
        return vw.metadata["functions_with_switch"]
    else:
        functions = set()
        for switch in get_switches(vw):
            functions.add(vw.getFunction(switch))
        vw.metadata["functions_with_switch"] = functions
        return functions


def extract_function_switch(f):
    """
    parse if a function contains a switch statement based on location names
    method can be optimized
    """
    if f.va in get_functions_with_switch(f.vw):
        yield Characteristic("switch"), f.va


def extract_function_calls_to(f):
    for src, _, _, _ in f.vw.getXrefsTo(f.va, rtype=vivisect.const.REF_CODE):
        yield Characteristic("calls to"), src


def extract_function_loop(f):
    """
    parse if a function has a loop
    """
    edges = []

    for bb in f.basic_blocks:
        if len(bb.instructions) > 0:
            for bva, bflags in bb.instructions[-1].getBranches():
                # vivisect does not set branch flags for non-conditional jmp so add explicit check
                if bflags & vivisect.envi.BR_COND or bflags & vivisect.envi.BR_FALL or bflags & vivisect.envi.BR_TABLE \
                        or bb.instructions[-1].mnem == "jmp":
                    edges.append((bb.va, bva))

    if edges and loops.has_loop(edges):
        yield Characteristic("loop"), f.va


def extract_features(f):
    """
    extract features from the given function.

    args:
      f (viv_utils.Function): the function from which to extract features

    yields:
      Feature, set[VA]: the features and their location found in this function.
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, va in func_handler(f):
            yield feature, va


FUNCTION_HANDLERS = (extract_function_switch, extract_function_calls_to, extract_function_loop)
