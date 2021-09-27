# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import envi
import vivisect.const

from capa.features.common import Characteristic
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
                if (
                    bflags & envi.BR_COND
                    or bflags & envi.BR_FALL
                    or bflags & envi.BR_TABLE
                    or bb.instructions[-1].mnem == "jmp"
                ):
                    edges.append((bb.va, bva))

    if edges and loops.has_loop(edges):
        yield Characteristic("loop"), f.va


def extract_features(f):
    """
    extract features from the given function.

    args:
      f (viv_utils.Function): the function from which to extract features

    yields:
      Tuple[Feature, int]: the features and their location found in this function.
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, va in func_handler(f):
            yield feature, va


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop)
