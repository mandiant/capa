# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Tuple, Iterator

import envi
import viv_utils
import vivisect.const

from capa.features.file import FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.elf import SymTab
from capa.features.extractors.base_extractor import FunctionHandle


def interface_extract_function_XXX(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse features from the given function.

    args:
      f: the function to process.

    yields:
      (Feature, Address): the feature and the address at which its found.
    """
    raise NotImplementedError


def extract_function_symtab_names(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    if fh.inner.vw.metadata["Format"] == "elf":
        # the file's symbol table gets added to the metadata of the vivisect workspace.
        # this is in order to eliminate the computational overhead of refetching symtab each time.
        if "symtab" not in fh.ctx["cache"]:
            try:
                fh.ctx["cache"]["symtab"] = SymTab.from_viv(fh.inner.vw.parsedbin)
            except Exception:
                fh.ctx["cache"]["symtab"] = None

        symtab = fh.ctx["cache"]["symtab"]
        if symtab:
            for symbol in symtab.get_symbols():
                sym_name = symtab.get_name(symbol)
                sym_value = symbol.value
                sym_info = symbol.info

                STT_FUNC = 0x2
                if sym_value == fh.address and sym_info & STT_FUNC != 0:
                    yield FunctionName(sym_name), fh.address


def extract_function_calls_to(fhandle: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    f: viv_utils.Function = fhandle.inner
    for src, _, _, _ in f.vw.getXrefsTo(f.va, rtype=vivisect.const.REF_CODE):
        yield Characteristic("calls to"), AbsoluteVirtualAddress(src)


def extract_function_loop(fhandle: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse if a function has a loop
    """
    f: viv_utils.Function = fhandle.inner

    edges = []

    for bb in f.basic_blocks:
        if len(bb.instructions) > 0:
            for bva, bflags in bb.instructions[-1].getBranches():
                if bva is None:
                    # vivisect may be unable to recover the call target, e.g. on dynamic calls like `call esi`
                    # for this bva is None, and we don't want to add it for loop detection, ref: vivisect#574
                    continue
                # vivisect does not set branch flags for non-conditional jmp so add explicit check
                if (
                    bflags & envi.BR_COND
                    or bflags & envi.BR_FALL
                    or bflags & envi.BR_TABLE
                    or bb.instructions[-1].mnem == "jmp"
                ):
                    edges.append((bb.va, bva))

    if edges and loops.has_loop(edges):
        yield Characteristic("loop"), fhandle.address


def extract_features(fh: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    extract features from the given function.

    args:
      fh: the function handle from which to extract features

    yields:
      Tuple[Feature, int]: the features and their location found in this function.
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (
    extract_function_symtab_names,
    extract_function_calls_to,
    extract_function_loop,
)
