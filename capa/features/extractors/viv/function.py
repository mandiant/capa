# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Iterator, cast

import envi
import viv_utils
import vivisect.const

from capa.features.file import FunctionName
from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.viv.helpers import get_elf_symbol_functions
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_symtab_names(
    fh: FunctionHandle,
) -> Iterator[tuple[Feature, Address]]:
    if fh.inner.vw.metadata["Format"] == "elf":
        # index the symbol table once and cache it, to avoid rescanning it for each function.
        if "elf_symbol_functions" not in fh.ctx["cache"]:
            fh.ctx["cache"]["elf_symbol_functions"] = get_elf_symbol_functions(fh.inner.vw.parsedbin)

        funcs = fh.ctx["cache"]["elf_symbol_functions"]
        for sym_name in funcs.get(fh.address, ()):
            yield FunctionName(sym_name), fh.address


def extract_function_calls_to(fhandle: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    f: viv_utils.Function = fhandle.inner
    for src, _, _, _ in f.vw.getXrefsTo(f.va, rtype=vivisect.const.REF_CODE):
        yield Characteristic("calls to"), AbsoluteVirtualAddress(src)


def extract_function_loop(fhandle: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    """
    parse if a function has a loop
    """
    f: viv_utils.Function = fhandle.inner

    edges = []

    basic_blocks = cast(list[viv_utils.BasicBlock], f.basic_blocks)
    assert isinstance(basic_blocks, list)
    for bb in basic_blocks:
        instructions = cast(list[envi.Opcode], bb.instructions)
        assert isinstance(instructions, list)
        if len(instructions) > 0:
            for bva, bflags in instructions[-1].getBranches():  # type: ignore  # getBranches returns () in base; overridden at runtime
                if bva is None:
                    # vivisect may be unable to recover the call target, e.g. on dynamic calls like `call esi`
                    # for this bva is None, and we don't want to add it for loop detection, ref: vivisect#574
                    continue
                # vivisect does not set branch flags for non-conditional jmp so add explicit check
                if (
                    bflags & envi.BR_COND
                    or bflags & envi.BR_FALL
                    or bflags & envi.BR_TABLE
                    or instructions[-1].mnem == "jmp"
                ):
                    edges.append((bb.va, bva))

    if edges and loops.has_loop(edges):
        yield Characteristic("loop"), fhandle.address


def extract_features(fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
    """
    extract features from the given function.

    args:
      fh: the function handle from which to extract features

    yields:
      tuple[Feature, int]: the features and their location found in this function.
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(fh):
            yield feature, addr


FUNCTION_HANDLERS = (
    extract_function_symtab_names,
    extract_function_calls_to,
    extract_function_loop,
)
