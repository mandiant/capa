# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import re
from typing import List, Callable
from dataclasses import dataclass

from binaryninja import BinaryView, LowLevelILInstruction
from binaryninja.architecture import InstructionTextToken


@dataclass
class DisassemblyInstruction:
    address: int
    length: int
    text: List[InstructionTextToken]


LLIL_VISITOR = Callable[[LowLevelILInstruction, LowLevelILInstruction, int], bool]


def visit_llil_exprs(il: LowLevelILInstruction, func: LLIL_VISITOR):
    # BN does not really support operand index at the disassembly level, so use the LLIL operand index as a substitute.
    # Note, this is NOT always guaranteed to be the same as disassembly operand.
    for i, op in enumerate(il.operands):
        if isinstance(op, LowLevelILInstruction) and func(op, il, i):
            visit_llil_exprs(op, func)


def unmangle_c_name(name: str) -> str:
    # https://learn.microsoft.com/en-us/cpp/build/reference/decorated-names?view=msvc-170#FormatC
    # Possible variations for BaseThreadInitThunk:
    # @BaseThreadInitThunk@12
    # _BaseThreadInitThunk
    # _BaseThreadInitThunk@12
    # It is also possible for a function to have a `Stub` appended to its name:
    # _lstrlenWStub@4

    # A small optimization to avoid running the regex too many times
    # this still increases the unit test execution time from 170s to 200s, should be able to accelerate it
    #
    # TODO(xusheng): performance optimizations to improve test execution time
    # https://github.com/mandiant/capa/issues/1610
    if name[0] in ["@", "_"]:
        match = re.match(r"^[@|_](.*?)(Stub)?(@\d+)?$", name)
        if match:
            return match.group(1)

    return name


def read_c_string(bv: BinaryView, offset: int, max_len: int) -> str:
    s: List[str] = []
    while len(s) < max_len:
        try:
            c = bv.read(offset + len(s), 1)[0]
        except Exception:
            break

        if c == 0:
            break

        s.append(chr(c))

    return "".join(s)
