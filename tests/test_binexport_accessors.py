# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Any, Dict

from google.protobuf.json_format import ParseDict

from capa.features.extractors.binexport2.helpers import (
    get_operand_expressions,
    get_instruction_mnemonic,
    get_instruction_operands,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)

"""
mov     x0, 0x20
bl      0x100
add     x0, sp, 0x10

# not here yet ldr     x0, [x1, 8]
"""

BE2_DICT: Dict[str, Any] = {
    "expression": [
        {"type": 1, "symbol": "x0"},
        {"type": 2, "immediate": 0x20},
        {"type": 3, "immediate": 0x100},
        {"type": 1, "symbol": "sp"},
        {"type": 3, "immediate": 0x10},
    ],
    # operand consists of 1 or more expressions, linked together as a tree
    "operand": [
        {"expression_index": [0]},
        {"expression_index": [1]},
        {"expression_index": [2]},
        {"expression_index": [3]},
        {"expression_index": [4]},
    ],
    "mnemonic": [
        {"name": "mov"},  # mnem 0
        {"name": "bl"},  # mnem 1
        {"name": "add"},  # mnem 2
    ],
    # instruction may have 0 or more operands
    "instruction": [
        {"mnemonic_index": 0, "operand_index": [0, 1]},
        {"mnemonic_index": 1, "operand_index": [2]},
        {"mnemonic_index": 2, "operand_index": [0, 3, 4]},
    ],
}
BE2 = ParseDict(
    BE2_DICT,
    BinExport2(),
)


def test_get_instruction_mnemonic():
    mov = ParseDict(BE2_DICT["instruction"][0], BinExport2.Instruction())
    call = ParseDict(BE2_DICT["instruction"][1], BinExport2.Instruction())

    assert get_instruction_mnemonic(BE2, mov) == "mov"
    assert get_instruction_mnemonic(BE2, call) == "bl"


def test_get_instruction_operands():
    insn = ParseDict(BE2_DICT["instruction"][2], BinExport2.Instruction())

    assert len(get_instruction_operands(BE2, insn)) == 3


def test_get_operand_expressions():
    oper = ParseDict(BE2_DICT["operand"][0], BinExport2.Operand())

    assert len(get_operand_expressions(BE2, oper)) == 1
