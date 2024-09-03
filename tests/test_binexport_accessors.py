# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re
import logging
from typing import Any, Dict
from pathlib import Path

import pytest
import fixtures
from google.protobuf.json_format import ParseDict

from capa.features.extractors.binexport2.helpers import (
    get_operand_expressions,
    get_instruction_mnemonic,
    get_instruction_operands,
    get_operand_register_expression,
    get_operand_immediate_expression,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2
from capa.features.extractors.binexport2.arch.arm.helpers import is_stack_register_expression

logger = logging.getLogger(__name__)

CD = Path(__file__).resolve().parent


# found via https://www.virustotal.com/gui/search/type%253Aelf%2520and%2520size%253A1.2kb%252B%2520and%2520size%253A1.4kb-%2520and%2520tag%253Aarm%2520and%2520not%2520tag%253Arelocatable%2520and%2520tag%253A64bits/files
# Ghidra disassembly of c7f38027552a3eca84e2bfc846ac1307fbf98657545426bb93a2d63555cbb486
GHIDRA_DISASSEMBLY = """
                             //
                             // segment_1
                             // Loadable segment  [0x200000 - 0x200157]
                             // ram:00200000-ram:00200157
                             //
        00200000 7f 45 4c        Elf64_Ehdr
...
                             //
                             // .text
                             // SHT_PROGBITS  [0x210158 - 0x2101c7]
                             // ram:00210158-ram:002101c7
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined entry()
             undefined         w0:1           <RETURN>
                             _start                                          XREF[4]:     Entry Point(*), 00200018(*),
                             entry                                                        002000c0(*),
                                                                                          _elfSectionHeaders::00000050(*)
        00210158 20 00 80 d2     mov        x0,#0x1
        0021015c a1 02 00 58     ldr        x1=>helloWorldStr,DAT_002101b0                   = "Hello World!\n"
                                                                                             = 00000000002201C8h
        00210160 c2 02 00 58     ldr        x2,DAT_002101b8                                  = 000000000000000Eh
        00210164 08 08 80 d2     mov        x8,#0x40
        00210168 01 00 00 d4     svc        0x0
        0021016c a0 02 00 58     ldr        x0=>$stringWith_Weird_Name,DAT_002101c0          = "This string has a very strang
                                                                                             = 00000000002201D6h
        00210170 04 00 00 94     bl         printString                                      undefined printString()
        00210174 60 0f 80 d2     mov        x0,#0x7b
        00210178 a8 0b 80 d2     mov        x8,#0x5d
        0021017c 01 00 00 d4     svc        0x0
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined printString()
             undefined         w0:1           <RETURN>
                             printString                                     XREF[1]:     entry:00210170(c)
        00210180 01 00 80 d2     mov        x1,#0x0
                             strlenLoop                                      XREF[1]:     00210194(j)
        00210184 02 68 61 38     ldrb       w2,[x0, x1, LSL ]
        00210188 5f 00 00 71     cmp        w2,#0x0
        0021018c 60 00 00 54     b.eq       strlenDone
        00210190 21 04 00 91     add        x1,x1,#0x1
        00210194 fc ff ff 17     b          strlenLoop
                             strlenDone                                      XREF[1]:     0021018c(j)
        00210198 e2 03 01 aa     mov        x2,x1
        0021019c e1 03 00 aa     mov        x1,x0
        002101a0 20 00 80 d2     mov        x0,#0x1
        002101a4 08 08 80 d2     mov        x8,#0x40
        002101a8 01 00 00 d4     svc        0x0
        002101ac c0 03 5f d6     ret
                             DAT_002101b0                                    XREF[1]:     entry:0021015c(R)
        002101b0 c8 01 22        undefined8 00000000002201C8h                                ?  ->  002201c8
                 00 00 00
                 00 00
                             DAT_002101b8                                    XREF[1]:     entry:00210160(R)
        002101b8 0e 00 00        undefined8 000000000000000Eh
                 00 00 00
                 00 00
                             DAT_002101c0                                    XREF[1]:     entry:0021016c(R)
        002101c0 d6 01 22        undefined8 00000000002201D6h                                ?  ->  002201d6
                 00 00 00
                 00 00
                             //
                             // .data
                             // SHT_PROGBITS  [0x2201c8 - 0x2201fb]
                             // ram:002201c8-ram:002201fb
                             //
                             helloWorldStr                                   XREF[3]:     002000f8(*), entry:0021015c(*),
                                                                                          _elfSectionHeaders::00000090(*)
        002201c8 48 65 6c        ds         "Hello World!\n"
                 6c 6f 20
                 57 6f 72
                             $stringWith_Weird_Name                          XREF[1]:     entry:0021016c(*)
        002201d6 54 68 69        ds         "This string has a very strange label\n"
                 73 20 73
                 74 72 69
...
"""


def _parse_ghidra_disassembly(disasm: str) -> dict:
    dd = {}
    # 00210158 20 00 80 d2     mov        x0,#0x1
    # ^^^^^^^^ ^^^^^^^^^^^     ^^^        ^^ ^^^^
    # address  bytes           mnemonic   o1,o2  (,o3)
    pattern = re.compile(
        r"^( ){8}(?P<address>[0-9a-f]+) "
        + r"(?P<bytes>([0-9a-f]{2}[ ]){4})\s+"
        + r"(?P<mnemonic>[\w\.]+)\s*"
        + r"(?P<operand1>[\w#$=>]+)?,?"
        + r"((?P<operand2>[\w#$=>]+))?,?"
        + r"((?P<operand3>[\w#$=>]+))?"
    )
    for line in disasm.splitlines()[20:]:
        m = pattern.match(line)
        if m:
            logger.debug("Match found\t%s\n\t\t\t\t%s", line, m.groupdict())
            dd[int(m["address"], 0x10)] = {
                "bytes": m["bytes"].strip(),
                "mnemonic": m["mnemonic"],
                "operands": [e for e in [m["operand1"], m["operand2"], m["operand3"]] if e is not None],
            }
        else:
            logger.debug("No match\t%s", line)
    return dd


BE2_EXTRACTOR = fixtures.get_binexport_extractor(
    CD
    / "data"
    / "binexport2"
    / "c7f38027552a3eca84e2bfc846ac1307fbf98657545426bb93a2d63555cbb486.elf_.ghidra.BinExport"
)
PARSED_DISASM = _parse_ghidra_disassembly(GHIDRA_DISASSEMBLY)


def test_instruction_bytes():
    # more a data sanity check here as we don't test our code
    for addr, de in PARSED_DISASM.items():
        insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
        assert insn.raw_bytes == bytes.fromhex(de["bytes"])


def test_get_instruction_mnemonic():
    for addr, de in PARSED_DISASM.items():
        insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
        assert get_instruction_mnemonic(BE2_EXTRACTOR.be2, insn) == de["mnemonic"]


def test_get_instruction_operands_count():
    for addr, de in PARSED_DISASM.items():
        insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
        ops = get_instruction_operands(BE2_EXTRACTOR.be2, insn)
        # this line is not properly parsed from the Ghidra disassembly using the current regex
        # 00210184 02 68 61 38     ldrb       w2,[x0, x1, LSL ]
        if addr == 0x210184:
            assert len(ops) == 2
        else:
            assert len(ops) == len(de["operands"])


@pytest.mark.parametrize(
    "addr,op_expressions",
    [
        # 00210158 20 00 80 d2     mov        x0,#0x1
        (0x210158, ("x0", "#0x1")),
        # 0021015c a1 02 00 58     ldr        x1=>helloWorldStr,DAT_002101b0
        (0x21015C, ("x1", "DAT_002101b0")),
        # 00210184 02 68 61 38     ldrb       w2,[x0, x1, LSL ]
        (0x210184, ("w2", "[x0, x1, LSL ]")),
        # 00210190 21 04 00 91     add        x1,x1,#0x1
        (0x210190, ("x1", "x1", "#0x1")),
    ],
)
def test_get_operand_expressions(addr, op_expressions):
    insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
    ops = get_instruction_operands(BE2_EXTRACTOR.be2, insn)
    for i, op in enumerate(ops):
        exps = get_operand_expressions(BE2_EXTRACTOR.be2, op)
        assert len(exps) == 1
        assert exps[0].symbol == op_expressions[i]


@pytest.mark.parametrize(
    "addr,reg_expressions",
    [
        # 00210158 20 00 80 d2     mov        x0,#0x1
        (0x210158, ("x0", None)),
        # 0021015c a1 02 00 58     ldr        x1=>helloWorldStr,DAT_002101b0
        (0x21015C, ("x1", None)),
        # 00210184 02 68 61 38     ldrb       w2,[x0, x1, LSL ]
        (0x210184, ("w2", None)),
        # 00210190 21 04 00 91     add        x1,x1,#0x1
        (0x210190, ("x1", "x1", None)),
    ],
)
def _TODO_test_get_operand_register_expression(addr, reg_expressions):
    insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
    ops = get_instruction_operands(BE2_EXTRACTOR.be2, insn)
    for i, op in enumerate(ops):
        reg_exp = get_operand_register_expression(BE2_EXTRACTOR.be2, op)
        logger.debug("%s", get_operand_expressions(BE2_EXTRACTOR.be2, op))
        assert reg_exp == reg_expressions[i]


@pytest.mark.parametrize(
    "addr,expressions",
    [
        # 00210158 20 00 80 d2     mov        x0,#0x1
        (0x210158, (None, 0x1)),
        # 0021015c a1 02 00 58     ldr        x1=>helloWorldStr,DAT_002101b0
        (0x21015C, (None, None)),
        # 00210184 02 68 61 38     ldrb       w2,[x0, x1, LSL ]
        (0x210184, (None, None)),
        # 00210190 21 04 00 91     add        x1,x1,#0x1
        (0x210190, (None, None, 0x1)),
    ],
)
def _TODO_test_get_operand_immediate_expression(addr, expressions):
    insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
    ops = get_instruction_operands(BE2_EXTRACTOR.be2, insn)
    for i, op in enumerate(ops):
        reg_exp = get_operand_immediate_expression(BE2_EXTRACTOR.be2, op)
        logger.debug("%s", get_operand_expressions(BE2_EXTRACTOR.be2, op))
        assert reg_exp == expressions[i]


"""
mov     x0, 0x20
bl      0x100
add     x0, sp, 0x10
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


def _TODO_test_is_stack_register_expression():
    mov = ParseDict(BE2_DICT["instruction"][0], BinExport2.Instruction())
    add = ParseDict(BE2_DICT["instruction"][2], BinExport2.Instruction())

    ops = get_instruction_operands(BE2_EXTRACTOR.be2, mov)
    exps = get_operand_expressions(BE2_EXTRACTOR.be2, ops[0])
    assert is_stack_register_expression(BE2_EXTRACTOR.be2, exps[0]) is False
    exps = get_operand_expressions(BE2_EXTRACTOR.be2, ops[1])
    assert is_stack_register_expression(BE2_EXTRACTOR.be2, exps[0]) is False

    ops = get_instruction_operands(BE2_EXTRACTOR.be2, add)
    exps = get_operand_expressions(BE2_EXTRACTOR.be2, ops[0])
    assert is_stack_register_expression(BE2_EXTRACTOR.be2, exps[0]) is False
    exps = get_operand_expressions(BE2_EXTRACTOR.be2, ops[1])
    assert is_stack_register_expression(BE2_EXTRACTOR.be2, exps[0]) is True
    exps = get_operand_expressions(BE2_EXTRACTOR.be2, ops[1])
    assert is_stack_register_expression(BE2_EXTRACTOR.be2, exps[0]) is False
