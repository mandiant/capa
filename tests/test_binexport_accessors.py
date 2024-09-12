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

import capa.features.extractors.binexport2.helpers
from capa.features.extractors.binexport2.helpers import (
    BinExport2InstructionPattern,
    BinExport2InstructionPatternMatcher,
    split_with_delimiters,
    get_operand_expressions,
    get_instruction_mnemonic,
    get_instruction_operands,
    get_operand_register_expression,
    get_operand_immediate_expression,
)
from capa.features.extractors.binexport2.extractor import BinExport2FeatureExtractor
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
    "addr,expressions",
    [
        # 00210158 20 00 80 d2     mov        x0,#0x1
        (
            0x210158,
            (
                BinExport2.Expression(type=BinExport2.Expression.REGISTER, symbol="x0"),
                BinExport2.Expression(type=BinExport2.Expression.IMMEDIATE_INT, immediate=0x1),
            ),
        ),
        # 0021015c a1 02 00 58     ldr        x1=>helloWorldStr,DAT_002101b0
        (
            0x21015C,
            (
                BinExport2.Expression(type=BinExport2.Expression.REGISTER, symbol="x1"),
                BinExport2.Expression(
                    type=BinExport2.Expression.IMMEDIATE_INT, symbol="PTR_helloWorldStr_002101b0", immediate=0x2101B0
                ),
            ),
        ),
        # 00210184 02 68 61 38     ldrb       w2,[x0, x1, LSL ]
        #                                                 ^^^ issue in Ghidra?
        #  IDA gives               LDRB       W2, [X0,X1]
        (
            0x210184,
            (
                BinExport2.Expression(type=BinExport2.Expression.REGISTER, symbol="w2"),
                (
                    BinExport2.Expression(type=BinExport2.Expression.DEREFERENCE, symbol="["),
                    BinExport2.Expression(type=BinExport2.Expression.REGISTER, symbol="x0"),
                    BinExport2.Expression(type=BinExport2.Expression.OPERATOR, symbol=","),
                    BinExport2.Expression(type=BinExport2.Expression.REGISTER, symbol="x1"),
                    BinExport2.Expression(type=BinExport2.Expression.DEREFERENCE, symbol="]"),
                ),
            ),
        ),
        # 00210190 21 04 00 91     add        x1,x1,#0x1
        (
            0x210190,
            (
                BinExport2.Expression(type=BinExport2.Expression.REGISTER, symbol="x1"),
                BinExport2.Expression(type=BinExport2.Expression.REGISTER, symbol="x1"),
                BinExport2.Expression(type=BinExport2.Expression.IMMEDIATE_INT, immediate=0x1),
            ),
        ),
    ],
)
def test_get_operand_expressions(addr, expressions):
    insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
    ops = get_instruction_operands(BE2_EXTRACTOR.be2, insn)
    for i, op in enumerate(ops):
        op_expression = expressions[i]
        exps = get_operand_expressions(BE2_EXTRACTOR.be2, op)
        if len(exps) > 1:
            for j, exp in enumerate(exps):
                assert exp.type == op_expression[j].type
                assert exp.symbol == op_expression[j].symbol
        else:
            assert len(exps) == 1
            assert exps[0] == op_expression


@pytest.mark.parametrize(
    "addr,expressions",
    [
        # 00210158 20 00 80 d2     mov        x0,#0x1
        (0x210158, ("x0", None)),
        # 0021015c a1 02 00 58     ldr        x1=>helloWorldStr,DAT_002101b0
        (0x21015C, ("x1", None)),
        # 0021019c e1 03 00 aa     mov        x1,x0
        (0x21019C, ("x1", "x0")),
        # 00210190 21 04 00 91     add        x1,x1,#0x1
        (0x210190, ("x1", "x1", None)),
    ],
)
def test_get_operand_register_expression(addr, expressions):
    insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
    ops = get_instruction_operands(BE2_EXTRACTOR.be2, insn)
    for i, op in enumerate(ops):
        reg_exp = get_operand_register_expression(BE2_EXTRACTOR.be2, op)
        if reg_exp is None:
            assert reg_exp == expressions[i]
        else:
            assert reg_exp.symbol == expressions[i]


@pytest.mark.parametrize(
    "addr,expressions",
    [
        # 00210158 20 00 80 d2     mov        x0,#0x1
        (0x210158, (None, 0x1)),
        # 0021015c a1 02 00 58     ldr        x1=>helloWorldStr,DAT_002101b0
        (0x21015C, (None, 0x2101B0)),
        # 002101a8 01 00 00 d4     svc        0x0
        (0x2101A8, (0x0,)),
        # 00210190 21 04 00 91     add        x1,x1,#0x1
        (0x210190, (None, None, 0x1)),
    ],
)
def test_get_operand_immediate_expression(addr, expressions):
    insn = BE2_EXTRACTOR.idx.get_instruction_by_address(addr)
    ops = get_instruction_operands(BE2_EXTRACTOR.be2, insn)
    for i, op in enumerate(ops):
        reg_exp = get_operand_immediate_expression(BE2_EXTRACTOR.be2, op)
        if reg_exp is None:
            assert reg_exp == expressions[i]
        else:
            assert reg_exp.immediate == expressions[i]


"""
mov     x0, 0x20
bl      0x100
add     x0, sp, 0x10
"""
BE2_DICT: Dict[str, Any] = {
    "expression": [
        {"type": BinExport2.Expression.REGISTER, "symbol": "x0"},
        {"type": BinExport2.Expression.IMMEDIATE_INT, "immediate": 0x20},
        {"type": BinExport2.Expression.IMMEDIATE_INT, "immediate": 0x100},
        {"type": BinExport2.Expression.REGISTER, "symbol": "sp"},
        {"type": BinExport2.Expression.IMMEDIATE_INT, "immediate": 0x10},
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


def test_is_stack_register_expression():
    mov = ParseDict(BE2_DICT["instruction"][0], BinExport2.Instruction())
    add = ParseDict(BE2_DICT["instruction"][2], BinExport2.Instruction())

    mov_op0, mov_op1 = get_instruction_operands(BE2, mov)
    op0_exp0 = get_operand_expressions(BE2, mov_op0)[0]
    assert is_stack_register_expression(BE2, op0_exp0) is False
    op0_exp1 = get_operand_expressions(BE2, mov_op1)[0]
    assert is_stack_register_expression(BE2, op0_exp1) is False

    add_op0, add_op1, add_op2 = get_instruction_operands(BE2, add)
    op0_exp0 = get_operand_expressions(BE2, add_op0)[0]
    assert is_stack_register_expression(BE2, op0_exp0) is False
    op1_exp0 = get_operand_expressions(BE2, add_op1)[0]
    assert is_stack_register_expression(BE2, op1_exp0) is True
    op2_exp0 = get_operand_expressions(BE2, add_op2)[0]
    assert is_stack_register_expression(BE2, op2_exp0) is False


def test_split_with_delimiters():
    assert tuple(split_with_delimiters("abc|def", ("|",))) == ("abc", "|", "def")
    assert tuple(split_with_delimiters("abc|def|", ("|",))) == ("abc", "|", "def", "|")
    assert tuple(split_with_delimiters("abc||def", ("|",))) == ("abc", "|", "", "|", "def")
    assert tuple(split_with_delimiters("abc|def-ghi", ("|", "-"))) == ("abc", "|", "def", "-", "ghi")


def test_pattern_parsing():
    assert BinExport2InstructionPattern.from_str(
        "br      reg                     ; capture reg"
    ) == BinExport2InstructionPattern(mnemonics=("br",), operands=("reg",), capture="reg")

    assert BinExport2InstructionPattern.from_str(
        "mov     reg0, reg1              ; capture reg0"
    ) == BinExport2InstructionPattern(mnemonics=("mov",), operands=("reg0", "reg1"), capture="reg0")

    assert BinExport2InstructionPattern.from_str(
        "adrp    reg, #int               ; capture #int"
    ) == BinExport2InstructionPattern(mnemonics=("adrp",), operands=("reg", "#int"), capture="#int")

    assert BinExport2InstructionPattern.from_str(
        "add     reg, reg, #int          ; capture #int"
    ) == BinExport2InstructionPattern(mnemonics=("add",), operands=("reg", "reg", "#int"), capture="#int")

    assert BinExport2InstructionPattern.from_str(
        "ldr     reg0, [reg1]            ; capture reg1"
    ) == BinExport2InstructionPattern(mnemonics=("ldr",), operands=("reg0", ("[", "reg1")), capture="reg1")

    assert BinExport2InstructionPattern.from_str(
        "ldr|str reg, [reg, #int]        ; capture #int"
    ) == BinExport2InstructionPattern(
        mnemonics=(
            "ldr",
            "str",
        ),
        operands=("reg", ("[", "reg", ",", "#int")),
        capture="#int",
    )

    assert BinExport2InstructionPattern.from_str(
        "ldr|str reg, [reg, #int]!       ; capture #int"
    ) == BinExport2InstructionPattern(
        mnemonics=(
            "ldr",
            "str",
        ),
        operands=("reg", ("!", "[", "reg", ",", "#int")),
        capture="#int",
    )

    assert BinExport2InstructionPattern.from_str(
        "ldr|str reg, [reg], #int        ; capture #int"
    ) == BinExport2InstructionPattern(
        mnemonics=(
            "ldr",
            "str",
        ),
        operands=(
            "reg",
            (
                "[",
                "reg",
            ),
            "#int",
        ),
        capture="#int",
    )

    assert BinExport2InstructionPattern.from_str(
        "ldp|stp reg, reg, [reg, #int]   ; capture #int"
    ) == BinExport2InstructionPattern(
        mnemonics=(
            "ldp",
            "stp",
        ),
        operands=("reg", "reg", ("[", "reg", ",", "#int")),
        capture="#int",
    )

    assert BinExport2InstructionPattern.from_str(
        "ldp|stp reg, reg, [reg, #int]!  ; capture #int"
    ) == BinExport2InstructionPattern(
        mnemonics=(
            "ldp",
            "stp",
        ),
        operands=("reg", "reg", ("!", "[", "reg", ",", "#int")),
        capture="#int",
    )

    assert BinExport2InstructionPattern.from_str(
        "ldp|stp reg, reg, [reg], #int   ; capture #int"
    ) == BinExport2InstructionPattern(
        mnemonics=(
            "ldp",
            "stp",
        ),
        operands=("reg", "reg", ("[", "reg"), "#int"),
        capture="#int",
    )

    assert (
        BinExport2InstructionPatternMatcher.from_str(
            """
            # comment
            br      reg
            br      reg(not-stack)
            br      reg                     ; capture reg
            mov     reg0, reg1              ; capture reg0
            adrp    reg, #int               ; capture #int
            add     reg, reg, #int          ; capture #int
            ldr     reg0, [reg1]            ; capture reg1
            ldr|str reg, [reg, #int]        ; capture #int
            ldr|str reg, [reg, #int]!       ; capture #int
            ldr|str reg, [reg], #int        ; capture #int
            ldp|stp reg, reg, [reg, #int]   ; capture #int
            ldp|stp reg, reg, [reg, #int]!  ; capture #int
            ldp|stp reg, reg, [reg], #int   ; capture #int
            ldrb    reg0, [reg1, reg2]      ; capture reg2
            call    [reg + reg * #int + #int]
            call    [reg + reg * #int]
            call    [reg * #int + #int]
            call    [reg + reg + #int]
            call    [reg + #int]
            """
        ).queries
        is not None
    )


def match_address(extractor: BinExport2FeatureExtractor, queries: BinExport2InstructionPatternMatcher, address: int):
    instruction = extractor.idx.insn_by_address[address]
    mnemonic: str = get_instruction_mnemonic(extractor.be2, instruction)

    operands = []
    for operand_index in instruction.operand_index:
        operand = extractor.be2.operand[operand_index]
        operands.append(capa.features.extractors.binexport2.helpers.get_operand_expressions(extractor.be2, operand))

    return queries.match(mnemonic, operands)


def match_address_with_be2(
    extractor: BinExport2FeatureExtractor, queries: BinExport2InstructionPatternMatcher, address: int
):
    instruction_index = extractor.idx.insn_index_by_address[address]
    return queries.match_with_be2(extractor.be2, instruction_index)


def test_pattern_matching():
    queries = BinExport2InstructionPatternMatcher.from_str(
        """
        br      reg(stack)                     ; capture reg
        br      reg(not-stack)                 ; capture reg
        mov     reg0, reg1                     ; capture reg0
        adrp    reg, #int                      ; capture #int
        add     reg, reg, #int                 ; capture #int
        ldr     reg0, [reg1]                   ; capture reg1
        ldr|str reg, [reg, #int]               ; capture #int
        ldr|str reg, [reg, #int]!              ; capture #int
        ldr|str reg, [reg], #int               ; capture #int
        ldp|stp reg, reg, [reg, #int]          ; capture #int
        ldp|stp reg, reg, [reg, #int]!         ; capture #int
        ldp|stp reg, reg, [reg], #int          ; capture #int
        ldrb    reg0, [reg1(not-stack), reg2]  ; capture reg2
        """
    )

    # 0x210184: ldrb      w2, [x0,                x1]
    # query:    ldrb    reg0, [reg1(not-stack), reg2]      ; capture reg2"
    assert match_address(BE2_EXTRACTOR, queries, 0x210184).expression.symbol == "x1"
    assert match_address_with_be2(BE2_EXTRACTOR, queries, 0x210184).expression.symbol == "x1"

    # 0x210198:  mov         x2, x1
    # query:     mov       reg0, reg1           ; capture reg0"),
    assert match_address(BE2_EXTRACTOR, queries, 0x210198).expression.symbol == "x2"
    assert match_address_with_be2(BE2_EXTRACTOR, queries, 0x210198).expression.symbol == "x2"

    # 0x210190:  add         x1, x1,  0x1
    # query:     add        reg, reg, #int      ; capture #int
    assert match_address(BE2_EXTRACTOR, queries, 0x210190).expression.immediate == 1
    assert match_address_with_be2(BE2_EXTRACTOR, queries, 0x210190).expression.immediate == 1


BE2_EXTRACTOR_687 = fixtures.get_binexport_extractor(
    CD
    / "data"
    / "binexport2"
    / "687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_.ghidra.BinExport"
)


def test_pattern_matching_exclamation():
    queries = BinExport2InstructionPatternMatcher.from_str(
        """
        stp  reg, reg, [reg, #int]!  ; capture #int
        """
    )

    # note this captures the sp
    # 0x107918:  stp  x20, x19, [sp,0xFFFFFFFFFFFFFFE0]!
    # query:     stp  reg, reg, [reg, #int]!  ; capture #int
    assert match_address(BE2_EXTRACTOR_687, queries, 0x107918).expression.immediate == 0xFFFFFFFFFFFFFFE0
    assert match_address_with_be2(BE2_EXTRACTOR_687, queries, 0x107918).expression.immediate == 0xFFFFFFFFFFFFFFE0


def test_pattern_matching_stack():
    queries = BinExport2InstructionPatternMatcher.from_str(
        """
        stp  reg, reg, [reg(stack), #int]!  ; capture #int
        """
    )

    # note this does capture the sp
    # compare this with the test above (exclamation)
    # 0x107918:  stp  x20, x19, [sp,         0xFFFFFFFFFFFFFFE0]!
    # query:     stp  reg, reg, [reg(stack), #int]!  ; capture #int
    assert match_address(BE2_EXTRACTOR_687, queries, 0x107918).expression.immediate == 0xFFFFFFFFFFFFFFE0
    assert match_address_with_be2(BE2_EXTRACTOR_687, queries, 0x107918).expression.immediate == 0xFFFFFFFFFFFFFFE0


def test_pattern_matching_not_stack():
    queries = BinExport2InstructionPatternMatcher.from_str(
        """
        stp  reg, reg, [reg(not-stack), #int]!  ; capture #int
        """
    )

    # note this does not capture the sp
    # compare this with the test above (exclamation)
    # 0x107918:  stp  x20, x19, [sp,             0xFFFFFFFFFFFFFFE0]!
    # query:     stp  reg, reg, [reg(not-stack), #int]!  ; capture #int
    assert match_address(BE2_EXTRACTOR_687, queries, 0x107918) is None
    assert match_address_with_be2(BE2_EXTRACTOR_687, queries, 0x107918) is None


BE2_EXTRACTOR_MIMI = fixtures.get_binexport_extractor(CD / "data" / "binexport2" / "mimikatz.exe_.ghidra.BinExport")


def test_pattern_matching_x86():
    queries = BinExport2InstructionPatternMatcher.from_str(
        """
        cmp|lea reg, [reg(not-stack) + #int0]  ; capture #int0
        """
    )

    # 0x4018c0:  LEA         ECX, [EBX+0x2]
    # query:     cmp|lea     reg, [reg(not-stack) + #int0]  ; capture #int0
    assert match_address(BE2_EXTRACTOR_MIMI, queries, 0x4018C0).expression.immediate == 2
    assert match_address_with_be2(BE2_EXTRACTOR_MIMI, queries, 0x4018C0).expression.immediate == 2
