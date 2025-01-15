# Copyright 2024 Google LLC
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

import logging
from typing import Iterator

import capa.features.extractors.strings
import capa.features.extractors.binexport2.helpers
from capa.features.insn import MAX_STRUCTURE_SIZE, Number, Offset, OperandNumber, OperandOffset
from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.extractors.binexport2 import BinExport2Index, FunctionContext, BasicBlockContext, InstructionContext
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.binexport2.helpers import (
    BinExport2InstructionPatternMatcher,
    mask_immediate,
    is_address_mapped,
    get_instruction_mnemonic,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2
from capa.features.extractors.binexport2.arch.intel.helpers import SECURITY_COOKIE_BYTES_DELTA

logger = logging.getLogger(__name__)


IGNORE_NUMBER_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    ret  #int
    retn #int
    add  reg(stack), #int
    sub  reg(stack), #int
    """
)

NUMBER_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    push #int0            ; capture #int0

    # its a little tedious to enumerate all the address forms
    # but at least we are explicit
    cmp|and|or|test|mov|add|adc|sub|shl|shr|sal|sar  reg,                      #int0  ; capture #int0
    cmp|and|or|test|mov|add|adc|sub|shl|shr|sal|sar [reg],                     #int0  ; capture #int0
    cmp|and|or|test|mov|add|adc|sub|shl|shr|sal|sar [#int],                    #int0  ; capture #int0
    cmp|and|or|test|mov|add|adc|sub|shl|shr|sal|sar [reg + #int],              #int0  ; capture #int0
    cmp|and|or|test|mov|add|adc|sub|shl|shr|sal|sar [reg + reg + #int],        #int0  ; capture #int0
    cmp|and|or|test|mov|add|adc|sub|shl|shr|sal|sar [reg + reg * #int],        #int0  ; capture #int0
    cmp|and|or|test|mov|add|adc|sub|shl|shr|sal|sar [reg + reg * #int + #int], #int0  ; capture #int0

    imul reg, reg, #int  ; capture #int
    # note that int is first
    cmp|test #int0, reg   ; capture #int0

    # imagine reg is zero'd out, then this is like `mov reg, #int`
    # which is not uncommon.
    lea reg, [reg + #int]  ; capture #int
    """
)


def extract_insn_number_features(
    fh: FunctionHandle, _bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    if IGNORE_NUMBER_PATTERNS.match_with_be2(be2, ii.instruction_index):
        return

    match = NUMBER_PATTERNS.match_with_be2(be2, ii.instruction_index)
    if not match:
        return

    value: int = mask_immediate(fhi.arch, match.expression.immediate)
    if is_address_mapped(be2, value):
        return

    yield Number(value), ih.address
    yield OperandNumber(match.operand_index, value), ih.address

    instruction_index: int = ii.instruction_index
    instruction: BinExport2.Instruction = be2.instruction[instruction_index]

    mnemonic: str = get_instruction_mnemonic(be2, instruction)
    if mnemonic.startswith("add"):
        if 0 < value < MAX_STRUCTURE_SIZE:
            yield Offset(value), ih.address
            yield OperandOffset(match.operand_index, value), ih.address


OFFSET_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    mov|movzx|movsb|cmp [reg            +  reg * #int + #int0], #int  ; capture #int0
    mov|movzx|movsb|cmp [reg            * #int + #int0],        #int  ; capture #int0
    mov|movzx|movsb|cmp [reg            +  reg + #int0],        #int  ; capture #int0
    mov|movzx|movsb|cmp [reg(not-stack) + #int0],               #int  ; capture #int0
    mov|movzx|movsb|cmp [reg            +  reg * #int + #int0], reg   ; capture #int0
    mov|movzx|movsb|cmp [reg            * #int + #int0],        reg   ; capture #int0
    mov|movzx|movsb|cmp [reg            +  reg + #int0],        reg   ; capture #int0
    mov|movzx|movsb|cmp [reg(not-stack) + #int0],               reg   ; capture #int0
    mov|movzx|movsb|cmp|lea reg, [reg            +  reg * #int + #int0]  ; capture #int0
    mov|movzx|movsb|cmp|lea reg, [reg            * #int + #int0]         ; capture #int0
    mov|movzx|movsb|cmp|lea reg, [reg            +  reg + #int0]         ; capture #int0
    mov|movzx|movsb|cmp|lea reg, [reg(not-stack) + #int0]                ; capture #int0
    """
)

# these are patterns that access offset 0 from some pointer
# (pointer is not the stack pointer).
OFFSET_ZERO_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    mov|movzx|movsb [reg(not-stack)], reg
    mov|movzx|movsb [reg(not-stack)], #int
    lea             reg,              [reg(not-stack)]
    """
)


def extract_insn_offset_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    match = OFFSET_PATTERNS.match_with_be2(be2, ii.instruction_index)
    if not match:
        match = OFFSET_ZERO_PATTERNS.match_with_be2(be2, ii.instruction_index)
        if not match:
            return

        yield Offset(0), ih.address
        yield OperandOffset(match.operand_index, 0), ih.address

    value = mask_immediate(fhi.arch, match.expression.immediate)
    if is_address_mapped(be2, value):
        return

    value = capa.features.extractors.binexport2.helpers.twos_complement(fhi.arch, value, 32)
    yield Offset(value), ih.address
    yield OperandOffset(match.operand_index, value), ih.address


def is_security_cookie(
    fhi: FunctionContext,
    bbi: BasicBlockContext,
    instruction_address: int,
    instruction: BinExport2.Instruction,
) -> bool:
    """
    check if an instruction is related to security cookie checks.
    """
    be2: BinExport2 = fhi.ctx.be2
    idx: BinExport2Index = fhi.ctx.idx

    # security cookie check should use SP or BP
    op1: BinExport2.Operand = be2.operand[instruction.operand_index[1]]
    op1_exprs: list[BinExport2.Expression] = [be2.expression[expr_i] for expr_i in op1.expression_index]
    if all(expr.symbol.lower() not in ("bp", "esp", "ebp", "rbp", "rsp") for expr in op1_exprs):
        return False

    # check_nzxor_security_cookie_delta
    # if insn falls at the start of first entry block of the parent function.
    flow_graph: BinExport2.FlowGraph = be2.flow_graph[fhi.flow_graph_index]
    basic_block_index: int = bbi.basic_block_index
    bb: BinExport2.BasicBlock = be2.basic_block[basic_block_index]
    if flow_graph.entry_basic_block_index == basic_block_index:
        first_addr: int = min((idx.insn_address_by_index[ir.begin_index] for ir in bb.instruction_index))
        if instruction_address < first_addr + SECURITY_COOKIE_BYTES_DELTA:
            return True
    # or insn falls at the end before return in a terminal basic block.
    if basic_block_index not in (e.source_basic_block_index for e in flow_graph.edge):
        last_addr: int = max((idx.insn_address_by_index[ir.end_index - 1] for ir in bb.instruction_index))
        if instruction_address > last_addr - SECURITY_COOKIE_BYTES_DELTA:
            return True
    return False


NZXOR_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    xor|xorpd|xorps|pxor reg, reg
    xor|xorpd|xorps|pxor reg, #int
    """
)


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2
    idx: BinExport2Index = fhi.ctx.idx

    if NZXOR_PATTERNS.match_with_be2(be2, ii.instruction_index) is None:
        return

    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]
    # guaranteed to be simple int/reg operands
    # so we don't have to realize the tree/list.
    operands: list[BinExport2.Operand] = [be2.operand[operand_index] for operand_index in instruction.operand_index]

    if operands[0] == operands[1]:
        return

    instruction_address: int = idx.insn_address_by_index[ii.instruction_index]
    if is_security_cookie(fhi, bbh.inner, instruction_address, instruction):
        return

    yield Characteristic("nzxor"), ih.address


INDIRECT_CALL_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    call|jmp reg0
    call|jmp [reg + reg * #int + #int]
    call|jmp [reg + reg * #int]
    call|jmp [reg * #int + #int]
    call|jmp [reg + reg + #int]
    call|jmp [reg + #int]
    call|jmp [reg]
    """
)


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner
    be2: BinExport2 = fhi.ctx.be2

    match = INDIRECT_CALL_PATTERNS.match_with_be2(be2, ii.instruction_index)
    if match is None:
        return

    yield Characteristic("indirect call"), ih.address
