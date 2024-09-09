# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import List, Tuple, Iterator, Optional

import capa.features.extractors.binexport2.helpers
from capa.features.insn import MAX_STRUCTURE_SIZE, Number, Offset, OperandNumber, OperandOffset
from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.extractors.binexport2 import FunctionContext, InstructionContext
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.binexport2.helpers import (
    BinExport2InstructionPatternMatcher,
    mask_immediate,
    is_address_mapped,
    get_instruction_mnemonic,
    get_operand_register_expression,
    get_operand_immediate_expression,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2
from capa.features.extractors.binexport2.arch.arm.helpers import is_stack_register_expression

logger = logging.getLogger(__name__)


def extract_insn_number_features(
    fh: FunctionHandle, _bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    instruction_index: int = ii.instruction_index
    instruction: BinExport2.Instruction = be2.instruction[instruction_index]

    if len(instruction.operand_index) == 0:
        # skip things like:
        #   .text:0040116e leave
        return

    mnemonic: str = get_instruction_mnemonic(be2, instruction)

    if mnemonic in ("add", "sub"):
        assert len(instruction.operand_index) == 3

        operand1_expression: Optional[BinExport2.Expression] = get_operand_register_expression(
            be2, be2.operand[instruction.operand_index[1]]
        )
        if operand1_expression and is_stack_register_expression(be2, operand1_expression):
            # skip things like:
            # add x0,sp,#0x8
            return

    for i, operand_index in enumerate(instruction.operand_index):
        operand: BinExport2.Operand = be2.operand[operand_index]

        immediate_expression: Optional[BinExport2.Expression] = get_operand_immediate_expression(be2, operand)
        if not immediate_expression:
            continue

        value: int = mask_immediate(fhi.arch, immediate_expression.immediate)
        if is_address_mapped(be2, value):
            continue

        yield Number(value), ih.address
        yield OperandNumber(i, value), ih.address

        if mnemonic == "add" and i == 2:
            if 0 < value < MAX_STRUCTURE_SIZE:
                yield Offset(value), ih.address
                yield OperandOffset(i, value), ih.address


OFFSET_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    ldr|ldrb|ldrh|ldrsb|ldrsh|ldrex|ldrd|str|strb|strh|strex|strd reg, [reg(not-stack),  #int]                                 ; capture #int
    ldr|ldrb|ldrh|ldrsb|ldrsh|ldrex|ldrd|str|strb|strh|strex|strd reg, [reg(not-stack),  #int]!                                ; capture #int
    ldr|ldrb|ldrh|ldrsb|ldrsh|ldrex|ldrd|str|strb|strh|strex|strd reg, [reg(not-stack)],        #int                           ; capture #int
    ldp|ldpd|stp|stpd                                             reg, reg,                     [reg(not-stack), #int]         ; capture #int
    ldp|ldpd|stp|stpd                                             reg, reg,                     [reg(not-stack), #int]!        ; capture #int
    ldp|ldpd|stp|stpd                                             reg, reg,                     [reg(not-stack)],       #int   ; capture #int
    """
)


def extract_insn_offset_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    match = OFFSET_PATTERNS.match_with_be2(be2, ii.instruction_index)
    if not match:
        return

    value = match.expression.immediate

    value = mask_immediate(fhi.arch, value)
    if not is_address_mapped(be2, value):
        value = capa.features.extractors.binexport2.helpers.twos_complement(fhi.arch, value)
        yield Offset(value), ih.address
        yield OperandOffset(match.operand_index, value), ih.address


NZXOR_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    eor reg, reg, reg
    eor reg, reg, #int
    """
)


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner
    be2: BinExport2 = fhi.ctx.be2

    if NZXOR_PATTERNS.match_with_be2(be2, ii.instruction_index) is None:
        return

    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]
    # guaranteed to be simple int/reg operands
    # so we don't have to realize the tree/list.
    operands: List[BinExport2.Operand] = [be2.operand[operand_index] for operand_index in instruction.operand_index]

    if operands[1] != operands[2]:
        yield Characteristic("nzxor"), ih.address


INDIRECT_CALL_PATTERNS = BinExport2InstructionPatternMatcher.from_str(
    """
    blx|bx|blr reg
    """
)


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner
    be2: BinExport2 = fhi.ctx.be2

    if INDIRECT_CALL_PATTERNS.match_with_be2(be2, ii.instruction_index) is not None:
        yield Characteristic("indirect call"), ih.address
