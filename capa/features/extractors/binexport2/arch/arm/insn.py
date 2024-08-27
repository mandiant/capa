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
    mask_immediate,
    is_address_mapped,
    get_operand_expressions,
    get_instruction_mnemonic,
    get_instruction_operands,
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

        expression1: Optional[BinExport2.Expression] = get_operand_register_expression(
            be2, be2.operand[instruction.operand_index[1]]
        )
        if expression1 and is_stack_register_expression(be2, expression1):
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


def extract_insn_offset_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2
    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]

    if len(instruction.operand_index) == 0:
        # skip things like:
        #   .text:0040116e leave
        return

    mnemonic: str = get_instruction_mnemonic(be2, instruction)
    value: Optional[int] = None
    value_index: Optional[int] = None

    operands: List[BinExport2.Operand]
    immediate_expression: Optional[BinExport2.Expression]

    if mnemonic.startswith(("ldr", "str")):
        operands = get_instruction_operands(be2, instruction)
        expressions1: List[BinExport2.Expression]

        if len(operands) == 2:
            # like:
            # ldr x0, [x1, 8]
            expressions1 = get_operand_expressions(be2, operands[1])

            if len(expressions1) == 4:
                # like:
                # ldr x0, [x1, 8]
                if not is_stack_register_expression(be2, expressions1[1]):
                    if expressions1[3].type == BinExport2.Expression.IMMEDIATE_INT:
                        value = expressions1[3].immediate
                        value_index = 1

            elif len(expressions1) == 5:
                # like
                # ldr x0, [x1, 8]!
                if not is_stack_register_expression(be2, expressions1[2]):
                    if expressions1[4].type == BinExport2.Expression.IMMEDIATE_INT:
                        value = expressions1[4].immediate
                        value_index = 1

        elif len(operands) == 3:
            # like:
            # ldr x0, [x1], 8
            expressions1 = get_operand_expressions(be2, operands[1])
            if not is_stack_register_expression(be2, expressions1[1]):
                immediate_expression = get_operand_immediate_expression(be2, operands[2])

                if immediate_expression:
                    value = immediate_expression.immediate
                    value_index = 2

    elif mnemonic in ("ldp", "stp"):
        operands = get_instruction_operands(be2, instruction)
        expressions2: List[BinExport2.Expression]

        if len(operands) == 3:
            # like:
            # ldp x0, x1, [x3, 8]!
            expressions2 = get_operand_expressions(be2, operands[2])

            if len(expressions2) == 4:
                # like:
                # ldp x0, x1, [x3, 8]
                if not is_stack_register_expression(be2, expressions2[1]):
                    if expressions2[3].type == BinExport2.Expression.IMMEDIATE_INT:
                        value = expressions2[3].immediate
                        value_index = 2

            elif len(expressions2) == 5:
                # like:
                # ldp x0, x1, [x3, 8]!
                if not is_stack_register_expression(be2, expressions2[2]):
                    if expressions2[4].type == BinExport2.Expression.IMMEDIATE_INT:
                        value = expressions2[4].immediate
                        value_index = 2

        elif len(operands) == 4:
            # like
            # ldp x0, x1, [x3], 8
            expressions2 = get_operand_expressions(be2, operands[2])

            if not is_stack_register_expression(be2, expressions2[1]):
                immediate_expression = get_operand_immediate_expression(be2, operands[3])

                if immediate_expression:
                    value = immediate_expression.immediate
                    value_index = 3

    if value is None:
        return

    # we shouldn't make it here if index is not set
    assert value_index is not None

    value = mask_immediate(fhi.arch, value)
    if not is_address_mapped(be2, value):
        value = capa.features.extractors.binexport2.helpers.twos_complement(fhi.arch, value)
        yield Offset(value), ih.address
        yield OperandOffset(value_index, value), ih.address


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]
    mnemonic: str = get_instruction_mnemonic(be2, instruction)

    if mnemonic != "eor":
        return

    operands: List[BinExport2.Operand] = [be2.operand[operand_index] for operand_index in instruction.operand_index]

    assert len(operands) == 3

    if operands[1] != operands[2]:
        yield Characteristic("nzxor"), ih.address


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]
    mnemonic: str = get_instruction_mnemonic(be2, instruction)

    if mnemonic not in ("blx", "bx", "blr"):
        return

    assert len(instruction.operand_index) == 1

    expressions: List[BinExport2.Expression] = get_operand_expressions(be2, be2.operand[instruction.operand_index[0]])

    assert len(expressions) == 1

    if expressions[0].type == BinExport2.Expression.REGISTER:
        yield Characteristic("indirect call"), ih.address
