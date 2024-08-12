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
from capa.features.insn import Number, Offset, OperandNumber, OperandOffset
from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.extractors.binexport2 import FunctionContext, InstructionContext
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.binexport2.helpers import (
    mask_immediate,
    is_address_mapped,
    get_operand_expressions,
    get_instruction_mnemonic,
    get_operand_immediate_expression,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

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

    for i, operand_index in enumerate(instruction.operand_index):
        operand: BinExport2.Operand = be2.operand[operand_index]

        is_dereference = False
        for expression_index in operand.expression_index:
            if be2.expression[expression_index].type == BinExport2.Expression.DEREFERENCE:
                is_dereference = True
                break

        if not is_dereference:
            continue

        if mnemonic in ("ldp", "stp"):
            # like:
            # 0013a2f0 ldp x22,x9,[x21, #0x18]
            expressions: List[BinExport2.Expression] = get_operand_expressions(be2, operand)
            if len(expressions) <= 2:
                continue

            if expressions[1].symbol.lower().endswith("sp"):
                continue

            value = mask_immediate(fhi.arch, expressions[-1].immediate)

            if not is_address_mapped(be2, value):
                value = capa.features.extractors.binexport2.helpers.twos_complement(fhi.arch, value)

                yield Offset(value), ih.address
                yield OperandOffset(i, value), ih.address


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
    yield from ()
