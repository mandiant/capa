# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import List, Tuple, Iterator, Optional

import capa.features.extractors.strings
import capa.features.extractors.binexport2.helpers
from capa.features.insn import MAX_STRUCTURE_SIZE, Number, Offset, OperandNumber, OperandOffset
from capa.features.common import Feature, Characteristic
from capa.features.address import Address
from capa.features.extractors.binexport2 import FunctionContext, BasicBlockContext, InstructionContext, BinExport2Index
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.binexport2.helpers import (
    mask_immediate,
    is_address_mapped,
    get_instruction_mnemonic,
    get_operand_register_expression,
    get_operand_immediate_expression,
)
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2
from capa.features.extractors.binexport2.arch.intel.helpers import (
    SECURITY_COOKIE_BYTES_DELTA,
    OperandPhraseInfo,
    get_operand_phrase_info,
)

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

    if mnemonic.startswith("ret"):
        # skip things like:
        #   .text:0042250E retn 8
        return

    if mnemonic.startswith(("add", "sub")):
        register_expression: Optional[BinExport2.Expression] = get_operand_register_expression(
            be2, be2.operand[instruction.operand_index[0]]
        )
        if register_expression and register_expression.symbol.lower().endswith(("sp", "bp")):
            # skip things like:
            # 0x415bbc  ADD         ESP, 0xC
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

        if mnemonic.startswith("add"):
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
    value: int

    for i, operand_index in enumerate(instruction.operand_index):
        operand: BinExport2.Operand = be2.operand[operand_index]

        is_dereference = False
        for expression_index in operand.expression_index:
            if be2.expression[expression_index].type == BinExport2.Expression.DEREFERENCE:
                is_dereference = True
                break

        if not is_dereference:
            continue

        phrase_info: Optional[OperandPhraseInfo] = get_operand_phrase_info(be2, operand)
        if not phrase_info:
            continue

        if phrase_info.displacement:
            if phrase_info.base and phrase_info.base.symbol.lower().endswith(("bp", "sp")):
                # skips things like:
                # 00401068 MOV dword ptr [EBP + local_8],EAX
                continue

            value = mask_immediate(fhi.arch, phrase_info.displacement.immediate)
            if not is_address_mapped(be2, value):
                value = capa.features.extractors.binexport2.helpers.twos_complement(fhi.arch, value, 32)

                yield Offset(value), ih.address
                yield OperandOffset(i, value), ih.address

                if mnemonic == "lea" and i == 1:
                    if phrase_info.base and not any((phrase_info.scale, phrase_info.index)):
                        yield Number(value), ih.address
                        yield OperandNumber(i, value), ih.address

        elif phrase_info.base and not any((phrase_info.index, phrase_info.scale)):
            # like:
            # 00401062 MOVZX EAX,word ptr [EDI]
            yield Offset(0), ih.address
            yield OperandOffset(i, 0), ih.address


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
    op1_exprs: List[BinExport2.Expression] = [be2.expression[expr_i] for expr_i in op1.expression_index]
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


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]
    mnemonic: str = get_instruction_mnemonic(be2, instruction)
    if mnemonic not in (
        "xor",
        "xorpd",
        "xorps",
        "pxor",
    ):
        return

    operands: List[BinExport2.Operand] = [be2.operand[operand_index] for operand_index in instruction.operand_index]

    if mnemonic in ("xor", "xorpd", "xorps", "pxor"):
        if operands[0] == operands[1]:
            return
        instruction_address: int = idx.insn_address_by_index[ii.instruction_index]
        if is_security_cookie(fhi, bbh.inner, instruction_address, instruction):
            return

    yield Characteristic("nzxor"), ih.address


def extract_function_indirect_call_characteristic_features(
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
    if mnemonic not in ("call", "jmp"):
        return

    assert len(instruction.operand_index) == 1

    operand: BinExport2.Operand = be2.operand[instruction.operand_index[0]]

    if len(operand.expression_index) == 1:
        expression0: BinExport2.Expression = be2.expression[operand.expression_index[0]]
        # call edx
        if expression0.type == BinExport2.Expression.REGISTER:
            yield Characteristic("indirect call"), ih.address
    else:
        is_dereference = False
        for expression_index in operand.expression_index:
            if be2.expression[expression_index].type == BinExport2.Expression.DEREFERENCE:
                is_dereference = True
                break

        if is_dereference:
            phrase_info: Optional[OperandPhraseInfo] = get_operand_phrase_info(be2, operand)
            if phrase_info and phrase_info.base:
                # call dword ptr [eax+50h]
                yield Characteristic("indirect call"), ih.address
