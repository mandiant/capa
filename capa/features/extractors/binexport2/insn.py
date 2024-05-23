# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import List, Tuple, Iterator

import capa.features.extractors.helpers
import capa.features.extractors.strings
import capa.features.extractors.binexport2.helpers
from capa.features.insn import API, Number, Mnemonic, OperandNumber
from capa.features.common import Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.binexport2 import FunctionContext, ReadMemoryError, InstructionContext
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def extract_insn_api_features(fh: FunctionHandle, _bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2 = fhi.ctx.be2
    be2_index = fhi.ctx.idx
    be2_analysis = fhi.ctx.analysis
    insn = be2.instruction[ii.instruction_index]

    for addr in insn.call_target:
        if addr in be2_analysis.thunks:
            addr = be2_analysis.thunks[addr]

        if addr not in be2_index.vertex_index_by_address:
            # disassembler did not define function at address
            logger.debug("0x%x is not a vertex", addr)
            continue

        vertex_idx = be2_index.vertex_index_by_address[addr]
        vertex = be2.call_graph.vertex[vertex_idx]

        if not capa.features.extractors.binexport2.helpers.is_vertex_type(
            vertex, BinExport2.CallGraph.Vertex.Type.IMPORTED
        ):
            continue

        if not vertex.HasField("mangled_name"):
            logger.debug("vertex %d does not have mangled_name", vertex_idx)
            continue

        api_name = vertex.mangled_name
        yield API(api_name), ih.address

    """
        # TODO: re-enable pending https://github.com/google/binexport/issues/126#issuecomment-2074402906
        function_name = vertex.mangled_name
        if vertex.HasField("library_index"):
            # TODO: this seems to be incorrect for Ghidra extractor
            library = be2.library[vertex.library_index]
            library_name = library.name

            for name in capa.features.extractors.helpers.generate_symbols(library_name, function_name):
                yield API(name), ih.address
        else:
            yield API(function_name), ih.address
    """


def is_address_mapped(be2: BinExport2, address: int) -> bool:
    """return True if the given address is mapped"""
    sections_with_perms = filter(lambda s: s.flag_r or s.flag_w or s.flag_x, be2.section)
    return any(section.address <= address < section.address + section.size for section in sections_with_perms)


###############################################################################
#
# begin Ghidra symbol madness ("gsm").
#
# This is a "temporary" section of code to deal with
#   https://github.com/google/binexport/issues/78
# because Ghidra exports all operands as a single SYMBOL expression node.
#
# Use references to `_is_ghidra_symbol_madness` to remove all this up later.


def _is_ghidra_symbol_madness(be2: BinExport2, instruction_index: int) -> bool:
    instruction = be2.instruction[instruction_index]
    for operand_index in instruction.operand_index:
        operand = be2.operand[operand_index]

        if len(operand.expression_index) != 1:
            return False

        expression0 = be2.expression[operand.expression_index[0]]

        if BinExport2.Expression.Type.SYMBOL != expression0.type:
            return False

    return True


def _gsm_get_instruction_operand(be2: BinExport2, instruction_index: int, operand_index: int) -> str:
    """since Ghidra represents all operands as a single string, just fetch that."""
    instruction = be2.instruction[instruction_index]
    operand = be2.operand[instruction.operand_index[operand_index]]
    assert len(operand.expression_index) == 1
    expression = be2.expression[operand.expression_index[0]]
    assert expression.type == BinExport2.Expression.Type.SYMBOL
    return expression.symbol


# end Ghidra symbol madness.
#
###############################################################################


def extract_insn_number_features(
    fh: FunctionHandle, _bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2 = fhi.ctx.be2
    analysis = fhi.ctx.analysis

    instruction_index = ii.instruction_index
    instruction = be2.instruction[instruction_index]

    # x86 / amd64
    mnemonic = be2.mnemonic[instruction.mnemonic_index]
    if mnemonic.name.lower().startswith("ret"):
        # skip things like:
        #   .text:0042250E retn 8
        return

    _is_gsm = _is_ghidra_symbol_madness(be2, instruction_index)

    for i, operand_index in enumerate(instruction.operand_index):
        operand = be2.operand[operand_index]

        if len(operand.expression_index) == 1 and _is_gsm:
            # temporarily, we'll have to try to guess at the interpretation.
            symbol = _gsm_get_instruction_operand(be2, instruction_index, i)

            if symbol.startswith(("#0x", "#-0x")):
                # like:
                # - type: SYMBOL
                #   symbol: "#0xffffffff"
                # - type: SYMBOL
                #   symbol: "#-0x1"
                try:
                    value = int(symbol[len("#") :], 0x10)
                except ValueError:
                    # failed to parse as integer
                    continue

                # handling continues below at label: has a value

            elif symbol.startswith("0x"):
                # like:
                # - type: SYMBOL
                #   symbol: "0x1000"
                try:
                    value = int(symbol, 0x10)
                except ValueError:
                    # failed to parse as integer
                    continue

                # handling continues below at label: has a value

            else:
                continue

        elif len(operand.expression_index) == 1:
            # - type: IMMEDIATE_INT
            #   immediate: 20588728364
            #   parent_index: 0

            expression0 = be2.expression[operand.expression_index[0]]

            if BinExport2.Expression.Type.IMMEDIATE_INT != expression0.type:
                continue

            value = expression0.immediate

            # handling continues below at label: has a value

        elif len(operand.expression_index) == 2:
            # from IDA, which provides a size hint for every operand,
            # we get the following pattern for immediate constants:
            #
            # - type: SIZE_PREFIX
            #   symbol: "b8"
            # - type: IMMEDIATE_INT
            #   immediate: 20588728364
            #   parent_index: 0

            expression0 = be2.expression[operand.expression_index[0]]
            expression1 = be2.expression[operand.expression_index[1]]

            if BinExport2.Expression.Type.SIZE_PREFIX != expression0.type:
                continue

            if BinExport2.Expression.Type.IMMEDIATE_INT != expression1.type:
                continue

            value = expression1.immediate

            # handling continues below at label: has a value

        else:
            continue

        # label: has a value

        if analysis.base_address == 0x0:
            # When the image is mapped at 0x0,
            #  then its hard to tell if numbers are pointers or numbers.
            # TODO(mr): 1755 be a little less conservative otherwise?

            # TODO(mr): 1755 this removes a lot of valid numbers, could check alignment and use additional heuristics
            # if is_address_mapped(be2, value):
            #     continue
            pass

        yield Number(value), ih.address
        yield OperandNumber(i, value), ih.address


def extract_insn_bytes_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    ctx = fhi.ctx
    be2 = ctx.be2
    idx = ctx.idx
    address_space = ctx.address_space

    instruction_index = ii.instruction_index

    if instruction_index in idx.string_reference_index_by_source_instruction_index:
        # disassembler already identified string reference from instruction
        return

    reference_addresses: List[int] = []

    if instruction_index in idx.data_reference_index_by_source_instruction_index:
        for data_reference_index in idx.data_reference_index_by_source_instruction_index[instruction_index]:
            data_reference = be2.data_reference[data_reference_index]
            data_reference_address = data_reference.address

            reference_addresses.append(data_reference_address)

    for reference_address in reference_addresses:
        try:
            # if at end of segment then there might be an overrun here.
            buf = address_space.read_memory(reference_address, 0x100)
        except ReadMemoryError:
            logger.debug("failed to read memory: 0x%x", reference_address)
            continue

        if capa.features.extractors.helpers.all_zeros(buf):
            continue

        is_string = False

        # note: we *always* break after the first iteration
        for s in capa.features.extractors.strings.extract_ascii_strings(buf):
            if s.offset != 0:
                break

            yield String(s.s), ih.address
            is_string = True
            break

        # note: we *always* break after the first iteration
        for s in capa.features.extractors.strings.extract_unicode_strings(buf):
            if s.offset != 0:
                break

            yield String(s.s), ih.address
            is_string = True
            break

        if not is_string:
            yield Bytes(buf), ih.address


def extract_insn_string_features(
    fh: FunctionHandle, _bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2 = fhi.ctx.be2
    idx = fhi.ctx.idx

    instruction_index = ii.instruction_index

    if instruction_index in idx.string_reference_index_by_source_instruction_index:
        for string_reference_index in idx.string_reference_index_by_source_instruction_index[instruction_index]:
            string_reference = be2.string_reference[string_reference_index]
            string_index = string_reference.string_table_index
            string = be2.string_table[string_index]
            yield String(string), ih.address


def extract_insn_offset_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_insn_mnemonic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2 = fhi.ctx.be2

    instruction = be2.instruction[ii.instruction_index]
    mnemonic = be2.mnemonic[instruction.mnemonic_index]
    mnemonic_name = mnemonic.name.lower()
    yield Mnemonic(mnemonic_name), ih.address


def extract_function_calls_from(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope;
    however, its most efficient to extract at the instruction scope.
    """
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2 = fhi.ctx.be2

    instruction = be2.instruction[ii.instruction_index]
    for call_target_address in instruction.call_target:
        addr = AbsoluteVirtualAddress(call_target_address)
        yield Characteristic("calls from"), addr

        if fh.address == addr:
            yield Characteristic("recursive call"), addr


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_features(f: FunctionHandle, bbh: BBHandle, insn: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract instruction features"""
    for inst_handler in INSTRUCTION_HANDLERS:
        for feature, ea in inst_handler(f, bbh, insn):
            yield feature, ea


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_bytes_features,
    extract_insn_string_features,
    extract_insn_offset_features,
    extract_insn_nzxor_characteristic_features,
    extract_insn_mnemonic_features,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
)
