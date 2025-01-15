# Copyright 2023 Google LLC
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

import capa.features.extractors.helpers
import capa.features.extractors.strings
import capa.features.extractors.binexport2.helpers
import capa.features.extractors.binexport2.arch.arm.insn
import capa.features.extractors.binexport2.arch.intel.insn
from capa.features.insn import API, Mnemonic
from capa.features.common import Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.binexport2 import (
    AddressSpace,
    AnalysisContext,
    BinExport2Index,
    FunctionContext,
    ReadMemoryError,
    BinExport2Analysis,
    InstructionContext,
)
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.binexport2.helpers import HAS_ARCH_ARM, HAS_ARCH_INTEL
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def extract_insn_api_features(fh: FunctionHandle, _bbh: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2
    be2_index: BinExport2Index = fhi.ctx.idx
    be2_analysis: BinExport2Analysis = fhi.ctx.analysis
    insn: BinExport2.Instruction = be2.instruction[ii.instruction_index]

    for addr in insn.call_target:
        addr = be2_analysis.thunks.get(addr, addr)

        if addr not in be2_index.vertex_index_by_address:
            # disassembler did not define function at address
            logger.debug("0x%x is not a vertex", addr)
            continue

        vertex_idx: int = be2_index.vertex_index_by_address[addr]
        vertex: BinExport2.CallGraph.Vertex = be2.call_graph.vertex[vertex_idx]

        if not capa.features.extractors.binexport2.helpers.is_vertex_type(
            vertex, BinExport2.CallGraph.Vertex.Type.IMPORTED
        ):
            continue

        if not vertex.HasField("mangled_name"):
            logger.debug("vertex %d does not have mangled_name", vertex_idx)
            continue

        api_name: str = vertex.mangled_name
        for name in capa.features.extractors.helpers.generate_symbols("", api_name):
            yield API(name), ih.address


def extract_insn_number_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner

    if fhi.arch & HAS_ARCH_INTEL:
        yield from capa.features.extractors.binexport2.arch.intel.insn.extract_insn_number_features(fh, bbh, ih)
    elif fhi.arch & HAS_ARCH_ARM:
        yield from capa.features.extractors.binexport2.arch.arm.insn.extract_insn_number_features(fh, bbh, ih)


def extract_insn_bytes_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    ctx: AnalysisContext = fhi.ctx
    be2: BinExport2 = ctx.be2
    idx: BinExport2Index = ctx.idx
    address_space: AddressSpace = ctx.address_space

    instruction_index: int = ii.instruction_index

    if instruction_index in idx.string_reference_index_by_source_instruction_index:
        # disassembler already identified string reference from instruction
        return

    reference_addresses: list[int] = []

    if instruction_index in idx.data_reference_index_by_source_instruction_index:
        for data_reference_index in idx.data_reference_index_by_source_instruction_index[instruction_index]:
            data_reference: BinExport2.DataReference = be2.data_reference[data_reference_index]
            data_reference_address: int = data_reference.address

            if data_reference_address in idx.insn_address_by_index:
                # appears to be code
                continue

            reference_addresses.append(data_reference_address)

    for reference_address in reference_addresses:
        try:
            # if at end of segment then there might be an overrun here.
            buf: bytes = address_space.read_memory(reference_address, 0x100)
        except ReadMemoryError:
            logger.debug("failed to read memory: 0x%x", reference_address)
            continue

        if capa.features.extractors.helpers.all_zeros(buf):
            continue

        is_string: bool = False

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
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2
    idx: BinExport2Index = fhi.ctx.idx

    instruction_index: int = ii.instruction_index

    if instruction_index in idx.string_reference_index_by_source_instruction_index:
        for string_reference_index in idx.string_reference_index_by_source_instruction_index[instruction_index]:
            string_reference: BinExport2.Reference = be2.string_reference[string_reference_index]
            string_index: int = string_reference.string_table_index
            string: str = be2.string_table[string_index]
            yield String(string), ih.address


def extract_insn_offset_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner

    if fhi.arch & HAS_ARCH_INTEL:
        yield from capa.features.extractors.binexport2.arch.intel.insn.extract_insn_offset_features(fh, bbh, ih)
    elif fhi.arch & HAS_ARCH_ARM:
        yield from capa.features.extractors.binexport2.arch.arm.insn.extract_insn_offset_features(fh, bbh, ih)


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner

    if fhi.arch & HAS_ARCH_INTEL:
        yield from capa.features.extractors.binexport2.arch.intel.insn.extract_insn_nzxor_characteristic_features(
            fh, bbh, ih
        )
    elif fhi.arch & HAS_ARCH_ARM:
        yield from capa.features.extractors.binexport2.arch.arm.insn.extract_insn_nzxor_characteristic_features(
            fh, bbh, ih
        )


def extract_insn_mnemonic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]
    mnemonic: BinExport2.Mnemonic = be2.mnemonic[instruction.mnemonic_index]
    mnemonic_name: str = mnemonic.name.lower()
    yield Mnemonic(mnemonic_name), ih.address


def extract_function_calls_from(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope;
    however, its most efficient to extract at the instruction scope.
    """
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2: BinExport2 = fhi.ctx.be2

    instruction: BinExport2.Instruction = be2.instruction[ii.instruction_index]
    for call_target_address in instruction.call_target:
        addr: AbsoluteVirtualAddress = AbsoluteVirtualAddress(call_target_address)
        yield Characteristic("calls from"), addr

        if fh.address == addr:
            yield Characteristic("recursive call"), addr


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner

    if fhi.arch & HAS_ARCH_INTEL:
        yield from capa.features.extractors.binexport2.arch.intel.insn.extract_function_indirect_call_characteristic_features(
            fh, bbh, ih
        )
    elif fhi.arch & HAS_ARCH_ARM:
        yield from capa.features.extractors.binexport2.arch.arm.insn.extract_function_indirect_call_characteristic_features(
            fh, bbh, ih
        )


def extract_features(f: FunctionHandle, bbh: BBHandle, insn: InsnHandle) -> Iterator[tuple[Feature, Address]]:
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
