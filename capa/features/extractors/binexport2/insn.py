# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Tuple, Iterator

from capa.features.insn import API
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.binexport2 import FunctionContext, InstructionContext
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle


def extract_insn_api_features(fh: FunctionHandle, _bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    fhi: FunctionContext = fh.inner
    ii: InstructionContext = ih.inner

    be2 = fhi.be2

    insn = be2.instruction[ii.instruction_index]
    mnem = be2.mnemonic[insn.mnemonic_index]

    if mnem.name not in ("call", "jmp", "BL"):
        return

    if not insn.call_target:
        return

    address = insn.call_target[0]
    print(hex(insn.address), "->", hex(address))

    for vertex in be2.call_graph.vertex:
        # TODO: need an index here
        if vertex.address != address:
            continue

        if not vertex.mangled_name:
            continue

        yield API(name=vertex.mangled_name), AbsoluteVirtualAddress(address)

        if not vertex.HasField("library_index"):
            continue

        library = be2.library[vertex.library_index]
        lib_name = library.name.split("\\")[-1].split(".")[0]

        yield API(name=f"{lib_name}.{vertex.mangled_name}"), AbsoluteVirtualAddress(address)


def extract_insn_number_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_insn_bytes_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_insn_string_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


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
    # TODO(wb): 1755
    yield from ()


def extract_function_calls_from(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope
    """
    # TODO(wb): 1755
    yield from ()


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
