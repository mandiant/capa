# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Any, Dict, Tuple, Iterator

import ghidra
from ghidra.program.model.lang import OperandType
from ghidra.program.model.block import SimpleBlockModel

import capa.features.extractors.helpers
import capa.features.extractors.ghidra.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import MAX_BYTES_FEATURE_SIZE, Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40

listing = currentProgram.getListing()  # type: ignore [name-defined] # noqa: F821

# significantly cut down on runtime
imports = capa.features.extractors.ghidra.helpers.get_file_imports()
externs = capa.features.extractors.ghidra.helpers.get_file_externs()


def check_for_api_call(insn, funcs: Dict[int, Any]) -> Iterator[Any]:
    """check instruction for API call"""
    info = ()
    code_ref = OperandType.ADDRESS | OperandType.CODE
    data_ref = OperandType.ADDRESS | OperandType.DATA

    # assume only CALLs or JMPs are passed
    ref_type = insn.getOperandType(0)
    if ref_type != code_ref:
        if ref_type != data_ref:
            return

    ref = insn.getAddress(0).getOffset()
    info = funcs.get(ref)  # type: ignore

    if info:
        yield info


def extract_insn_api_features(insn) -> Iterator[Tuple[Feature, Address]]:
    insn_str = insn.getMnemonicString()
    if not (insn_str.startswith("CALL") or insn_str.startswith("J")):
        return

    # check calls to imported functions
    for api in check_for_api_call(insn, imports):
        yield API(api), AbsoluteVirtualAddress(insn.getAddress().getOffset())

    # check calls to extern functions
    for api in check_for_api_call(insn, externs):
        yield API(api), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_number_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction number features
    example:
        push    3136B0h         ; dwControlCode
    """
    if insn.getMnemonicString().startswith("RET"):
        # skip things like:
        #   .text:0042250E retn 8
        return

    if capa.features.extractors.ghidra.helpers.is_sp_modified(insn):
        # skip things like:
        #   .text:00401145 add esp, 0Ch
        return

    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) != OperandType.SCALAR:
            # skip things like:
            #   references, void types
            continue

        const = insn.getScalar(i).getValue()
        addr = AbsoluteVirtualAddress(insn.getAddress().getOffset())

        yield Number(const), addr
        yield OperandNumber(i, const), addr

        if insn.getMnemonicString().startswith("ADD") and 0 < const < MAX_STRUCTURE_SIZE:
            # for pattern like:
            #
            #     add eax, 0x10
            #
            # assume 0x10 is also an offset (imagine eax is a pointer).
            yield Offset(const), addr
            yield OperandOffset(i, const), addr


def extract_insn_offset_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction structure offset features

    example:
        .text:0040112F cmp [esi+4], ebx
    """

    # ignore any stack references
    if not capa.features.extractors.ghidra.helpers.is_stack_referenced(insn):
        # Ghidra stores operands in 2D arrays if they contain offsets
        for i in range(insn.getNumOperands()):
            if insn.getOperandType(i) == OperandType.DYNAMIC:  # e.g. [esi + 4]
                # manual extraction, since the default api calls only work on the 1st dimension of the array
                op_objs = insn.getOpObjects(i)
                for j in range(len(op_objs)):
                    if isinstance(op_objs[j], ghidra.program.model.scalar.Scalar):
                        op_off = op_objs[j].getValue()
                        yield Offset(op_off), AbsoluteVirtualAddress(insn.getAddress().getOffset())
                        yield OperandOffset(i, op_off), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_bytes_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """
    parse referenced byte sequences
    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """

    if insn.getMnemonicString().startswith("CALL"):
        return

    data_ref = OperandType.ADDRESS | OperandType.SCALAR  # DAT_* or s_*
    ref = insn.getAddress()
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == data_ref:
            ref = insn.getAddress(i)

    if ref != insn.getAddress():
        extracted_bytes = capa.features.extractors.ghidra.helpers.get_bytes(ref, MAX_BYTES_FEATURE_SIZE)
        if extracted_bytes and not capa.features.extractors.helpers.all_zeros(extracted_bytes):
            ghidra_dat = getDataAt(ref)  # type: ignore [name-defined] # noqa: F821
            if ghidra_dat and not ghidra_dat.hasStringValue():
                # don't extract byte features for obvious strings
                yield Bytes(extracted_bytes), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_string_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction string features

    example:
        push offset aAcr     ; "ACR  > "
    """
    data_ref = OperandType.ADDRESS | OperandType.SCALAR  # DAT_* or s_*
    ref = insn.getAddress()
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == data_ref:
            ref = insn.getAddress(i)

    if ref != insn.getAddress():
        ghidra_dat = getDataAt(ref)  # type: ignore [name-defined] # noqa: F821
        if ghidra_dat and ghidra_dat.hasStringValue():
            yield String(ghidra_dat.getValue()), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_mnemonic_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction mnemonic features"""
    yield Mnemonic(insn.getMnemonicString().lower()), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_obfs_call_plus_5_characteristic_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """
    parse call $+5 instruction from the given instruction.
    """

    if not insn.getMnemonicString().startswith("CALL"):
        return

    code_ref = OperandType.ADDRESS | OperandType.CODE
    ref = insn.getAddress()
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == code_ref:
            ref = insn.getAddress(i)

    if insn.getAddress().add(5) == ref:
        yield Characteristic("call $+5"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_segment_access_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction fs or gs access"""
    insn_str = insn.toString()

    if "FS:" in insn_str:
        yield Characteristic("fs access"), AbsoluteVirtualAddress(insn.getAddress().getOffset())

    if "GS:" in insn_str:
        yield Characteristic("gs access"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_peb_access_characteristic_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64

    """
    insn_str = insn.toString()
    if insn_str.startswith("PUSH") or insn_str.startswith("MOV"):
        if "FS:[0x30]" in insn_str or "GS:[0x60]" in insn_str:
            yield Characteristic("peb access"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_cross_section_cflow(insn) -> Iterator[Tuple[Feature, Address]]:
    """inspect the instruction for a CALL or JMP that crosses section boundaries"""

    code_ref = OperandType.ADDRESS | OperandType.CODE
    data_ref = OperandType.ADDRESS | OperandType.DATA

    insn_str = insn.getMnemonicString()
    if not (insn_str.startswith("CALL") or insn_str.startswith("J")):
        return

    this_mem_block = getMemoryBlock(insn.getAddress()).getName()  # type: ignore [name-defined] # noqa: F821

    # assume only CALLs or JMPs are passed
    ref_type = insn.getOperandType(0)
    if ref_type != code_ref:
        if ref_type != data_ref:
            return

    ref_block = getMemoryBlock(insn.getAddress(0)).getName()  # type: ignore [name-defined] # noqa: F821
    if ref_block != this_mem_block:
        yield Characteristic("cross section flow"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_function_calls_from(insn) -> Iterator[Tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope
    """

    if insn.getMnemonicString().startswith("CALL"):
        code_ref = OperandType.ADDRESS | OperandType.CODE
        data_ref = OperandType.ADDRESS | OperandType.DATA

        ref_type = insn.getOperandType(0)
        if ref_type != code_ref:
            if ref_type != data_ref:
                return

        ref = insn.getAddress(0).getOffset()

        yield Characteristic("calls from"), AbsoluteVirtualAddress(ref)


def extract_function_indirect_call_characteristic_features(insn) -> Iterator[Tuple[Feature, Address]]:
    """extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974

    most relevant at the function or basic block scope;
    however, its most efficient to extract at the instruction scope
    """
    if insn.getMnemonicString().startswith("CALL"):
        code_ref = OperandType.ADDRESS | OperandType.CODE
        data_ref = OperandType.ADDRESS | OperandType.DATA

        ref_type = insn.getOperandType(0)
        if ref_type != code_ref:
            if ref_type != data_ref:
                yield Characteristic("indirect call"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def check_nzxor_security_cookie_delta(insn):
    """Get the function containing the insn
    Get the last block of the function that contains the insn

    Check the bb containing the insn
    Check the last bb of the function containing the insn
    """
    model = SimpleBlockModel(currentProgram)  # type: ignore [name-defined] # noqa: F821
    insn_addr = insn.getAddress()

    func = currentProgram.getFunctionManager().getFunctionContaining(insn_addr)  # type: ignore [name-defined] # noqa: F821
    if func:
        first_addr = func.getBody().getMinAddress()
        last_addr = func.getBody().getMaxAddress()
    else:
        return False

    if model.getFirstCodeBlockContaining(first_addr, monitor) == model.getFirstCodeBlockContaining(last_addr, monitor):  # type: ignore [name-defined] # noqa: F821
        if insn_addr < first_addr.add(SECURITY_COOKIE_BYTES_DELTA):
            return True
        else:
            return insn_addr > last_addr.add(SECURITY_COOKIE_BYTES_DELTA * -1)


def extract_insn_nzxor_characteristic_features(insn) -> Iterator[Tuple[Feature, Address]]:
    if not insn.getMnemonicString().startswith("XOR"):
        return
    if capa.features.extractors.ghidra.helpers.is_stack_referenced(insn):
        return
    if capa.features.extractors.ghidra.helpers.is_zxor(insn):
        return
    if check_nzxor_security_cookie_delta(insn):
        return
    yield Characteristic("nzxor"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_features(insn: ghidra.program.database.code.InstructionDB) -> Iterator[Tuple[Feature, Address]]:
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature, addr in insn_handler(insn):
            yield feature, addr


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_offset_features,
    extract_insn_mnemonic_features,
    extract_insn_bytes_features,
    extract_insn_string_features,
    extract_insn_obfs_call_plus_5_characteristic_features,
    extract_insn_segment_access_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
    extract_insn_nzxor_characteristic_features,
)


def main():
    """ """
    features = []
    for insn in listing.getInstructions(True):
        features.extend(list(extract_features(insn)))

    import pprint

    pprint.pprint(features)  # noqa: T203


if __name__ == "__main__":
    main()
