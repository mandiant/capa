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
from ghidra.program.model.block import BasicBlockModel, SimpleBlockModel, SimpleBlockIterator

import capa.features.extractors.helpers
import capa.features.extractors.ghidra.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import MAX_BYTES_FEATURE_SIZE, Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40

# significantly cut down on runtime by caching api info
imports = capa.features.extractors.ghidra.helpers.get_file_imports()
externs = capa.features.extractors.ghidra.helpers.get_file_externs()
mapped_fake_addrs = capa.features.extractors.ghidra.helpers.map_fake_import_addrs()
external_locs = capa.features.extractors.ghidra.helpers.get_external_locs()


def check_for_api_call(insn, funcs: Dict[int, Any]) -> Iterator[Any]:
    """check instruction for API call"""
    info = ()

    # assume only CALLs or JMPs are passed
    ref_type = insn.getOperandType(0)
    addr_data = OperandType.ADDRESS | OperandType.DATA  # needs dereferencing

    if OperandType.isRegister(ref_type):
        if OperandType.isAddress(ref_type):
            # If it's an address in a register, check the mapped fake addrs
            # since they're dereferenced to their fake addrs
            op_ref = insn.getAddress(0).getOffset()
            ref = mapped_fake_addrs.get(op_ref)  # obtain the real addr
            if not ref:
                return
        else:
            return
    elif ref_type == addr_data:
        # we must dereference and check if the addr is a pointer to an api function
        addr_ref = capa.features.extractors.ghidra.helpers.dereference_ptr(insn)
        if addr_ref != insn.getAddress(0):
            if not capa.features.extractors.ghidra.helpers.check_addr_for_api(
                addr_ref, mapped_fake_addrs, imports, externs, external_locs
            ):
                return
            ref = addr_ref.getOffset()
        else:
            # could not dereference
            return
    elif ref_type == OperandType.DYNAMIC | OperandType.ADDRESS or ref_type == OperandType.DYNAMIC:
        return  # cannot resolve dynamics statically
    elif OperandType.isIndirect(ref_type):
        return  # cannot resolve the indirection statically
    else:
        # pure address does not need to get dereferenced/ handled
        addr_ref = insn.getAddress(0)
        if not capa.features.extractors.ghidra.helpers.check_addr_for_api(
            addr_ref, mapped_fake_addrs, imports, externs, external_locs
        ):
            return
        ref = addr_ref.getOffset()

    info = funcs.get(ref)  # type: ignore
    if info:
        yield info


def extract_insn_api_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    if not capa.features.extractors.ghidra.helpers.is_call_or_jmp(insn):
        return

    # check calls to imported functions
    for api in check_for_api_call(insn, imports):
        yield API(api), AbsoluteVirtualAddress(insn.getAddress().getOffset())

    # check calls to extern functions
    for api in check_for_api_call(insn, externs):
        yield API(api), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_number_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
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


def extract_insn_offset_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
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
                if isinstance(op_objs[-1], ghidra.program.model.scalar.Scalar):
                    op_off = op_objs[-1].getValue()
                    yield Offset(op_off), AbsoluteVirtualAddress(insn.getAddress().getOffset())
                    yield OperandOffset(i, op_off), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_bytes_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse referenced byte sequences
    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """

    if capa.features.extractors.ghidra.helpers.is_call_or_jmp(insn):
        return

    ref = insn.getAddress()  # init to insn addr
    for i in range(insn.getNumOperands()):
        if OperandType.isScalarAsAddress(insn.getOperandType(i)):
            ref = insn.getAddress(i)  # pulls pointer if there is one

    if ref != insn.getAddress():  # bail out if there's no pointer
        ghidra_dat = getDataAt(ref)  # type: ignore [name-defined] # noqa: F821
        if (
            ghidra_dat and not ghidra_dat.hasStringValue() and not ghidra_dat.isPointer()
        ):  # avoid if the data itself is a pointer
            extracted_bytes = capa.features.extractors.ghidra.helpers.get_bytes(ref, MAX_BYTES_FEATURE_SIZE)
            if extracted_bytes and not capa.features.extractors.helpers.all_zeros(extracted_bytes):
                # don't extract byte features for obvious strings
                yield Bytes(extracted_bytes), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_string_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction string features

    example:
        push offset aAcr     ; "ACR  > "
    """
    ref = insn.getAddress()
    for i in range(insn.getNumOperands()):
        if OperandType.isScalarAsAddress(insn.getOperandType(i)):
            ref = insn.getAddress(i)

    if ref != insn.getAddress():
        ghidra_dat = getDataAt(ref)  # type: ignore [name-defined] # noqa: F821
        if ghidra_dat and ghidra_dat.hasStringValue():
            yield String(ghidra_dat.getValue()), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_mnemonic_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction mnemonic features"""
    yield Mnemonic(insn.getMnemonicString().lower()), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_obfs_call_plus_5_characteristic_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse call $+5 instruction from the given instruction.
    """

    if not capa.features.extractors.ghidra.helpers.is_call_or_jmp(insn):
        return

    code_ref = OperandType.ADDRESS | OperandType.CODE
    ref = insn.getAddress()
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == code_ref:
            ref = insn.getAddress(i)

    if insn.getAddress().add(5) == ref:
        yield Characteristic("call $+5"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_segment_access_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction fs or gs access"""
    insn_str = insn.toString()

    if "FS:" in insn_str:
        yield Characteristic("fs access"), AbsoluteVirtualAddress(insn.getAddress().getOffset())

    if "GS:" in insn_str:
        yield Characteristic("gs access"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_peb_access_characteristic_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64

    """
    insn_str = insn.toString()
    if insn_str.startswith(("PUSH", "MOV")):
        if "FS:[0x30]" in insn_str or "GS:[0x60]" in insn_str:
            yield Characteristic("peb access"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_insn_cross_section_cflow(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """inspect the instruction for a CALL or JMP that crosses section boundaries"""

    if not capa.features.extractors.ghidra.helpers.is_call_or_jmp(insn):
        return

    # OperandType to dereference
    addr_data = OperandType.ADDRESS | OperandType.DATA

    ref_type = insn.getOperandType(0)

    # both OperandType flags must be present
    # bail on REGISTER alone
    if OperandType.isRegister(ref_type):
        if OperandType.isAddress(ref_type):
            ref = insn.getAddress(0)  # Ghidra dereferences REG | ADDR
            if capa.features.extractors.ghidra.helpers.check_addr_for_api(
                ref, mapped_fake_addrs, imports, externs, external_locs
            ):
                return
        else:
            return
    elif ref_type == addr_data:
        # we must dereference and check if the addr is a pointer to an api function
        ref = capa.features.extractors.ghidra.helpers.dereference_ptr(insn)
        if ref != insn.getAddress(0):
            if capa.features.extractors.ghidra.helpers.check_addr_for_api(
                ref, mapped_fake_addrs, imports, externs, external_locs
            ):
                return
        else:
            # could not dereference
            return
    elif ref_type == OperandType.DYNAMIC | OperandType.ADDRESS or ref_type == OperandType.DYNAMIC:
        return  # cannot resolve dynamics statically
    elif OperandType.isIndirect(ref_type):
        return  # cannot resolve the indirection statically
    else:
        # pure address does not need to get dereferenced/ handled
        ref = insn.getAddress(0)
        if capa.features.extractors.ghidra.helpers.check_addr_for_api(
            ref, mapped_fake_addrs, imports, externs, external_locs
        ):
            return

    this_mem_block = getMemoryBlock(insn.getAddress())  # type: ignore [name-defined] # noqa: F821
    ref_block = getMemoryBlock(ref)  # type: ignore [name-defined] # noqa: F821
    if ref_block != this_mem_block:
        yield Characteristic("cross section flow"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_function_calls_from(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope
    """

    if insn.getMnemonicString().startswith("CALL"):
        # This method of "dereferencing" addresses/ pointers
        # is not as robust as methods in other functions,
        # but works just fine for this one
        for ref in insn.getReferencesFrom():
            reference = ref.getToAddress().getOffset()

            # avoid returning fake addrs
            check = mapped_fake_addrs.get(reference)
            if check:
                reference = check

            # if a reference is < 0, then ghidra pulled an offset from a DYNAMIC | ADDR (usually a stackvar)
            # these cannot be resolved to actual addrs
            if reference >= 0:
                yield Characteristic("calls from"), AbsoluteVirtualAddress(reference)


def extract_function_indirect_call_characteristic_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    """extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974

    most relevant at the function or basic block scope;
    however, its most efficient to extract at the instruction scope
    """
    if insn.getMnemonicString().startswith("CALL"):
        if OperandType.isIndirect(insn.getOperandType(0)):
            yield Characteristic("indirect call"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def check_nzxor_security_cookie_delta(
    fh: ghidra.program.database.function.FunctionDB, insn: ghidra.program.database.code.InstructionDB
):
    """Get the function containing the insn
    Get the last block of the function that contains the insn

    Check the bb containing the insn
    Check the last bb of the function containing the insn
    """

    model = SimpleBlockModel(currentProgram)  # type: ignore [name-defined] # noqa: F821
    insn_addr = insn.getAddress()
    func_asv = fh.getBody()
    first_addr = func_asv.getMinAddress()
    last_addr = func_asv.getMaxAddress()

    if model.getFirstCodeBlockContaining(first_addr, monitor) == model.getFirstCodeBlockContaining(last_addr, monitor):  # type: ignore [name-defined] # noqa: F821
        if insn_addr < first_addr.add(SECURITY_COOKIE_BYTES_DELTA):
            return True
        else:
            return insn_addr > last_addr.add(SECURITY_COOKIE_BYTES_DELTA * -1)
    else:
        return False


def extract_insn_nzxor_characteristic_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    if "XOR" not in insn.getMnemonicString():
        return
    if capa.features.extractors.ghidra.helpers.is_stack_referenced(insn):
        return
    if capa.features.extractors.ghidra.helpers.is_zxor(insn):
        return
    if check_nzxor_security_cookie_delta(fh, insn):
        return
    yield Characteristic("nzxor"), AbsoluteVirtualAddress(insn.getAddress().getOffset())


def extract_features(
    fh: ghidra.program.database.function.FunctionDB,
    bb: ghidra.program.model.block.CodeBlock,
    insn: ghidra.program.database.code.InstructionDB,
) -> Iterator[Tuple[Feature, Address]]:
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature, addr in insn_handler(fh, bb, insn):
            yield feature, addr


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_bytes_features,
    extract_insn_string_features,
    extract_insn_offset_features,
    extract_insn_nzxor_characteristic_features,
    extract_insn_mnemonic_features,
    extract_insn_obfs_call_plus_5_characteristic_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_insn_segment_access_features,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
)


def main():
    """ """
    listing = currentProgram.getListing()  # type: ignore [name-defined] # noqa: F821
    features = []
    for fh in capa.features.extractors.ghidra.helpers.get_function_symbols():
        for bb in SimpleBlockIterator(BasicBlockModel(currentProgram), fh.getBody(), monitor):  # type: ignore [name-defined] # noqa: F821
            for insn in listing.getInstructions(bb, True):
                features.extend(list(extract_features(fh, bb, insn)))

    import pprint

    pprint.pprint(features)  # noqa: T203


if __name__ == "__main__":
    main()
