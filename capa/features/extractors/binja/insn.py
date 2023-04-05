# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
from typing import Any, Dict, List, Tuple, Iterator, Optional

from binaryninja import Function
from binaryninja import BasicBlock as BinjaBasicBlock
from binaryninja import (
    BinaryView,
    ILRegister,
    SymbolType,
    BinaryReader,
    RegisterValueType,
    LowLevelILOperation,
    LowLevelILInstruction,
    InstructionTextTokenType,
)

import capa.features.extractors.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import MAX_BYTES_FEATURE_SIZE, THUNK_CHAIN_DEPTH_DELTA, Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.binja.helpers import DisassemblyInstruction, visit_llil_exprs
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40


# check if a function is a stub function to another function/symbol. The criteria is:
# 1. The function must only have one basic block
# 2. The function must only make one call/jump to another address
# If the function being checked is a stub function, returns the target address. Otherwise, return None.
def is_stub_function(bv: BinaryView, addr: int) -> Optional[int]:
    funcs = bv.get_functions_at(addr)
    for func in funcs:
        if len(func.basic_blocks) != 1:
            continue

        call_count = 0
        call_target = None
        for il in func.llil.instructions:
            if il.operation in [
                LowLevelILOperation.LLIL_CALL,
                LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
                LowLevelILOperation.LLIL_JUMP,
                LowLevelILOperation.LLIL_TAILCALL,
            ]:
                call_count += 1
                if il.dest.value.type in [
                    RegisterValueType.ImportedAddressValue,
                    RegisterValueType.ConstantValue,
                    RegisterValueType.ConstantPointerValue,
                ]:
                    call_target = il.dest.value.value

        if call_count == 1 and call_target is not None:
            return call_target

    return None


def extract_insn_api_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction API features

    example:
       call dword [0x00473038]
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner
    bv: BinaryView = func.view

    for llil in func.get_llils_at(ih.address):
        if llil.operation in [
            LowLevelILOperation.LLIL_CALL,
            LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
            LowLevelILOperation.LLIL_JUMP,
            LowLevelILOperation.LLIL_TAILCALL,
        ]:
            if llil.dest.value.type not in [
                RegisterValueType.ImportedAddressValue,
                RegisterValueType.ConstantValue,
                RegisterValueType.ConstantPointerValue,
            ]:
                continue
            address = llil.dest.value.value
            candidate_addrs = [address]
            stub_addr = is_stub_function(bv, address)
            if stub_addr is not None:
                candidate_addrs.append(stub_addr)

            for address in candidate_addrs:
                sym = func.view.get_symbol_at(address)
                if sym is None or sym.type not in [SymbolType.ImportAddressSymbol, SymbolType.ImportedFunctionSymbol]:
                    continue

                sym_name = sym.short_name

                lib_name = ""
                import_lib = bv.lookup_imported_object_library(sym.address)
                if import_lib is not None:
                    lib_name = import_lib[0].name
                    if lib_name.endswith(".dll"):
                        lib_name = lib_name[:-4]
                    elif lib_name.endswith(".so"):
                        lib_name = lib_name[:-3]

                for name in capa.features.extractors.helpers.generate_symbols(lib_name, sym_name):
                    yield API(name), ih.address

                if sym_name.startswith("_"):
                    for name in capa.features.extractors.helpers.generate_symbols(lib_name, sym_name[1:]):
                        yield API(name), ih.address


def extract_insn_number_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction number features
    example:
        push    3136B0h         ; dwControlCode
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner
    bv: BinaryView = func.view

    results: List[Tuple[Any[Number, OperandNumber], Address]] = []
    address_size = func.view.arch.address_size * 8

    def llil_checker(il: LowLevelILInstruction, parent: LowLevelILInstruction, index: int) -> bool:
        if il.operation == LowLevelILOperation.LLIL_LOAD:
            return False

        if il.operation not in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR]:
            return True

        for op in parent.operands:
            if isinstance(op, ILRegister) and op.name in ["esp", "ebp", "rsp", "rbp", "sp"]:
                return False
            elif isinstance(op, LowLevelILInstruction) and op.operation == LowLevelILOperation.LLIL_REG:
                if op.src.name in ["esp", "ebp", "rsp", "rbp", "sp"]:
                    return False

        raw_value = il.value.value
        if parent.operation == LowLevelILOperation.LLIL_SUB:
            raw_value = -raw_value

        results.append((Number(raw_value), ih.address))
        results.append((OperandNumber(index, raw_value), ih.address))

        return False

    for llil in func.get_llils_at(ih.address):
        visit_llil_exprs(llil, llil_checker)

    for result in results:
        yield result


def extract_insn_bytes_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse referenced byte sequences
    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner
    bv: BinaryView = func.view

    candidate_addrs = set()

    llil = func.get_llil_at(ih.address)
    if llil is None or llil.operation in [LowLevelILOperation.LLIL_CALL, LowLevelILOperation.LLIL_CALL_STACK_ADJUST]:
        return

    for ref in bv.get_code_refs_from(ih.address):
        if ref == ih.address:
            continue

        if len(bv.get_functions_containing(ref)) > 0:
            continue

        candidate_addrs.add(ref)

    # collect candidate address by enumerating all integers, https://github.com/Vector35/binaryninja-api/issues/3966
    def llil_checker(il: LowLevelILInstruction, parent: LowLevelILInstruction, index: int) -> bool:
        if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR]:
            value = il.value.value
            if value > 0:
                candidate_addrs.add(value)
            return False

        return True

    for llil in func.get_llils_at(ih.address):
        visit_llil_exprs(llil, llil_checker)

    for addr in candidate_addrs:
        extracted_bytes = bv.read(addr, MAX_BYTES_FEATURE_SIZE)
        if extracted_bytes and not capa.features.extractors.helpers.all_zeros(extracted_bytes):
            if bv.get_string_at(addr) is None:
                # don't extract byte features for obvious strings
                yield Bytes(extracted_bytes), ih.address


def extract_insn_string_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction string features

    example:
        push offset aAcr     ; "ACR  > "
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner
    bv: BinaryView = func.view

    candidate_addrs = set()

    # collect candidate address from code refs directly
    for ref in bv.get_code_refs_from(ih.address):
        if ref == ih.address:
            continue

        if len(bv.get_functions_containing(ref)) > 0:
            continue

        candidate_addrs.add(ref)

    # collect candidate address by enumerating all integers, https://github.com/Vector35/binaryninja-api/issues/3966
    def llil_checker(il: LowLevelILInstruction, parent: LowLevelILInstruction, index: int) -> bool:
        if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR]:
            value = il.value.value
            if value > 0:
                candidate_addrs.add(value)
            return False

        return True

    for llil in func.get_llils_at(ih.address):
        visit_llil_exprs(llil, llil_checker)

    # Now we have all the candidate address, check them for string or pointer to string
    br = BinaryReader(bv)
    for addr in candidate_addrs:
        found = bv.get_string_at(addr)
        if found:
            yield String(found.value), ih.address

        br.seek(addr)
        pointer = None
        if bv.arch.address_size == 4:
            pointer = br.read32()
        elif bv.arch.address_size == 8:
            pointer = br.read64()

        if pointer is not None:
            found = bv.get_string_at(pointer)
            if found:
                yield String(found.value), ih.address


def extract_insn_offset_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction structure offset features

    example:
        .text:0040112F cmp [esi+4], ebx
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner

    results: List[Tuple[Any[Offset, OperandOffset], Address]] = []
    address_size = func.view.arch.address_size * 8

    def llil_checker(il: LowLevelILInstruction, parent: LowLevelILInstruction, index: int) -> bool:
        #  The most common case, read/write dereference to something like `dword [eax+0x28]`
        if il.operation in [LowLevelILOperation.LLIL_ADD, LowLevelILOperation.LLIL_SUB]:
            left = il.left
            right = il.right
            # Exclude offsets based on stack/franme pointers
            if left.operation == LowLevelILOperation.LLIL_REG and left.src.name in ["esp", "ebp", "rsp", "rbp", "sp"]:
                return True

            if right.operation != LowLevelILOperation.LLIL_CONST:
                return True

            raw_value = right.value.value
            # If this is not a dereference, then this must be an add and the offset must be in the range \
            # [0, MAX_STRUCTURE_SIZE]. For example,
            # add eax, 0x10,
            # lea ebx, [eax + 1]
            if parent.operation not in [LowLevelILOperation.LLIL_LOAD, LowLevelILOperation.LLIL_STORE]:
                if il.operation != LowLevelILOperation.LLIL_ADD or (not 0 < raw_value < MAX_STRUCTURE_SIZE):
                    return False

            if address_size > 0:
                # BN also encodes the constant value as two's complement, we need to restore its original value
                value = capa.features.extractors.helpers.twos_complement(raw_value, address_size)
            else:
                value = raw_value

            results.append((Offset(value), ih.address))
            results.append((OperandOffset(index, value), ih.address))
            return False

        # An edge case: for code like `push dword [esi]`, we need to generate a feature for offset 0x0
        elif il.operation in [LowLevelILOperation.LLIL_LOAD, LowLevelILOperation.LLIL_STORE]:
            if il.operands[0].operation == LowLevelILOperation.LLIL_REG:
                results.append((Offset(0), ih.address))
                results.append((OperandOffset(index, 0), ih.address))
                return False

        return True

    for llil in func.get_llils_at(ih.address):
        visit_llil_exprs(llil, llil_checker)

    for result in results:
        yield result


def is_nzxor_stack_cookie(f: Function, bb: BinjaBasicBlock, llil: LowLevelILInstruction) -> bool:
    """check if nzxor exists within stack cookie delta"""
    # TODO: we can do a much accurate analysi using LLIL SSA

    reg_names = []
    if llil.left.operation == LowLevelILOperation.LLIL_REG:
        reg_names.append(llil.left.src.name)

    if llil.right.operation == LowLevelILOperation.LLIL_REG:
        reg_names.append(llil.right.src.name)

    # stack cookie reg should be stack/frame pointer
    if not any(reg in ["ebp", "esp", "rbp", "rsp", "sp"] for reg in reg_names):
        return False

    # expect security cookie init in first basic block within first bytes (instructions)
    if len(bb.incoming_edges) == 0 and llil.address < (bb.start + SECURITY_COOKIE_BYTES_DELTA):
        return True

    # ... or within last bytes (instructions) before a return
    if len(bb.outgoing_edges) == 0 and llil.address > (bb.end - SECURITY_COOKIE_BYTES_DELTA):
        return True

    return False


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction non-zeroing XOR instruction
    ignore expected non-zeroing XORs, e.g. security cookies
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner

    results = []

    def llil_checker(il: LowLevelILInstruction, parent: LowLevelILInstruction, index: int) -> bool:
        # If the two operands of the xor instruction are the same, the LLIL will be translated to other instructions,
        # e.g., <llil: eax = 0>, (LLIL_SET_REG). So we do not need to check whether the two operands are the same.
        if il.operation == LowLevelILOperation.LLIL_XOR:
            # Exclude cases related to the stack cookie
            if is_nzxor_stack_cookie(fh.inner, bbh.inner[0], il):
                return False
            results.append((Characteristic("nzxor"), ih.address))
            return False
        else:
            return True

    for llil in func.get_llils_at(ih.address):
        visit_llil_exprs(llil, llil_checker)

    for result in results:
        yield result


def extract_insn_mnemonic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction mnemonic features"""
    insn: DisassemblyInstruction = ih.inner
    yield Mnemonic(insn.text[0].text), ih.address


def extract_insn_obfs_call_plus_5_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse call $+5 instruction from the given instruction.
    """
    insn: DisassemblyInstruction = ih.inner
    if insn.text[0].text == "call" and insn.text[2].text == "$+5" and insn.length == 5:
        yield Characteristic("call $+5"), ih.address


def extract_insn_peb_access_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner

    results = []

    def llil_checker(il: LowLevelILInstruction, parent: LowLevelILOperation, index: int) -> bool:
        if il.operation != LowLevelILOperation.LLIL_LOAD:
            return True

        src = il.src
        if src.operation != LowLevelILOperation.LLIL_ADD:
            return True

        left = src.left
        right = src.right

        if left.operation != LowLevelILOperation.LLIL_REG:
            return True

        reg = left.src.name

        if right.operation != LowLevelILOperation.LLIL_CONST:
            return True

        value = right.value.value
        if not (reg, value) in (("fsbase", 0x30), ("gsbase", 0x60)):
            return True

        results.append((Characteristic("peb access"), ih.address))
        return False

    for llil in func.get_llils_at(ih.address):
        visit_llil_exprs(llil, llil_checker)

    for result in results:
        yield result


def extract_insn_segment_access_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction fs or gs access"""
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner

    results = []

    def llil_checker(il: LowLevelILInstruction, parent: LowLevelILInstruction, index: int) -> bool:
        if il.operation == LowLevelILOperation.LLIL_REG:
            reg = il.src.name
            if reg == "fsbase":
                results.append((Characteristic("fs access"), ih.address))
                return False
            elif reg == "gsbase":
                results.append((Characteristic("gs access"), ih.address))
                return False
            return False

        return True

    for llil in func.get_llils_at(ih.address):
        visit_llil_exprs(llil, llil_checker)

    for result in results:
        yield result


def extract_insn_cross_section_cflow(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """inspect the instruction for a CALL or JMP that crosses section boundaries"""
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner
    bv: BinaryView = func.view

    if bv is None:
        return

    seg1 = bv.get_segment_at(ih.address)
    sections1 = bv.get_sections_at(ih.address)
    for ref in bv.get_code_refs_from(ih.address):
        if len(bv.get_functions_at(ref)) == 0:
            continue

        seg2 = bv.get_segment_at(ref)
        sections2 = bv.get_sections_at(ref)
        if seg1 != seg2 or sections1 != sections2:
            yield Characteristic("cross section flow"), ih.address


def extract_function_calls_from(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner
    bv: BinaryView = func.view

    if bv is None:
        return

    for il in func.get_llils_at(ih.address):
        if il.operation not in [
            LowLevelILOperation.LLIL_CALL,
            LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
            LowLevelILOperation.LLIL_TAILCALL,
        ]:
            continue

        dest = il.dest
        if dest.operation == LowLevelILOperation.LLIL_CONST_PTR:
            value = dest.value.value
            yield Characteristic("calls from"), AbsoluteVirtualAddress(value)
        elif dest.operation == LowLevelILOperation.LLIL_CONST:
            yield Characteristic("calls from"), AbsoluteVirtualAddress(dest.value)
        elif dest.operation == LowLevelILOperation.LLIL_LOAD:
            indirect_src = dest.src
            if indirect_src.operation == LowLevelILOperation.LLIL_CONST_PTR:
                value = indirect_src.value.value
                yield Characteristic("calls from"), AbsoluteVirtualAddress(value)
            elif indirect_src.operation == LowLevelILOperation.LLIL_CONST:
                yield Characteristic("calls from"), AbsoluteVirtualAddress(indirect_src.value)
        elif dest.operation == LowLevelILOperation.LLIL_REG:
            if dest.value.type in [
                RegisterValueType.ImportedAddressValue,
                RegisterValueType.ConstantValue,
                RegisterValueType.ConstantPointerValue,
            ]:
                yield Characteristic("calls from"), AbsoluteVirtualAddress(dest.value.value)


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974

    most relevant at the function or basic block scope;
    however, its most efficient to extract at the instruction scope
    """
    insn: DisassemblyInstruction = ih.inner
    func: Function = fh.inner

    llil = func.get_llil_at(ih.address)
    if llil is None or llil.operation not in [
        LowLevelILOperation.LLIL_CALL,
        LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
        LowLevelILOperation.LLIL_TAILCALL,
    ]:
        return

    if llil.dest.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR]:
        return

    if llil.dest.operation == LowLevelILOperation.LLIL_LOAD:
        src = llil.dest.src
        if src.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR]:
            return

    yield Characteristic("indirect call"), ih.address


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
    extract_insn_obfs_call_plus_5_characteristic_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_insn_segment_access_features,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
)


def main():
    """ """
    if len(sys.argv) < 2:
        return

    from binaryninja import BinaryViewType

    from capa.features.extractors.binja.extractor import BinjaFeatureExtractor

    bv: BinaryView = BinaryViewType.get_view_of_file(sys.argv[1])
    if bv is None:
        return

    features = []
    extractor = BinjaFeatureExtractor(bv)
    for fh in extractor.get_functions():
        for bbh in extractor.get_basic_blocks(fh):
            for insn in extractor.get_instructions(fh, bbh):
                features.extend(list(extract_features(fh, bbh, insn)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
