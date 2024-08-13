# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import re
from typing import Any, Dict, Tuple, Iterator, Optional

import idc
import ida_ua
import idaapi
import idautils

import capa.features.extractors.helpers
import capa.features.extractors.ida.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import MAX_BYTES_FEATURE_SIZE, THUNK_CHAIN_DEPTH_DELTA, Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40


def get_imports(ctx: Dict[str, Any]) -> Dict[int, Any]:
    if "imports_cache" not in ctx:
        ctx["imports_cache"] = capa.features.extractors.ida.helpers.get_file_imports()
    return ctx["imports_cache"]


def get_externs(ctx: Dict[str, Any]) -> Dict[int, Any]:
    if "externs_cache" not in ctx:
        ctx["externs_cache"] = capa.features.extractors.ida.helpers.get_file_externs()
    return ctx["externs_cache"]


def check_for_api_call(insn: idaapi.insn_t, funcs: Dict[int, Any]) -> Optional[Tuple[str, str]]:
    """check instruction for API call"""
    info = None
    ref = insn.ea

    # attempt to resolve API calls by following chained thunks to a reasonable depth
    for _ in range(THUNK_CHAIN_DEPTH_DELTA):
        # assume only one code/data ref when resolving "call" or "jmp"
        try:
            ref = tuple(idautils.CodeRefsFrom(ref, False))[0]
        except IndexError:
            try:
                # thunks may be marked as data refs
                ref = tuple(idautils.DataRefsFrom(ref))[0]
            except IndexError:
                break

        info = funcs.get(ref)
        if info:
            break

        f = idaapi.get_func(ref)
        if not f or not (f.flags & idaapi.FUNC_THUNK):
            break

    return info


def extract_insn_api_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction API features

    example:
       call dword [0x00473038]
    """
    insn: idaapi.insn_t = ih.inner

    if insn.get_canon_mnem() not in ("call", "jmp"):
        return

    # check call to imported functions
    api = check_for_api_call(insn, get_imports(fh.ctx))
    if api:
        # tuple (<module>, <function>, <ordinal>)
        for name in capa.features.extractors.helpers.generate_symbols(api[0], api[1]):
            yield API(name), ih.address
        # a call instruction should only call one function, stop if a call to an import is extracted
        return

    # check call to extern functions
    api = check_for_api_call(insn, get_externs(fh.ctx))
    if api:
        # tuple (<module>, <function>, <ordinal>)
        yield API(api[1]), ih.address
        # a call instruction should only call one function, stop if a call to an extern is extracted
        return

    # extract dynamically resolved APIs stored in renamed globals (renamed for example using `renimp.idc`)
    # examples: `CreateProcessA`, `HttpSendRequestA`
    if insn.Op1.type == ida_ua.o_mem:
        op_addr = insn.Op1.addr
        op_name = idaapi.get_name(op_addr)
        # when renaming a global using an API name, IDA assigns it the function type
        # ensure we do not extract something wrong by checking that the address has a name and a type
        # we could check that the type is a function definition, but that complicates the code
        if (not op_name.startswith("off_")) and idc.get_type(op_addr):
            # Remove suffix used in repeated names, for example _0 in VirtualFree_0
            match = re.match(r"(.+)_\d+", op_name)
            if match:
                op_name = match.group(1)
            # the global name does not include the DLL name, so we can't extract it
            for name in capa.features.extractors.helpers.generate_symbols("", op_name):
                yield API(name), ih.address

    # extract IDA/FLIRT recognized API functions
    targets = tuple(idautils.CodeRefsFrom(insn.ea, False))
    if not targets:
        return

    target = targets[0]
    target_func = idaapi.get_func(target)
    if not target_func or target_func.start_ea != target:
        # not a function (start)
        return

    if target_func.flags & idaapi.FUNC_LIB:
        name = idaapi.get_name(target_func.start_ea)
        yield API(name), ih.address
        if name.startswith("_"):
            # some linkers may prefix linked routines with a `_` to avoid name collisions.
            # extract features for both the mangled and un-mangled representations.
            # e.g. `_fwrite` -> `fwrite`
            # see: https://stackoverflow.com/a/2628384/87207
            yield API(name[1:]), ih.address


def extract_insn_number_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction number features
    example:
        push    3136B0h         ; dwControlCode
    """
    insn: idaapi.insn_t = ih.inner

    if idaapi.is_ret_insn(insn):
        # skip things like:
        #   .text:0042250E retn 8
        return

    if capa.features.extractors.ida.helpers.is_sp_modified(insn):
        # skip things like:
        #   .text:00401145 add esp, 0Ch
        return

    for i, op in enumerate(insn.ops):
        if op.type == idaapi.o_void:
            break
        if op.type not in (idaapi.o_imm, idaapi.o_mem):
            continue
        # skip things like:
        #   .text:00401100 shr eax, offset loc_C
        if capa.features.extractors.ida.helpers.is_op_offset(insn, op):
            continue

        if op.type == idaapi.o_imm:
            const = capa.features.extractors.ida.helpers.mask_op_val(op)
        else:
            const = op.addr

        yield Number(const), ih.address
        yield OperandNumber(i, const), ih.address

        if insn.itype == idaapi.NN_add and 0 < const < MAX_STRUCTURE_SIZE and op.type == idaapi.o_imm:
            # for pattern like:
            #
            #     add eax, 0x10
            #
            # assume 0x10 is also an offset (imagine eax is a pointer).
            yield Offset(const), ih.address
            yield OperandOffset(i, const), ih.address


def extract_insn_bytes_features(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse referenced byte sequences
    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """
    insn: idaapi.insn_t = ih.inner

    if idaapi.is_call_insn(insn):
        return

    ref = capa.features.extractors.ida.helpers.find_data_reference_from_insn(insn)
    if ref != insn.ea:
        extracted_bytes = capa.features.extractors.ida.helpers.read_bytes_at(ref, MAX_BYTES_FEATURE_SIZE)
        if extracted_bytes and not capa.features.extractors.helpers.all_zeros(extracted_bytes):
            if not capa.features.extractors.ida.helpers.find_string_at(ref):
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
    insn: idaapi.insn_t = ih.inner

    ref = capa.features.extractors.ida.helpers.find_data_reference_from_insn(insn)
    if ref != insn.ea:
        found = capa.features.extractors.ida.helpers.find_string_at(ref)
        if found:
            yield String(found), ih.address


def extract_insn_offset_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction structure offset features

    example:
        .text:0040112F cmp [esi+4], ebx
    """
    insn: idaapi.insn_t = ih.inner

    for i, op in enumerate(insn.ops):
        if op.type == idaapi.o_void:
            break
        if op.type not in (idaapi.o_phrase, idaapi.o_displ):
            continue
        if capa.features.extractors.ida.helpers.is_op_stack_var(insn.ea, op.n):
            continue

        p_info = capa.features.extractors.ida.helpers.get_op_phrase_info(op)

        op_off = p_info.get("offset")
        if op_off is None:
            continue

        if idaapi.is_mapped(op_off):
            # Ignore:
            #   mov esi, dword_1005B148[esi]
            continue

        # I believe that IDA encodes all offsets as two's complement in a u32.
        # a 64-bit displacement isn't a thing, see:
        # https://stackoverflow.com/questions/31853189/x86-64-assembly-why-displacement-not-64-bits
        op_off = capa.features.extractors.helpers.twos_complement(op_off, 32)

        yield Offset(op_off), ih.address
        yield OperandOffset(i, op_off), ih.address

        if (
            insn.itype == idaapi.NN_lea
            and i == 1
            # o_displ is used for both:
            #   [eax+1]
            #   [eax+ebx+2]
            and op.type == idaapi.o_displ
            # but the SIB is only present for [eax+ebx+2]
            # which we don't want
            and not capa.features.extractors.ida.helpers.has_sib(op)
        ):
            # for pattern like:
            #
            #     lea eax, [ebx + 1]
            #
            # assume 1 is also an offset (imagine ebx is a zero register).
            yield Number(op_off), ih.address
            yield OperandNumber(i, op_off), ih.address


def contains_stack_cookie_keywords(s: str) -> bool:
    """
    check if string contains stack cookie keywords

    Examples:
        xor     ecx, ebp ; StackCookie
        mov     eax, ___security_cookie
    """
    if not s:
        return False
    s = s.strip().lower()
    if "cookie" not in s:
        return False
    return any(keyword in s for keyword in ("stack", "security"))


def bb_stack_cookie_registers(bb: idaapi.BasicBlock) -> Iterator[int]:
    """scan basic block for stack cookie operations

    yield registers ids that may have been used for stack cookie operations

    assume instruction that sets stack cookie and nzxor exist in same block
    and stack cookie register is not modified prior to nzxor

    Example:
        .text:004062DA mov     eax, ___security_cookie <-- stack cookie
        .text:004062DF mov     ecx, eax
        .text:004062E1 mov     ebx, [esi]
        .text:004062E3 and     ecx, 1Fh
        .text:004062E6 mov     edi, [esi+4]
        .text:004062E9 xor     ebx, eax
        .text:004062EB mov     esi, [esi+8]
        .text:004062EE xor     edi, eax <-- ignore
        .text:004062F0 xor     esi, eax <-- ignore
        .text:004062F2 ror     edi, cl
        .text:004062F4 ror     esi, cl
        .text:004062F6 ror     ebx, cl
        .text:004062F8 cmp     edi, esi
        .text:004062FA jnz     loc_40639D

    TODO: this is expensive, but necessary?...
    """
    for insn in capa.features.extractors.ida.helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
        if contains_stack_cookie_keywords(idc.GetDisasm(insn.ea)):
            for op in capa.features.extractors.ida.helpers.get_insn_ops(insn, target_ops=(idaapi.o_reg,)):
                if capa.features.extractors.ida.helpers.is_op_write(insn, op):
                    # only include modified registers
                    yield op.reg


def is_nzxor_stack_cookie_delta(f: idaapi.func_t, bb: idaapi.BasicBlock, insn: idaapi.insn_t) -> bool:
    """check if nzxor exists within stack cookie delta"""
    # security cookie check should use SP or BP
    if not capa.features.extractors.ida.helpers.is_frame_register(insn.Op2.reg):
        return False

    f_bbs = tuple(capa.features.extractors.ida.helpers.get_function_blocks(f))

    # expect security cookie init in first basic block within first bytes (instructions)
    if capa.features.extractors.ida.helpers.is_basic_block_equal(bb, f_bbs[0]) and insn.ea < (
        bb.start_ea + SECURITY_COOKIE_BYTES_DELTA
    ):
        return True

    # ... or within last bytes (instructions) before a return
    if capa.features.extractors.ida.helpers.is_basic_block_return(bb) and insn.ea > (
        bb.start_ea + capa.features.extractors.ida.helpers.basic_block_size(bb) - SECURITY_COOKIE_BYTES_DELTA
    ):
        return True

    return False


def is_nzxor_stack_cookie(f: idaapi.func_t, bb: idaapi.BasicBlock, insn: idaapi.insn_t) -> bool:
    """check if nzxor is related to stack cookie"""
    if contains_stack_cookie_keywords(idaapi.get_cmt(insn.ea, False)):
        # Example:
        #   xor     ecx, ebp        ; StackCookie
        return True
    if is_nzxor_stack_cookie_delta(f, bb, insn):
        return True
    stack_cookie_regs = tuple(bb_stack_cookie_registers(bb))
    if any(op_reg in stack_cookie_regs for op_reg in (insn.Op1.reg, insn.Op2.reg)):
        # Example:
        #   mov     eax, ___security_cookie
        #   xor     eax, ebp
        return True
    return False


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse instruction non-zeroing XOR instruction
    ignore expected non-zeroing XORs, e.g. security cookies
    """
    insn: idaapi.insn_t = ih.inner

    if insn.itype not in (idaapi.NN_xor, idaapi.NN_xorpd, idaapi.NN_xorps, idaapi.NN_pxor):
        return
    if capa.features.extractors.ida.helpers.is_operand_equal(insn.Op1, insn.Op2):
        return
    if is_nzxor_stack_cookie(fh.inner, bbh.inner, insn):
        return
    yield Characteristic("nzxor"), ih.address


def extract_insn_mnemonic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction mnemonic features"""
    yield Mnemonic(idc.print_insn_mnem(ih.inner.ea)), ih.address


def extract_insn_obfs_call_plus_5_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse call $+5 instruction from the given instruction.
    """
    insn: idaapi.insn_t = ih.inner

    if not idaapi.is_call_insn(insn):
        return

    if insn.ea + 5 == idc.get_operand_value(insn.ea, 0):
        yield Characteristic("call $+5"), ih.address


def extract_insn_peb_access_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64

    TODO:
        IDA should be able to do this..
    """
    insn: idaapi.insn_t = ih.inner

    if insn.itype not in (idaapi.NN_push, idaapi.NN_mov):
        return

    if all(op.type != idaapi.o_mem for op in insn.ops):
        # try to optimize for only memory references
        return

    disasm = idc.GetDisasm(insn.ea)

    if " fs:30h" in disasm or " gs:60h" in disasm:
        # TODO(mike-hunhoff): use proper IDA API for fetching segment access
        # scanning the disassembly text is a hack.
        # https://github.com/mandiant/capa/issues/1605
        yield Characteristic("peb access"), ih.address


def extract_insn_segment_access_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """parse instruction fs or gs access

    TODO:
        IDA should be able to do this...
    """
    insn: idaapi.insn_t = ih.inner

    if all(op.type != idaapi.o_mem for op in insn.ops):
        # try to optimize for only memory references
        return

    disasm = idc.GetDisasm(insn.ea)

    if " fs:" in disasm:
        # TODO(mike-hunhoff): use proper IDA API for fetching segment access
        # scanning the disassembly text is a hack.
        # https://github.com/mandiant/capa/issues/1605
        yield Characteristic("fs access"), ih.address

    if " gs:" in disasm:
        # TODO(mike-hunhoff): use proper IDA API for fetching segment access
        # scanning the disassembly text is a hack.
        # https://github.com/mandiant/capa/issues/1605
        yield Characteristic("gs access"), ih.address


def extract_insn_cross_section_cflow(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """inspect the instruction for a CALL or JMP that crosses section boundaries"""
    insn: idaapi.insn_t = ih.inner

    for ref in idautils.CodeRefsFrom(insn.ea, False):
        if ref in get_imports(fh.ctx):
            # ignore API calls
            continue
        if not idaapi.getseg(ref):
            # handle IDA API bug
            continue
        if idaapi.getseg(ref) == idaapi.getseg(insn.ea):
            continue
        yield Characteristic("cross section flow"), ih.address


def extract_function_calls_from(fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope
    """
    insn: idaapi.insn_t = ih.inner

    if idaapi.is_call_insn(insn):
        for ref in idautils.CodeRefsFrom(insn.ea, False):
            yield Characteristic("calls from"), AbsoluteVirtualAddress(ref)


def extract_function_indirect_call_characteristic_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974

    most relevant at the function or basic block scope;
    however, its most efficient to extract at the instruction scope
    """
    insn: idaapi.insn_t = ih.inner

    if idaapi.is_call_insn(insn) and idc.get_operand_type(insn.ea, 0) in (idc.o_reg, idc.o_phrase, idc.o_displ):
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
