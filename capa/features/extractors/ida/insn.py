# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import idc
import idaapi
import idautils

import capa.features.extractors.helpers
import capa.features.extractors.ida.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import MAX_BYTES_FEATURE_SIZE, THUNK_CHAIN_DEPTH_DELTA, Bytes, String, Characteristic

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40


def get_imports(ctx):
    if "imports_cache" not in ctx:
        ctx["imports_cache"] = capa.features.extractors.ida.helpers.get_file_imports()
    return ctx["imports_cache"]


def check_for_api_call(ctx, insn):
    """check instruction for API call"""
    info = ()
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

        info = get_imports(ctx).get(ref, ())
        if info:
            break

        f = idaapi.get_func(ref)
        if not f or not (f.flags & idaapi.FUNC_THUNK):
            break

    if info:
        yield "%s.%s" % (info[0], info[1])


def extract_insn_api_features(f, bb, insn):
    """parse instruction API features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        call dword [0x00473038]
    """
    if not insn.get_canon_mnem() in ("call", "jmp"):
        return

    for api in check_for_api_call(f.ctx, insn):
        dll, _, symbol = api.rpartition(".")
        for name in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield API(name), insn.ea

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
        yield API(name), insn.ea
        if name.startswith("_"):
            # some linkers may prefix linked routines with a `_` to avoid name collisions.
            # extract features for both the mangled and un-mangled representations.
            # e.g. `_fwrite` -> `fwrite`
            # see: https://stackoverflow.com/a/2628384/87207
            yield API(name[1:]), insn.ea


def extract_insn_number_features(f, bb, insn):
    """parse instruction number features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push    3136B0h         ; dwControlCode
    """
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

        yield Number(const), insn.ea
        yield OperandNumber(i, const), insn.ea

        if insn.itype == idaapi.NN_add and 0 < const < MAX_STRUCTURE_SIZE and op.type == idaapi.o_imm:
            # for pattern like:
            #
            #     add eax, 0x10
            #
            # assume 0x10 is also an offset (imagine eax is a pointer).
            yield Offset(const), insn.ea
            yield OperandOffset(i, const), insn.ea


def extract_insn_bytes_features(f, bb, insn):
    """parse referenced byte sequences

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push    offset iid_004118d4_IShellLinkA ; riid
    """
    if idaapi.is_call_insn(insn):
        return

    ref = capa.features.extractors.ida.helpers.find_data_reference_from_insn(insn)
    if ref != insn.ea:
        extracted_bytes = capa.features.extractors.ida.helpers.read_bytes_at(ref, MAX_BYTES_FEATURE_SIZE)
        if extracted_bytes and not capa.features.extractors.helpers.all_zeros(extracted_bytes):
            yield Bytes(extracted_bytes), insn.ea


def extract_insn_string_features(f, bb, insn):
    """parse instruction string features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        push offset aAcr     ; "ACR  > "
    """
    ref = capa.features.extractors.ida.helpers.find_data_reference_from_insn(insn)
    if ref != insn.ea:
        found = capa.features.extractors.ida.helpers.find_string_at(ref)
        if found:
            yield String(found), insn.ea


def extract_insn_offset_features(f, bb, insn):
    """parse instruction structure offset features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)

    example:
        .text:0040112F cmp [esi+4], ebx
    """
    for i, op in enumerate(insn.ops):
        if op.type == idaapi.o_void:
            break
        if op.type not in (idaapi.o_phrase, idaapi.o_displ):
            continue
        if capa.features.extractors.ida.helpers.is_op_stack_var(insn.ea, op.n):
            continue

        p_info = capa.features.extractors.ida.helpers.get_op_phrase_info(op)
        op_off = p_info.get("offset", 0)
        if idaapi.is_mapped(op_off):
            # Ignore:
            #   mov esi, dword_1005B148[esi]
            continue

        # I believe that IDA encodes all offsets as two's complement in a u32.
        # a 64-bit displacement isn't a thing, see:
        # https://stackoverflow.com/questions/31853189/x86-64-assembly-why-displacement-not-64-bits
        op_off = capa.features.extractors.helpers.twos_complement(op_off, 32)

        yield Offset(op_off), insn.ea
        yield OperandOffset(i, op_off), insn.ea

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
            yield Number(op_off), insn.ea
            yield OperandNumber(i, op_off), insn.ea


def contains_stack_cookie_keywords(s):
    """check if string contains stack cookie keywords

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


def bb_stack_cookie_registers(bb):
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


def is_nzxor_stack_cookie_delta(f, bb, insn):
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


def is_nzxor_stack_cookie(f, bb, insn):
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


def extract_insn_nzxor_characteristic_features(f, bb, insn):
    """parse instruction non-zeroing XOR instruction

    ignore expected non-zeroing XORs, e.g. security cookies

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    if insn.itype not in (idaapi.NN_xor, idaapi.NN_xorpd, idaapi.NN_xorps, idaapi.NN_pxor):
        return
    if capa.features.extractors.ida.helpers.is_operand_equal(insn.Op1, insn.Op2):
        return
    if is_nzxor_stack_cookie(f, bb, insn):
        return
    yield Characteristic("nzxor"), insn.ea


def extract_insn_mnemonic_features(f, bb, insn):
    """parse instruction mnemonic features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    yield Mnemonic(idc.print_insn_mnem(insn.ea)), insn.ea


def extract_insn_obfs_call_plus_5_characteristic_features(f, bb, insn):
    """
    parse call $+5 instruction from the given instruction.
    """
    if not idaapi.is_call_insn(insn):
        return

    if insn.ea + 5 == idc.get_operand_value(insn.ea, 0):
        yield Characteristic("call $+5"), insn.ea


def extract_insn_peb_access_characteristic_features(f, bb, insn):
    """parse instruction peb access

    fs:[0x30] on x86, gs:[0x60] on x64

    TODO:
        IDA should be able to do this..
    """
    if insn.itype not in (idaapi.NN_push, idaapi.NN_mov):
        return

    if all(map(lambda op: op.type != idaapi.o_mem, insn.ops)):
        # try to optimize for only memory references
        return

    disasm = idc.GetDisasm(insn.ea)

    if " fs:30h" in disasm or " gs:60h" in disasm:
        # TODO: replace above with proper IDA
        yield Characteristic("peb access"), insn.ea


def extract_insn_segment_access_features(f, bb, insn):
    """parse instruction fs or gs access

    TODO:
        IDA should be able to do this...
    """
    if all(map(lambda op: op.type != idaapi.o_mem, insn.ops)):
        # try to optimize for only memory references
        return

    disasm = idc.GetDisasm(insn.ea)

    if " fs:" in disasm:
        # TODO: replace above with proper IDA
        yield Characteristic("fs access"), insn.ea

    if " gs:" in disasm:
        # TODO: replace above with proper IDA
        yield Characteristic("gs access"), insn.ea


def extract_insn_cross_section_cflow(f, bb, insn):
    """inspect the instruction for a CALL or JMP that crosses section boundaries

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    for ref in idautils.CodeRefsFrom(insn.ea, False):
        if ref in get_imports(f.ctx).keys():
            # ignore API calls
            continue
        if not idaapi.getseg(ref):
            # handle IDA API bug
            continue
        if idaapi.getseg(ref) == idaapi.getseg(insn.ea):
            continue
        yield Characteristic("cross section flow"), insn.ea


def extract_function_calls_from(f, bb, insn):
    """extract functions calls from features

    most relevant at the function scope, however, its most efficient to extract at the instruction scope

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    if idaapi.is_call_insn(insn):
        for ref in idautils.CodeRefsFrom(insn.ea, False):
            yield Characteristic("calls from"), ref


def extract_function_indirect_call_characteristic_features(f, bb, insn):
    """extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974

    most relevant at the function or basic block scope;
    however, its most efficient to extract at the instruction scope

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    if idaapi.is_call_insn(insn) and idc.get_operand_type(insn.ea, 0) in (idc.o_reg, idc.o_phrase, idc.o_displ):
        yield Characteristic("indirect call"), insn.ea


def extract_features(f, bb, insn):
    """extract instruction features

    args:
        f (IDA func_t)
        bb (IDA BasicBlock)
        insn (IDA insn_t)
    """
    for inst_handler in INSTRUCTION_HANDLERS:
        for (feature, ea) in inst_handler(f, bb, insn):
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
    features = []
    for f in capa.features.extractors.ida.helpers.get_functions(skip_thunks=True, skip_libs=True):
        for bb in idaapi.FlowChart(f, flags=idaapi.FC_PREDS):
            for insn in capa.features.extractors.ida.helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
                features.extend(list(extract_features(f, bb, insn)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
