import pprint

import idautils
import idaapi
import idc

from capa.features import String
from capa.features import Bytes
from capa.features import Characteristic
from capa.features import MAX_BYTES_FEATURE_SIZE
from capa.features.insn import Number
from capa.features.insn import Offset
from capa.features.insn import Mnemonic
import capa.features.extractors.helpers
import capa.features.extractors.ida.helpers


_file_imports_cache = None


def get_imports():
    global _file_imports_cache
    if _file_imports_cache is None:
        _file_imports_cache = capa.features.extractors.ida.helpers.get_file_imports()
    return _file_imports_cache


def _check_for_api_call(insn):
    ''' check instruction for API call '''
    if not idaapi.is_call_insn(insn):
        return

    for call_ref in idautils.CodeRefsFrom(insn.ea, False):
        imp = get_imports().get(call_ref, None)

        if imp:
            yield '%s.%s' % (imp[0], imp[1])
        else:
            f = idaapi.get_func(call_ref)

            if f and f.flags & idaapi.FUNC_THUNK:
                # check if call to thunk
                # TODO: first instruction might not always be the thunk
                for thunk_ref in idautils.DataRefsFrom(call_ref):
                    # TODO: always data ref for thunk??
                    imp = get_imports().get(thunk_ref, None)

                    if imp:
                        yield '%s.%s' % (imp[0], imp[1])


def extract_insn_api_features(f, bb, insn):
    ''' parse instruction API features

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)

        example:
            call dword [0x00473038]
    '''
    for api_name in _check_for_api_call(insn):
        for feature, va in capa.features.extractors.helpers.generate_api_features(api_name, insn.ea):
            yield feature, va


def extract_insn_number_features(f, bb, insn):
    ''' parse instruction number features

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)

        example:
            push    3136B0h         ; dwControlCode
    '''
    if idaapi.is_ret_insn(insn):
        # skip things like:
        #   .text:0042250E retn 8
        return

    if capa.features.extractors.ida.helpers.is_sp_modified(insn):
        # skip things like:
        #   .text:00401145 add esp, 0Ch
        return

    for op in capa.features.extractors.ida.helpers.get_insn_ops(insn, op_type=(idaapi.o_imm,)):
        op_val = capa.features.extractors.ida.helpers.mask_op_val(op)

        if idaapi.is_mapped(op_val):
            # assume valid address is not a constant
            continue

        yield Number(op_val), insn.ea


def extract_insn_bytes_features(f, bb, insn):
    ''' parse referenced byte sequences

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)

        example:
            push    offset iid_004118d4_IShellLinkA ; riid
    '''
    if idaapi.is_call_insn(insn):
        # ignore call instructions
        return

    for ref in idautils.DataRefsFrom(insn.ea):
        extracted_bytes = capa.features.extractors.ida.helpers.read_bytes_at(ref, MAX_BYTES_FEATURE_SIZE)
        if extracted_bytes:
            if not capa.features.extractors.helpers.all_zeros(extracted_bytes):
                yield Bytes(extracted_bytes), insn.ea


def extract_insn_string_features(f, bb, insn):
    ''' parse instruction string features

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)

        example:
            push offset aAcr     ; "ACR  > "
    '''
    for ref in idautils.DataRefsFrom(insn.ea):
        found = capa.features.extractors.ida.helpers.find_string_at(ref)
        if found:
            yield String(found), insn.ea


def extract_insn_offset_features(f, bb, insn):
    ''' parse instruction structure offset features

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)

        example:
            .text:0040112F cmp [esi+4], ebx
    '''
    for op in capa.features.extractors.ida.helpers.get_insn_ops(insn, op_type=(idaapi.o_phrase, idaapi.o_displ)):
        if capa.features.extractors.ida.helpers.is_op_stack_var(insn.ea, op.n):
            # skip stack offsets
            continue

        p_info = capa.features.extractors.ida.helpers.get_op_phrase_info(op)

        if not p_info:
            continue

        op_off = p_info['offset']

        if 0 == op_off:
            # TODO: Do we want to record offset of zero?
            continue

        if idaapi.is_mapped(op_off):
            # Ignore:
            #   mov esi, dword_1005B148[esi]
            continue

        # TODO: Do we handle two's complement?
        yield Offset(op_off), insn.ea


def _contains_stack_cookie_keywords(s):
    ''' check if string contains stack cookie keywords

        Examples:
            xor     ecx, ebp ; StackCookie

            mov     eax, ___security_cookie
    '''
    if not s:
        return False

    s = s.strip().lower()

    if 'cookie' not in s:
        return False

    return any(keyword in s for keyword in ('stack', 'security'))


def _bb_stack_cookie_registers(bb):
    ''' scan basic block for stack cookie operations

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
    '''
    for insn in capa.features.extractors.ida.helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
        if _contains_stack_cookie_keywords(idc.GetDisasm(insn.ea)):
            for op in capa.features.extractors.ida.helpers.get_insn_ops(insn, op_type=(idaapi.o_reg,)):
                if capa.features.extractors.ida.helpers.is_op_write(insn, op):
                    # only include modified registers
                    yield op.reg


def _is_nzxor_stack_cookie(f, bb, insn):
    ''' check if nzxor is related to stack cookie '''
    if _contains_stack_cookie_keywords(idaapi.get_cmt(insn.ea, False)):
        # Example:
        #   xor     ecx, ebp        ; StackCookie
        return True

    if any(op_reg in _bb_stack_cookie_registers(bb) for op_reg in (insn.Op1.reg, insn.Op2.reg)):
        # Example:
        #   mov     eax, ___security_cookie
        #   xor     eax, ebp
        return True

    return False


def extract_insn_nzxor_characteristic_features(f, bb, insn):
    ''' parse instruction non-zeroing XOR instruction

        ignore expected non-zeroing XORs, e.g. security cookies

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)
    '''
    if insn.itype != idaapi.NN_xor:
        return

    if capa.features.extractors.ida.helpers.is_operand_equal(insn.Op1, insn.Op2):
        return

    if _is_nzxor_stack_cookie(f, bb, insn):
        return

    yield Characteristic('nzxor', True), insn.ea


def extract_insn_mnemonic_features(f, bb, insn):
    ''' parse instruction mnemonic features

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)
    '''
    yield Mnemonic(insn.get_canon_mnem()), insn.ea


def extract_insn_peb_access_characteristic_features(f, bb, insn):
    ''' parse instruction peb access

        fs:[0x30] on x86, gs:[0x60] on x64

        TODO:
            IDA should be able to do this..
    '''
    if insn.itype not in (idaapi.NN_push, idaapi.NN_mov):
        return

    if all(map(lambda op: op.type != idaapi.o_mem, insn.ops)):
        # try to optimize for only memory referencese
        return

    disasm = idc.GetDisasm(insn.ea)

    if ' fs:30h' in disasm or ' gs:60h' in disasm:
        # TODO: replace above with proper IDA
        yield Characteristic('peb access', True), insn.ea


def extract_insn_segment_access_features(f, bb, insn):
    ''' parse instruction fs or gs access

        TODO:
            IDA should be able to do this...
    '''
    if all(map(lambda op: op.type != idaapi.o_mem, insn.ops)):
        # try to optimize for only memory referencese
        return

    disasm = idc.GetDisasm(insn.ea)

    if ' fs:' in disasm:
        # TODO: replace above with proper IDA
        yield Characteristic('fs access', True), insn.ea

    if ' gs:' in disasm:
        # TODO: replace above with proper IDA
        yield Characteristic('gs access', True), insn.ea


def extract_insn_cross_section_cflow(f, bb, insn):
    ''' inspect the instruction for a CALL or JMP that crosses section boundaries

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)
    '''
    for ref in idautils.CodeRefsFrom(insn.ea, False):
        if ref in get_imports().keys():
            # ignore API calls
            continue

        if not idaapi.getseg(ref):
            # handle IDA API bug
            continue

        if idaapi.getseg(ref) == idaapi.getseg(insn.ea):
            continue

        yield Characteristic('cross section flow', True), insn.ea


def extract_function_calls_from(f, bb, insn):
    ''' extract functions calls from features

        most relevant at the function scope, however, its most efficient to extract at the instruction scope

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)
    '''
    if not idaapi.is_call_insn(insn):
        # ignore jmp, etc.
        return

    for ref in idautils.CodeRefsFrom(insn.ea, False):
        yield Characteristic('calls from', True), ref


def extract_function_indirect_call_characteristic_features(f, bb, insn):
    ''' extract indirect function calls (e.g., call eax or call dword ptr [edx+4])
        does not include calls like => call ds:dword_ABD4974

        most relevant at the function or basic block scope;
        however, its most efficient to extract at the instruction scope

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)
    '''
    if not idaapi.is_call_insn(insn):
        return

    if idc.get_operand_type(insn.ea, 0) in (idc.o_reg, idc.o_phrase, idc.o_displ):
        yield Characteristic('indirect call', True), insn.ea


def extract_features(f, bb, insn):
    ''' extract instruction features

        args:
            f (IDA func_t)
            bb (IDA BasicBlock)
            insn (IDA insn_t)
    '''
    for inst_handler in INSTRUCTION_HANDLERS:
        for feature, va in inst_handler(f, bb, insn):
            yield feature, va


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_bytes_features,
    extract_insn_string_features,
    extract_insn_offset_features,
    extract_insn_nzxor_characteristic_features,
    extract_insn_mnemonic_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_insn_segment_access_features,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features
)


def main():
    features = []

    for f in capa.features.extractors.ida.helpers.get_functions(ignore_thunks=True, ignore_libs=True):
        for bb in idaapi.FlowChart(f, flags=idaapi.FC_PREDS):
            for insn in capa.features.extractors.ida.helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
                features.extend(list(extract_features(f, bb, insn)))

    pprint.pprint(features)


if __name__ == '__main__':
    main()
