# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import envi.memory
import vivisect.const
import envi.archs.i386.disasm

import capa.features.extractors.helpers
from capa.features import MAX_BYTES_FEATURE_SIZE, Bytes, String, Characteristic
from capa.features.insn import Number, Offset, Mnemonic
from capa.features.extractors.viv.indirect_calls import NotFoundError, resolve_indirect_call

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40


def interface_extract_instruction_XXX(f, bb, insn):
    """
    parse features from the given instruction.

    args:
      f (viv_utils.Function): the function to process.
      bb (viv_utils.BasicBlock): the basic block to process.
      insn (vivisect...Instruction): the instruction to process.

    yields:
      (Feature, int): the feature and the address at which its found.
    """
    yield NotImplementedError("feature"), NotImplementedError("virtual address")


def get_imports(vw):
    """
    caching accessor to vivisect workspace imports
    avoids performance issues in vivisect when collecting locations
    """
    if "imports" in vw.metadata:
        return vw.metadata["imports"]
    else:
        imports = {p[0]: p[3] for p in vw.getImports()}
        vw.metadata["imports"] = imports
        return imports


def extract_insn_api_features(f, bb, insn):
    """parse API features from the given instruction."""

    # example:
    #
    #    call dword [0x00473038]

    if insn.mnem != "call":
        return

    # traditional call via IAT
    if isinstance(insn.opers[0], envi.archs.i386.disasm.i386ImmMemOper):
        oper = insn.opers[0]
        target = oper.getOperAddr(insn)

        imports = get_imports(f.vw)
        if target in imports.keys():
            for feature, va in capa.features.extractors.helpers.generate_api_features(imports[target], insn.va):
                yield feature, va

    # call via thunk on x86,
    # see 9324d1a8ae37a36ae560c37448c9705a at 0x407985
    #
    # this is also how calls to internal functions may be decoded on x64.
    # see Lab21-01.exe_:0x140001178
    elif isinstance(insn.opers[0], envi.archs.i386.disasm.i386PcRelOper):
        target = insn.opers[0].getOperValue(insn)

        try:
            thunk = f.vw.getFunctionMeta(target, "Thunk")
        except vivisect.exc.InvalidFunction:
            return
        else:
            if thunk:
                for feature, va in capa.features.extractors.helpers.generate_api_features(thunk, insn.va):
                    yield feature, va

    # call via import on x64
    # see Lab21-01.exe_:0x14000118C
    elif isinstance(insn.opers[0], envi.archs.amd64.disasm.Amd64RipRelOper):
        op = insn.opers[0]
        target = op.getOperAddr(insn)

        imports = get_imports(f.vw)
        if target in imports.keys():
            for feature, va in capa.features.extractors.helpers.generate_api_features(imports[target], insn.va):
                yield feature, va

    elif isinstance(insn.opers[0], envi.archs.i386.disasm.i386RegOper):
        try:
            (_, target) = resolve_indirect_call(f.vw, insn.va, insn=insn)
        except NotFoundError:
            # not able to resolve the indirect call, sorry
            return

        if target is None:
            # not able to resolve the indirect call, sorry
            return

        imports = get_imports(f.vw)
        if target in imports.keys():
            for feature, va in capa.features.extractors.helpers.generate_api_features(imports[target], insn.va):
                yield feature, va


def extract_insn_number_features(f, bb, insn):
    """parse number features from the given instruction."""
    # example:
    #
    #     push    3136B0h         ; dwControlCode
    for oper in insn.opers:
        # this is for both x32 and x64
        if not isinstance(oper, envi.archs.i386.disasm.i386ImmOper):
            continue

        v = oper.getOperValue(oper)

        if f.vw.probeMemory(v, 1, envi.memory.MM_READ):
            # this is a valid address
            # assume its not also a constant.
            continue

        if insn.mnem == "add" and insn.opers[0].isReg() and insn.opers[0].reg == envi.archs.i386.disasm.REG_ESP:
            # skip things like:
            #
            #    .text:00401140                 call    sub_407E2B
            #    .text:00401145                 add     esp, 0Ch
            return

        yield Number(v), insn.va


def extract_insn_bytes_features(f, bb, insn):
    """
    parse byte sequence features from the given instruction.
    example:
        #     push    offset iid_004118d4_IShellLinkA ; riid
    """
    for oper in insn.opers:
        if insn.mnem == "call":
            # ignore call instructions
            continue

        if isinstance(oper, envi.archs.i386.disasm.i386ImmOper):
            v = oper.getOperValue(oper)
        elif isinstance(oper, envi.archs.i386.disasm.i386RegMemOper):
            # handle case like:
            #   movzx   ecx, ds:byte_423258[eax]
            v = oper.disp
        elif isinstance(oper, envi.archs.amd64.disasm.Amd64RipRelOper):
            # see: Lab21-01.exe_:0x1400010D3
            v = oper.getOperAddr(insn)
        else:
            continue

        segm = f.vw.getSegment(v)
        if not segm:
            continue

        segm_end = segm[0] + segm[1]
        try:
            # Do not read beyond the end of a segment
            if v + MAX_BYTES_FEATURE_SIZE > segm_end:
                extracted_bytes = f.vw.readMemory(v, segm_end - v)
            else:
                extracted_bytes = f.vw.readMemory(v, MAX_BYTES_FEATURE_SIZE)
        except envi.SegmentationViolation:
            pass
        else:
            if not capa.features.extractors.helpers.all_zeros(extracted_bytes):
                yield Bytes(extracted_bytes), insn.va


def read_memory(vw, va, size):
    # as documented in #176, vivisect will not readMemory() when the section is not marked readable.
    #
    # but here, we don't care about permissions.
    # so, copy the viv implementation of readMemory and remove the permissions check.
    #
    # this is derived from:
    #   https://github.com/vivisect/vivisect/blob/5eb4d237bddd4069449a6bc094d332ceed6f9a96/envi/memory.py#L453-L462
    for mva, mmaxva, mmap, mbytes in vw._map_defs:
        if va >= mva and va < mmaxva:
            mva, msize, mperms, mfname = mmap
            offset = va - mva
            return mbytes[offset : offset + size]
    raise envi.SegmentationViolation(va)


def read_string(vw, offset):
    try:
        alen = vw.detectString(offset)
    except envi.SegmentationViolation:
        pass
    else:
        if alen > 0:
            return read_memory(vw, offset, alen).decode("utf-8")

    try:
        ulen = vw.detectUnicode(offset)
    except envi.SegmentationViolation:
        pass
    except IndexError:
        # potential vivisect bug detecting Unicode at segment end
        pass
    else:
        if ulen > 0:
            if ulen % 2 == 1:
                # vivisect seems to mis-detect the end unicode strings
                # off by one, too short
                ulen += 1
            return read_memory(vw, offset, ulen).decode("utf-16")

    raise ValueError("not a string", offset)


def extract_insn_string_features(f, bb, insn):
    """parse string features from the given instruction."""
    # example:
    #
    #     push    offset aAcr     ; "ACR  > "
    for oper in insn.opers:
        if isinstance(oper, envi.archs.i386.disasm.i386ImmOper):
            v = oper.getOperValue(oper)
        elif isinstance(oper, envi.archs.amd64.disasm.Amd64RipRelOper):
            v = oper.getOperAddr(insn)
        else:
            continue

        try:
            s = read_string(f.vw, v)
        except ValueError:
            continue
        else:
            yield String(s.rstrip("\x00")), insn.va


def extract_insn_offset_features(f, bb, insn):
    """parse structure offset features from the given instruction."""
    # example:
    #
    #     .text:0040112F    cmp     [esi+4], ebx
    for oper in insn.opers:
        # this is for both x32 and x64
        if not isinstance(oper, envi.archs.i386.disasm.i386RegMemOper):
            continue

        if oper.reg == envi.archs.i386.disasm.REG_ESP:
            continue

        if oper.reg == envi.archs.i386.disasm.REG_EBP:
            continue

        # TODO: do x64 support for real.
        if oper.reg == envi.archs.amd64.disasm.REG_RBP:
            continue

        # viv already decodes offsets as signed

        yield Offset(oper.disp), insn.va


def is_security_cookie(f, bb, insn):
    """
    check if an instruction is related to security cookie checks
    """
    # security cookie check should use SP or BP
    oper = insn.opers[1]
    if oper.isReg() and oper.reg not in [
        envi.archs.i386.disasm.REG_ESP,
        envi.archs.i386.disasm.REG_EBP,
        # TODO: do x64 support for real.
        envi.archs.amd64.disasm.REG_RBP,
        envi.archs.amd64.disasm.REG_RSP,
    ]:
        return False

    # expect security cookie init in first basic block within first bytes (instructions)
    bb0 = f.basic_blocks[0]

    if bb == bb0 and insn.va < (bb.va + SECURITY_COOKIE_BYTES_DELTA):
        return True

    # ... or within last bytes (instructions) before a return
    elif bb.instructions[-1].isReturn() and insn.va > (bb.va + bb.size - SECURITY_COOKIE_BYTES_DELTA):
        return True

    return False


def extract_insn_nzxor_characteristic_features(f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    if insn.mnem != "xor":
        return

    if insn.opers[0] == insn.opers[1]:
        return

    if is_security_cookie(f, bb, insn):
        return

    yield Characteristic("nzxor"), insn.va


def extract_insn_mnemonic_features(f, bb, insn):
    """parse mnemonic features from the given instruction."""
    yield Mnemonic(insn.mnem), insn.va


def extract_insn_peb_access_characteristic_features(f, bb, insn):
    """
    parse peb access from the given function. fs:[0x30] on x86, gs:[0x60] on x64
    """
    # TODO handle where fs/gs are loaded into a register or onto the stack and used later

    if insn.mnem not in ["push", "mov"]:
        return

    if "fs" in insn.getPrefixName():
        for oper in insn.opers:
            # examples
            #
            #     IDA: mov     eax, large fs:30h
            #     viv: fs: mov eax,dword [0x00000030]  ; i386ImmMemOper
            #     IDA: push    large dword ptr fs:30h
            #     viv: fs: push dword [0x00000030]
            #     fs: push dword [eax + 0x30]  ; i386RegMemOper, with eax = 0
            if (isinstance(oper, envi.archs.i386.disasm.i386RegMemOper) and oper.disp == 0x30) or (
                isinstance(oper, envi.archs.i386.disasm.i386ImmMemOper) and oper.imm == 0x30
            ):
                yield Characteristic("peb access"), insn.va
    elif "gs" in insn.getPrefixName():
        for oper in insn.opers:
            if (isinstance(oper, envi.archs.amd64.disasm.i386RegMemOper) and oper.disp == 0x60) or (
                isinstance(oper, envi.archs.amd64.disasm.i386ImmMemOper) and oper.imm == 0x60
            ):
                yield Characteristic("peb access"), insn.va
    else:
        pass


def extract_insn_segment_access_features(f, bb, insn):
    """ parse the instruction for access to fs or gs """
    prefix = insn.getPrefixName()

    if prefix == "fs":
        yield Characteristic("fs access"), insn.va

    if prefix == "gs":
        yield Characteristic("gs access"), insn.va


def get_section(vw, va):
    for start, length, _, __ in vw.getMemoryMaps():
        if start <= va < start + length:
            return start

    raise KeyError(va)


def extract_insn_cross_section_cflow(f, bb, insn):
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    for va, flags in insn.getBranches():
        if flags & envi.BR_FALL:
            continue

        try:
            # skip 32-bit calls to imports
            if insn.mnem == "call" and isinstance(insn.opers[0], envi.archs.i386.disasm.i386ImmMemOper):
                oper = insn.opers[0]
                target = oper.getOperAddr(insn)

                if target in get_imports(f.vw):
                    continue

            # skip 64-bit calls to imports
            elif insn.mnem == "call" and isinstance(insn.opers[0], envi.archs.amd64.disasm.Amd64RipRelOper):
                op = insn.opers[0]
                target = op.getOperAddr(insn)

                if target in get_imports(f.vw):
                    continue

            if get_section(f.vw, insn.va) != get_section(f.vw, va):
                yield Characteristic("cross section flow"), insn.va

        except KeyError:
            continue


# this is a feature that's most relevant at the function scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_calls_from(f, bb, insn):
    if insn.mnem != "call":
        return

    target = None

    # traditional call via IAT, x32
    if isinstance(insn.opers[0], envi.archs.i386.disasm.i386ImmMemOper):
        oper = insn.opers[0]
        target = oper.getOperAddr(insn)
        yield Characteristic("calls from"), target

    # call via thunk on x86,
    # see 9324d1a8ae37a36ae560c37448c9705a at 0x407985
    #
    # call to internal function on x64
    # see Lab21-01.exe_:0x140001178
    elif isinstance(insn.opers[0], envi.archs.i386.disasm.i386PcRelOper):
        target = insn.opers[0].getOperValue(insn)
        yield Characteristic("calls from"), target

    # call via IAT, x64
    elif isinstance(insn.opers[0], envi.archs.amd64.disasm.Amd64RipRelOper):
        op = insn.opers[0]
        target = op.getOperAddr(insn)
        yield Characteristic("calls from"), target

    if target and target == f.va:
        # if we found a jump target and it's the function address
        # mark as recursive
        yield Characteristic("recursive call"), target


# this is a feature that's most relevant at the function or basic block scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_indirect_call_characteristic_features(f, bb, insn):
    """
    extract indirect function call characteristic (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974
    """
    if insn.mnem != "call":
        return

    # Checks below work for x86 and x64
    if isinstance(insn.opers[0], envi.archs.i386.disasm.i386RegOper):
        # call edx
        yield Characteristic("indirect call"), insn.va
    elif isinstance(insn.opers[0], envi.archs.i386.disasm.i386RegMemOper):
        # call dword ptr [eax+50h]
        yield Characteristic("indirect call"), insn.va
    elif isinstance(insn.opers[0], envi.archs.i386.disasm.i386SibOper):
        # call qword ptr [rsp+78h]
        yield Characteristic("indirect call"), insn.va


def extract_features(f, bb, insn):
    """
    extract features from the given insn.

    args:
      f (viv_utils.Function): the function from which to extract features
      bb (viv_utils.BasicBlock): the basic block to process.
      insn (vivisect...Instruction): the instruction to process.

    yields:
      Feature, set[VA]: the features and their location found in this insn.
    """
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature, va in insn_handler(f, bb, insn):
            yield feature, va


INSTRUCTION_HANDLERS = (
    extract_insn_api_features,
    extract_insn_number_features,
    extract_insn_string_features,
    extract_insn_bytes_features,
    extract_insn_offset_features,
    extract_insn_nzxor_characteristic_features,
    extract_insn_mnemonic_features,
    extract_insn_peb_access_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_insn_segment_access_features,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
)
