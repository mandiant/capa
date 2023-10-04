# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import List, Tuple, Callable, Iterator

import envi
import envi.exc
import viv_utils
import envi.memory
import viv_utils.flirt
import envi.archs.i386.regs
import envi.archs.amd64.regs
import envi.archs.i386.disasm
import envi.archs.amd64.disasm

import capa.features.extractors.helpers
import capa.features.extractors.viv.helpers
from capa.features.insn import API, MAX_STRUCTURE_SIZE, Number, Offset, Mnemonic, OperandNumber, OperandOffset
from capa.features.common import Bytes, String, Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.viv.insn import (
    derefs,
    read_bytes,
    get_imports,
    get_section,
    read_string,
    is_security_cookie,
)
from capa.features.extractors.viv.helpers import read_memory
from capa.features.extractors.viv.syscall import get_library_function_name_arm
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle
from capa.features.extractors.viv.indirect_calls import NotFoundError, resolve_indirect_call, get_previous_instructions

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA = 0x40


logger = logging.getLogger("capa")


def interface_extract_instruction_XXX(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse features from the given instruction.

    args:
      fh: the function handle to process.
      bbh: the basic block handle to process.
      ih: the instruction handle to process.

    yields:
      (Feature, Address): the feature and the address at which its found.
    """
    raise NotImplementedError


def extract_insn_api_features(fh: FunctionHandle, bb, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse API features from the given instruction.
    """

    insn: envi.Opcode = ih.inner
    f: viv_utils.Function = fh.inner

    if insn.mnem not in ("blx", "bx", "bl", "b", "svc"):
        return

    if isinstance(insn.opers[0], envi.archs.arm.disasm.ArmPcOffsetOper):
        imports = get_imports(f.vw)
        target = capa.features.extractors.viv.helpers.get_coderef_from(f.vw, insn.va)
        if not target:
            return

        if viv_utils.flirt.is_library_function(f.vw, target):
            name = viv_utils.get_function_name(f.vw, target)
            yield API(name), ih.address
            if name.startswith("_"):
                # some linkers may prefix linked routines with a `_` to avoid name collisions.
                # extract features for both the mangled and un-mangled representations.
                # e.g. `_fwrite` -> `fwrite`
                # see: https://stackoverflow.com/a/2628384/87207
                yield API(name[1:]), ih.address
            return

        if read_memory(f.vw, target, 4) != b"\x00\xc6\x8f\xe2":
            return
        api = f.vw.parseOpcode(target).opers[-1].getOperValue(insn)
        op = f.vw.parseOpcode(target + 4).opers[-1]
        api += envi.archs.arm.disasm.shifters[op.shtype](op.val, op.shval, op.size, emu=None)
        api += f.vw.parseOpcode(target + 8).opers[-1].offset

        if api not in imports:
            return
        dll, symbol = imports[api]
        for name in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield API(name), ih.address

    # Added a case for catching basic blocks that contain direct calls to system functions.
    elif isinstance(insn.opers[0], envi.archs.arm.disasm.ArmImmOper):
        if insn.mnem != "svc":
            return

        name = get_library_function_name_arm(f.vw, bb)
        if not name:
            return
        yield API(name), ih.address

    elif isinstance(insn.opers[0], envi.archs.arm.disasm.ArmRegOper):
        # arm ret: bx lr
        if insn.mnem == "bx" and insn.opers[0].reg == 14:
            return  # just return befor the blx
        try:
            (_, target) = resolve_indirect_call(f.vw, insn.va, insn=insn)
        except NotFoundError as e:
            logger.warning("Not able to resolve the indirect call : %s", str(e))
            return

        if target is None:
            return

        imports = get_imports(f.vw)
        if target in imports:
            dll, symbol = imports[target]
            for name in capa.features.extractors.helpers.generate_symbols(dll, symbol):
                yield API(name), ih.address

        else:
            pass


def extract_insn_bytes_features(fh: FunctionHandle, bb, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse byte sequence features from the given instruction.
    example:
        #     push    offset iid_004118d4_IShellLinkA ; riid
    """
    insn: envi.Opcode = ih.inner
    f: viv_utils.Function = fh.inner

    if insn.mnem == "bl" or insn.mnem == "blx":
        return

    for oper in insn.opers:
        if isinstance(oper, envi.archs.arm.disasm.ArmImmOper):
            v = oper.getOperValue(oper)
        elif isinstance(oper, envi.archs.arm.disasm.ArmRegOper):
            continue
        elif isinstance(oper, envi.archs.arm.disasm.ArmRegShiftImmOper) and oper.reg == 0xF:  # REG_PC
            v = oper.getOperValue(oper)

        else:
            continue

        for v in derefs(f.vw, v):
            try:
                buf = read_bytes(f.vw, v)
            except envi.exc.SegmentationViolation:
                continue

            if capa.features.extractors.helpers.all_zeros(buf):
                continue

            yield Bytes(buf), ih.address


def extract_insn_nzxor_characteristic_features(
    fh: FunctionHandle, bbhandle: BBHandle, ih: InsnHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    insn: envi.Opcode = ih.inner
    bb: viv_utils.BasicBlock = bbhandle.inner
    f: viv_utils.Function = fh.inner

    if insn.mnem not in ("eor", "eors", "veor"):
        return

    if insn.opers[0] == insn.opers[1]:
        return

    if is_security_cookie(f, bb, insn):
        return

    yield Characteristic("nzxor"), ih.address


def extract_insn_mnemonic_features(f, bb, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """parse mnemonic features from the given instruction."""
    yield Mnemonic(ih.inner.mnem), ih.address


def extract_insn_obfs_call_plus_5_characteristic_features(f, bb, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse call $+5 instruction from the given instruction.
    """
    insn: envi.Opcode = ih.inner

    if insn.mnem not in ("blx", "bl"):  # call
        return

    if isinstance(insn.opers[0], envi.archs.arm.disasm.ArmPcOffsetOper):
        if insn.va + 4 == insn.opers[0].getOperValue(insn):
            yield Characteristic("call $+5"), ih.address

    if isinstance(insn.opers[0], envi.archs.arm.disasm.ArmImmOper):
        if insn.va + 4 == insn.opers[0].getOperAddr(insn):
            yield Characteristic("call $+5"), ih.address


def extract_insn_cross_section_cflow(fh: FunctionHandle, bb, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    insn: envi.Opcode = ih.inner
    f: viv_utils.Function = fh.inner

    for va, flags in insn.getBranches():
        if va is None:
            # va may be none for dynamic branches that haven't been resolved, such as `jmp eax`.
            continue

        if flags & envi.BR_FALL:
            continue

        try:
            if insn.mnem in ("b", "bl", "bx", "blx") and isinstance(
                insn.opers[0], envi.archs.arm.disasm.ArmImmOffsetOper
            ):
                oper = insn.opers[0]
                target = oper.getOperAddr(insn)

                if target in get_imports(f.vw):
                    continue

            if get_section(f.vw, insn.va) != get_section(f.vw, va):
                yield Characteristic("cross section flow"), ih.address

        except KeyError:
            continue


# this is a feature that's most relevant at the function scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_calls_from(fh: FunctionHandle, bb, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    insn: envi.Opcode = ih.inner
    f: viv_utils.Function = fh.inner

    if insn.mnem != "blx" and insn.mnem != "bl":
        return

    target = None

    if isinstance(insn.opers[0], envi.archs.arm.disasm.ArmImmOffsetOper):
        oper = insn.opers[0]
        target = oper.getOperAddr(insn)
        yield Characteristic("calls from"), AbsoluteVirtualAddress(target)

    elif isinstance(insn.opers[0], envi.archs.arm.disasm.ArmPcOffsetOper):
        target = insn.opers[0].getOperValue(insn)
        if target >= 0:
            yield Characteristic("calls from"), AbsoluteVirtualAddress(target)

    if target and target == f.va:
        # if we found a jump target and it's the function address
        # mark as recursive
        yield Characteristic("recursive call"), AbsoluteVirtualAddress(target)


# this is a feature that's most relevant at the function or basic block scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_indirect_call_characteristic_features(f, bb, ih: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    extract indirect function call characteristic (e.g., call eax or call dword ptr [edx+4])
    does not include calls like => call ds:dword_ABD4974
    """
    insn: envi.Opcode = ih.inner

    if insn.mnem not in ("bl", "blx"):
        return

    if isinstance(insn.opers[0], envi.archs.arm.disasm.ArmRegOper):
        yield Characteristic("indirect call"), ih.address
    elif isinstance(insn.opers[0], envi.archs.arm.disasm.ArmRegOffsetOper):
        yield Characteristic("indirect call"), ih.address
    elif isinstance(insn.opers[0], envi.archs.arm.disasm.ArmRegScalarOper):
        yield Characteristic("indirect call"), ih.address


def extract_op_number_features(
    fh: FunctionHandle, bb, ih: InsnHandle, i, oper: envi.Operand
) -> Iterator[Tuple[Feature, Address]]:
    """parse number features from the given operand."""

    insn: envi.Opcode = ih.inner
    f: viv_utils.Function = fh.inner

    # not sure for ImmOffsetOper
    if not isinstance(oper, (envi.archs.arm.disasm.ArmImmOper, envi.archs.arm.disasm.ArmImmOffsetOper)):
        return

    v = oper.getOperValue(oper)

    if f.vw.probeMemory(v, 1, envi.memory.MM_READ):
        # this is a valid address
        # assume its not also a constant.
        return

    if insn.mnem == "add" and insn.opers[0].isReg() and insn.opers[0].reg == envi.archs.arm.regs.REG_SP:
        # skip things like:
        #
        #    .text:00401140                 call    sub_407E2B
        #    .text:00401145                 add     esp, 0Ch
        return

    yield Number(v), ih.address
    yield OperandNumber(i, v), ih.address

    if insn.mnem == "add" and 0 < v < MAX_STRUCTURE_SIZE and isinstance(oper, envi.archs.arm.disasm.ArmImmOper):
        # for pattern like:
        #
        #     add eax, 0x10
        #
        # assume 0x10 is also an offset (imagine eax is a pointer).
        yield Offset(v), ih.address
        yield OperandOffset(i, v), ih.address


def extract_op_offset_features(
    fh: FunctionHandle, bb, ih: InsnHandle, i, oper: envi.Operand
) -> Iterator[Tuple[Feature, Address]]:
    """parse structure offset features from the given operand."""
    # example:
    #
    #     .text:0040112F    cmp     [esi+4], ebx
    insn: envi.Opcode = ih.inner
    f: viv_utils.Function = fh.inner

    # this is for both x32 and x64
    # like [esi + 4]
    #       reg   ^
    #             disp
    if isinstance(oper, envi.archs.arm.disasm.ArmRegOffsetOper):
        if oper.base_reg == envi.archs.arm.regs.REG_SP:
            return

        if oper.base_reg == envi.archs.arm.regs.REG_BP:
            return

        v = oper.offset_reg

        yield Offset(v), ih.address
        yield OperandOffset(i, v), ih.address

        if insn.mnem == "ldr" and i == 1 and not f.vw.probeMemory(v, 1, envi.memory.MM_READ):
            yield Number(v), ih.address
            yield OperandNumber(i, v), ih.address

    # like: [esi + ecx + 16384]
    #        reg   ^     ^
    #              index ^
    #                    disp
    elif isinstance(oper, envi.archs.arm.disasm.ArmRegShiftImmOper):
        v = oper.shimm

        yield Offset(v), ih.address
        yield OperandOffset(i, v), ih.address


def extract_op_string_features(
    fh: FunctionHandle, bb, ih: InsnHandle, i, oper: envi.Operand
) -> Iterator[Tuple[Feature, Address]]:
    """parse string features from the given operand."""
    # example:
    #
    #     push    offset aAcr     ; "ACR  > "
    f: viv_utils.Function = fh.inner

    if isinstance(oper, envi.archs.arm.disasm.ArmImmOper):
        v = oper.getOperValue(oper)
    elif isinstance(oper, envi.archs.arm.disasm.ArmImmOffsetOper):
        v = oper.getOperAddr(oper)
    elif isinstance(oper, envi.archs.arm.disasm.ArmRegShiftImmOper):
        v = oper.shimm
    else:
        return

    for v in derefs(f.vw, v):
        try:
            s = read_string(f.vw, v).rstrip("\x00")
        except ValueError:
            continue
        else:
            if len(s) >= 4:
                yield String(s), ih.address


def extract_op_string_arm(fh: FunctionHandle, bb: BBHandle, ih: InsnHandle):
    insn = ih.inner
    if not (
        insn.mnem == "add"
        and len(insn.opers) == 2
        and isinstance(insn.opers[0], envi.archs.arm.disasm.ArmRegOper)
        and isinstance(insn.opers[1], envi.archs.arm.disasm.ArmRegOper)
        and insn.opers[1].reg == envi.archs.arm.regs.REG_PC
    ):
        return

    f = fh.inner
    target = insn.opers[0].reg
    prev_inst = get_previous_instructions(f.vw, ih.address)
    while 1:
        i = f.vw.parseOpcode(prev_inst[0])
        if len(i.opers) == 2:
            if isinstance(i.opers[0], envi.archs.arm.disasm.ArmRegOper) and i.opers[0].reg == target:
                if i.mnem == "ldr":
                    addr = i.opers[1].getOperAddr(i.opers[1])
                    off = int.from_bytes(read_memory(f.vw, addr, 4), "big" if f.vw.bigend else "little")
                    res = ih.address + 4 + off  # may not be always 4, (next next inst)
                    try:
                        s = read_string(f.vw, res)
                        yield String(s.rstrip("\x00")), ih.address
                    except Exception:
                        return
                return
        prev_inst = get_previous_instructions(f.vw, prev_inst[0])


def extract_operand_features(f: FunctionHandle, bb, insn: InsnHandle) -> Iterator[Tuple[Feature, Address]]:
    for i, oper in enumerate(insn.inner.opers):
        for op_handler in OPERAND_HANDLERS:
            for feature, addr in op_handler(f, bb, insn, i, oper):
                yield feature, addr


OPERAND_HANDLERS: List[
    Callable[[FunctionHandle, BBHandle, InsnHandle, int, envi.Operand], Iterator[Tuple[Feature, Address]]]
] = [
    extract_op_number_features,
    extract_op_offset_features,
    extract_op_string_features,
]


def extract_features(f, bb, insn) -> Iterator[Tuple[Feature, Address]]:
    """
    extract features from the given insn.

    args:
      f (viv_utils.Function): the function from which to extract features
      bb (viv_utils.BasicBlock): the basic block to process.
      insn (vivisect...Instruction): the instruction to process.

    yields:
      Tuple[Feature, Address]: the features and their location found in this insn.
    """
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature, addr in insn_handler(f, bb, insn):
            yield feature, addr


INSTRUCTION_HANDLERS: List[Callable[[FunctionHandle, BBHandle, InsnHandle], Iterator[Tuple[Feature, Address]]]] = [
    extract_insn_api_features,
    extract_insn_bytes_features,
    extract_insn_nzxor_characteristic_features,
    extract_insn_mnemonic_features,
    extract_insn_obfs_call_plus_5_characteristic_features,
    extract_insn_cross_section_cflow,
    extract_function_calls_from,
    extract_function_indirect_call_characteristic_features,
    extract_op_string_arm,
    extract_operand_features,
]
