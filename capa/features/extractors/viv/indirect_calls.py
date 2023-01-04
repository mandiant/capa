# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import collections
from typing import Set, List, Deque, Tuple, Union, Optional

import envi
import vivisect.const
import envi.archs.i386.disasm
import envi.archs.amd64.disasm
from vivisect import VivWorkspace

# pull out consts for lookup performance
i386RegOper = envi.archs.i386.disasm.i386RegOper
i386ImmOper = envi.archs.i386.disasm.i386ImmOper
i386ImmMemOper = envi.archs.i386.disasm.i386ImmMemOper
Amd64RipRelOper = envi.archs.amd64.disasm.Amd64RipRelOper
LOC_OP = vivisect.const.LOC_OP
IF_NOFALL = envi.IF_NOFALL
REF_CODE = vivisect.const.REF_CODE
FAR_BRANCH_MASK = envi.BR_PROC | envi.BR_DEREF | envi.BR_ARCH

DESTRUCTIVE_MNEMONICS = ("mov", "lea", "pop", "xor")


def get_previous_instructions(vw: VivWorkspace, va: int) -> List[int]:
    """
    collect the instructions that flow to the given address, local to the current function.

    args:
      vw (vivisect.Workspace)
      va (int): the virtual address to inspect

    returns:
      List[int]: the prior instructions, which may fallthrough and/or jump here
    """
    ret = []

    # find the immediate prior instruction.
    # ensure that it falls through to this one.
    loc = vw.getPrevLocation(va, adjacent=True)
    if loc is not None:
        ploc = vw.getPrevLocation(va, adjacent=True)
        if ploc is not None:
            # from vivisect.const:
            # location: (L_VA, L_SIZE, L_LTYPE, L_TINFO)
            (pva, _, ptype, pinfo) = ploc

            if ptype == LOC_OP and not (pinfo & IF_NOFALL):
                ret.append(pva)

    # find any code refs, e.g. jmp, to this location.
    # ignore any calls.
    #
    # from vivisect.const:
    # xref: (XR_FROM, XR_TO, XR_RTYPE, XR_RFLAG)
    for (xfrom, _, _, xflag) in vw.getXrefsTo(va, REF_CODE):
        if (xflag & FAR_BRANCH_MASK) != 0:
            continue
        ret.append(xfrom)

    return ret


class NotFoundError(Exception):
    pass


def find_definition(vw: VivWorkspace, va: int, reg: int) -> Tuple[int, Union[int, None]]:
    """
    scan backwards from the given address looking for assignments to the given register.
    if a constant, return that value.

    args:
      vw (vivisect.Workspace)
      va (int): the virtual address at which to start analysis
      reg (int): the vivisect register to study

    returns:
      (va: int, value?: int|None): the address of the assignment and the value, if a constant.

    raises:
      NotFoundError: when the definition cannot be found.
    """
    q = collections.deque()  # type: Deque[int]
    seen = set([])  # type: Set[int]

    q.extend(get_previous_instructions(vw, va))
    while q:
        cur = q.popleft()

        # skip if we've already processed this location
        if cur in seen:
            continue
        seen.add(cur)

        insn = vw.parseOpcode(cur)

        if len(insn.opers) == 0:
            q.extend(get_previous_instructions(vw, cur))
            continue

        opnd0 = insn.opers[0]
        if not (isinstance(opnd0, i386RegOper) and opnd0.reg == reg and insn.mnem in DESTRUCTIVE_MNEMONICS):
            q.extend(get_previous_instructions(vw, cur))
            continue

        # if we reach here, the instruction is destructive to our target register.

        # we currently only support extracting the constant from something like: `mov $reg, IAT`
        # so, any other pattern results in an unknown value, represented by None.
        # this is a good place to extend in the future, if we need more robust support.
        if insn.mnem != "mov":
            return (cur, None)
        else:
            opnd1 = insn.opers[1]
            if isinstance(opnd1, i386ImmOper):
                return (cur, opnd1.getOperValue(opnd1))
            elif isinstance(opnd1, i386ImmMemOper):
                return (cur, opnd1.getOperAddr(opnd1))
            elif isinstance(opnd1, Amd64RipRelOper):
                return (cur, opnd1.getOperAddr(insn))
            else:
                # might be something like: `mov $reg, dword_401000[eax]`
                return (cur, None)

    raise NotFoundError()


def is_indirect_call(vw: VivWorkspace, va: int, insn: envi.Opcode) -> bool:
    if insn is None:
        insn = vw.parseOpcode(va)

    return insn.mnem in ("call", "jmp") and isinstance(insn.opers[0], envi.archs.i386.disasm.i386RegOper)


def resolve_indirect_call(vw: VivWorkspace, va: int, insn: envi.Opcode) -> Tuple[int, Optional[int]]:
    """
    inspect the given indirect call instruction and attempt to resolve the target address.

    args:
      vw (vivisect.Workspace)
      va (int): the virtual address at which to start analysis

    returns:
      (va: int, value?: int|None): the address of the assignment and the value, if a constant.

    raises:
      NotFoundError: when the definition cannot be found.
    """
    if insn is None:
        insn = vw.parseOpcode(va)

    assert is_indirect_call(vw, va, insn=insn)

    return find_definition(vw, va, insn.opers[0].reg)
