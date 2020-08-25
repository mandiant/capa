# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import collections

from lancelot import (
    FLOW_VA,
    OPERAND_TYPE,
    PERMISSION_READ,
    MEMORY_OPERAND_BASE,
    MEMORY_OPERAND_DISP,
    OPERAND_TYPE_MEMORY,
    MEMORY_OPERAND_INDEX,
    OPERAND_TYPE_REGISTER,
    MEMORY_OPERAND_SEGMENT,
    OPERAND_TYPE_IMMEDIATE,
    IMMEDIATE_OPERAND_VALUE,
    REGISTER_OPERAND_REGISTER,
    IMMEDIATE_OPERAND_IS_RELATIVE,
)

from capa.features.extractors.lancelot.helpers import get_operand_target

DESTRUCTIVE_MNEMONICS = ("mov", "lea", "pop", "xor")


class NotFoundError(Exception):
    pass


def read_instructions(ws, bb):
    va = bb.address
    while va < bb.address + bb.length:
        try:
            insn = ws.read_insn(va)
        except ValueError:
            return

        yield insn
        va += insn.length


def build_instruction_predecessors(ws, cfg):
    preds = collections.defaultdict(set)

    for bb in cfg.basic_blocks.values():
        insns = list(read_instructions(ws, bb))

        for i, insn in enumerate(insns):
            if i == 0:
                for pred in bb.predecessors:
                    pred_bb = cfg.basic_blocks[pred[FLOW_VA]]
                    preds[insn.address].add(list(read_instructions(ws, pred_bb))[-1].address)
            else:
                preds[insn.address].add(insns[i - 1].address)

    return preds


def find_definition(ws, f, insn):
    """
    scan backwards from the given address looking for assignments to the given register.
    if a constant, return that value.
    args:
      ws (lancelot.PE)
      f (int): the function start address
      insn (lancelot.Instruction): call instruction to resolve
    returns:
      (va: int, value?: int|None): the address of the assignment and the value, if a constant.
    raises:
      NotFoundError: when the definition cannot be found.
    """
    assert insn.mnemonic == "call"
    op0 = insn.operands[0]
    assert op0[OPERAND_TYPE] == OPERAND_TYPE_REGISTER
    reg = op0[REGISTER_OPERAND_REGISTER]

    cfg = ws.build_cfg(f)
    preds = build_instruction_predecessors(ws, cfg)

    q = collections.deque()
    seen = set([])
    q.extend(preds[insn.address])
    while q:
        cur = q.popleft()

        # skip if we've already processed this location
        if cur in seen:
            continue
        seen.add(cur)

        insn = ws.read_insn(cur)
        operands = insn.operands

        if len(operands) == 0:
            q.extend(preds[cur])
            continue

        op0 = operands[0]
        if not (
            op0[OPERAND_TYPE] == OPERAND_TYPE_REGISTER
            and op0[REGISTER_OPERAND_REGISTER] == reg
            and insn.mnemonic in DESTRUCTIVE_MNEMONICS
        ):
            q.extend(preds[cur])
            continue

        # if we reach here, the instruction is destructive to our target register.

        # we currently only support extracting the constant from something like: `mov $reg, IAT`
        # so, any other pattern results in an unknown value, represented by None.
        # this is a good place to extend in the future, if we need more robust support.
        if insn.mnemonic != "mov":
            return (cur, None)
        else:
            op1 = operands[1]
            try:
                target = get_operand_target(insn, op1)
            except ValueError:
                return (cur, None)
            else:
                return (cur, target)

    raise NotFoundError()


def is_indirect_call(insn):
    return insn.mnemonic == "call" and insn.operands[0][OPERAND_TYPE] == OPERAND_TYPE_REGISTER


def resolve_indirect_call(ws, f, insn):
    """
    inspect the given indirect call instruction and attempt to resolve the target address.
    args:
      ws (lancelot.PE): the analysis workspace
      f (int): the address of the function to analyze
      insn (lancelot.Instruction): the instruction at which to start analysis
    returns:
      (va: int, value?: int|None): the address of the assignment and the value, if a constant.
    raises:
      NotFoundError: when the definition cannot be found.
    """
    assert is_indirect_call(insn)
    return find_definition(ws, f, insn)
