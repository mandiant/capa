# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import re
from typing import Set, Dict, List, Tuple, Union, Iterator, Optional
from collections import defaultdict
from dataclasses import dataclass

import capa.features.extractors.helpers
import capa.features.extractors.binexport2.helpers
from capa.features.common import ARCH_I386, ARCH_AMD64, ARCH_AARCH64
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

HAS_ARCH32 = {ARCH_I386}
HAS_ARCH64 = {ARCH_AARCH64, ARCH_AMD64}

HAS_ARCH_INTEL = {ARCH_I386, ARCH_AMD64}
HAS_ARCH_ARM = {ARCH_AARCH64}


def mask_immediate(arch: Set[str], immediate: int) -> int:
    if arch & HAS_ARCH64:
        immediate &= 0xFFFFFFFFFFFFFFFF
    elif arch & HAS_ARCH32:
        immediate &= 0xFFFFFFFF
    return immediate


def twos_complement(arch: Set[str], immediate: int, default: Optional[int] = None) -> int:
    if default is not None:
        return capa.features.extractors.helpers.twos_complement(immediate, default)
    elif arch & HAS_ARCH64:
        return capa.features.extractors.helpers.twos_complement(immediate, 64)
    elif arch & HAS_ARCH32:
        return capa.features.extractors.helpers.twos_complement(immediate, 32)
    return immediate


def is_address_mapped(be2: BinExport2, address: int) -> bool:
    """return True if the given address is mapped"""
    sections_with_perms: Iterator[BinExport2.Section] = filter(lambda s: s.flag_r or s.flag_w or s.flag_x, be2.section)
    return any(section.address <= address < section.address + section.size for section in sections_with_perms)


def is_vertex_type(vertex: BinExport2.CallGraph.Vertex, type_: BinExport2.CallGraph.Vertex.Type.ValueType) -> bool:
    return vertex.HasField("type") and vertex.type == type_


# internal to `build_expression_tree`
# this is unstable: it is subject to change, so don't rely on it!
def _prune_expression_tree_empty_shifts(
    be2: BinExport2,
    operand: BinExport2.Operand,
    expression_tree: List[List[int]],
    tree_index: int,
):
    expression_index = operand.expression_index[tree_index]
    expression = be2.expression[expression_index]
    children_tree_indexes: List[int] = expression_tree[tree_index]

    if expression.type == BinExport2.Expression.OPERATOR:
        if len(children_tree_indexes) == 0 and expression.symbol in ("lsl", "lsr"):
            # Ghidra may emit superfluous lsl nodes with no children.
            # https://github.com/mandiant/capa/pull/2340/files#r1750003919
            # Which is maybe: https://github.com/NationalSecurityAgency/ghidra/issues/6821#issuecomment-2295394697
            #
            # Which seems to be as if the shift wasn't there (shift of #0)
            # so we want to remove references to this node from any parent nodes.
            for tree_node in expression_tree:
                if tree_index in tree_node:
                    tree_node.remove(tree_index)

            return

    for child_tree_index in children_tree_indexes:
        _prune_expression_tree_empty_shifts(be2, operand, expression_tree, child_tree_index)


# internal to `build_expression_tree`
# this is unstable: it is subject to change, so don't rely on it!
def _prune_expression_tree_empty_commas(
    be2: BinExport2,
    operand: BinExport2.Operand,
    expression_tree: List[List[int]],
    tree_index: int,
):
    expression_index = operand.expression_index[tree_index]
    expression = be2.expression[expression_index]
    children_tree_indexes: List[int] = expression_tree[tree_index]

    if expression.type == BinExport2.Expression.OPERATOR:
        if len(children_tree_indexes) == 1 and expression.symbol == ",":
            # Due to the above pruning of empty LSL or LSR expressions,
            # the parents might need to be fixed up.
            #
            # Specifically, if the pruned node was part of a comma list with two children,
            # now there's only a single child, which renders as an extra comma,
            # so we replace references to the comma node with the immediate child.
            #
            # A more correct way of doing this might be to walk up the parents and do fixups,
            # but I'm not quite sure how to do this yet. Just do two passes right now.
            child = children_tree_indexes[0]

            for tree_node in expression_tree:
                tree_node.index
                if tree_index in tree_node:
                    tree_node[tree_node.index(tree_index)] = child

            return

    for child_tree_index in children_tree_indexes:
        _prune_expression_tree_empty_commas(be2, operand, expression_tree, child_tree_index)


# internal to `build_expression_tree`
# this is unstable: it is subject to change, so don't rely on it!
def _prune_expression_tree(
    be2: BinExport2,
    operand: BinExport2.Operand,
    expression_tree: List[List[int]],
):
    _prune_expression_tree_empty_shifts(be2, operand, expression_tree, 0)
    _prune_expression_tree_empty_commas(be2, operand, expression_tree, 0)


# this is unstable: it is subject to change, so don't rely on it!
def _build_expression_tree(
    be2: BinExport2,
    operand: BinExport2.Operand,
) -> List[List[int]]:
    # The reconstructed expression tree layout, linking parent nodes to their children.
    #
    # There is one list of integers for each expression in the operand.
    # These integers are indexes of other expressions in the same operand,
    # which are the children of that expression.
    #
    # So:
    #
    #   [ [1, 3], [2], [], [4], [5], []]
    #
    # means the first expression has two children, at index 1 and 3,
    # and the tree looks like:
    #
    #        0
    #       / \
    #      1   3
    #      |   |
    #      2   4
    #          |
    #          5
    #
    # Remember, these are the indices into the entries in operand.expression_index.
    if len(operand.expression_index) == 0:
        # Ghidra bug where empty operands (no expressions) may
        # exist (see https://github.com/NationalSecurityAgency/ghidra/issues/6817)
        return []

    tree: List[List[int]] = []
    for i, expression_index in enumerate(operand.expression_index):
        children = []

        # scan all subsequent expressions, looking for those that have parent_index == current.expression_index
        for j, candidate_index in enumerate(operand.expression_index[i + 1 :]):
            candidate = be2.expression[candidate_index]

            if candidate.parent_index == expression_index:
                children.append(i + j + 1)

        tree.append(children)

    _prune_expression_tree(be2, operand, tree)
    _prune_expression_tree(be2, operand, tree)

    return tree


def _fill_operand_expression_list(
    be2: BinExport2,
    operand: BinExport2.Operand,
    expression_tree: List[List[int]],
    tree_index: int,
    expression_list: List[BinExport2.Expression],
):
    """
    Walk the given expression tree and collect the expression nodes in-order.
    """
    expression_index = operand.expression_index[tree_index]
    expression = be2.expression[expression_index]
    children_tree_indexes: List[int] = expression_tree[tree_index]

    if expression.type == BinExport2.Expression.REGISTER:
        assert len(children_tree_indexes) == 0
        expression_list.append(expression)
        return

    elif expression.type == BinExport2.Expression.SYMBOL:
        assert len(children_tree_indexes) <= 1
        expression_list.append(expression)

        if len(children_tree_indexes) == 0:
            return
        elif len(children_tree_indexes) == 1:
            # like: v
            # from: mov v0.D[0x1], x9
            #           |
            #           0
            #           .
            #           |
            #           D
            child_index = children_tree_indexes[0]
            _fill_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
            return
        else:
            raise NotImplementedError(len(children_tree_indexes))

    elif expression.type == BinExport2.Expression.IMMEDIATE_INT:
        assert len(children_tree_indexes) == 0
        expression_list.append(expression)
        return

    elif expression.type == BinExport2.Expression.SIZE_PREFIX:
        # like: b4
        #
        # We might want to use this occasionally, such as to disambiguate the
        # size of MOVs into/out of memory. But I'm not sure when/where we need that yet.
        #
        # IDA spams this size prefix hint *everywhere*, so we can't rely on the exporter
        # to provide it only when necessary.
        assert len(children_tree_indexes) == 1
        child_index = children_tree_indexes[0]
        _fill_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
        return

    elif expression.type == BinExport2.Expression.OPERATOR:
        if len(children_tree_indexes) == 1:
            # prefix operator, like "ds:"
            expression_list.append(expression)
            child_index = children_tree_indexes[0]
            _fill_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
            return

        elif len(children_tree_indexes) == 2:
            # infix operator: like "+" in "ebp+10"
            child_a = children_tree_indexes[0]
            child_b = children_tree_indexes[1]
            _fill_operand_expression_list(be2, operand, expression_tree, child_a, expression_list)
            expression_list.append(expression)
            _fill_operand_expression_list(be2, operand, expression_tree, child_b, expression_list)
            return

        elif len(children_tree_indexes) == 3:
            # infix operator: like "+" in "ebp+ecx+10"
            child_a = children_tree_indexes[0]
            child_b = children_tree_indexes[1]
            child_c = children_tree_indexes[2]
            _fill_operand_expression_list(be2, operand, expression_tree, child_a, expression_list)
            expression_list.append(expression)
            _fill_operand_expression_list(be2, operand, expression_tree, child_b, expression_list)
            expression_list.append(expression)
            _fill_operand_expression_list(be2, operand, expression_tree, child_c, expression_list)
            return

        else:
            raise NotImplementedError(len(children_tree_indexes))

    elif expression.type == BinExport2.Expression.DEREFERENCE:
        assert len(children_tree_indexes) == 1
        expression_list.append(expression)

        child_index = children_tree_indexes[0]
        _fill_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
        return

    elif expression.type == BinExport2.Expression.IMMEDIATE_FLOAT:
        raise NotImplementedError(expression.type)

    else:
        raise NotImplementedError(expression.type)


def get_operand_expressions(be2: BinExport2, op: BinExport2.Operand) -> List[BinExport2.Expression]:
    tree = _build_expression_tree(be2, op)

    expressions: List[BinExport2.Expression] = []
    _fill_operand_expression_list(be2, op, tree, 0, expressions)

    return expressions


def get_operand_register_expression(be2: BinExport2, operand: BinExport2.Operand) -> Optional[BinExport2.Expression]:
    if len(operand.expression_index) == 1:
        expression: BinExport2.Expression = be2.expression[operand.expression_index[0]]
        if expression.type == BinExport2.Expression.REGISTER:
            return expression
    return None


def get_operand_immediate_expression(be2: BinExport2, operand: BinExport2.Operand) -> Optional[BinExport2.Expression]:
    if len(operand.expression_index) == 1:
        # - type: IMMEDIATE_INT
        #   immediate: 20588728364
        #   parent_index: 0
        expression: BinExport2.Expression = be2.expression[operand.expression_index[0]]
        if expression.type == BinExport2.Expression.IMMEDIATE_INT:
            return expression

    elif len(operand.expression_index) == 2:
        # from IDA, which provides a size hint for every operand,
        # we get the following pattern for immediate constants:
        #
        # - type: SIZE_PREFIX
        #   symbol: "b8"
        # - type: IMMEDIATE_INT
        #   immediate: 20588728364
        #   parent_index: 0
        expression0: BinExport2.Expression = be2.expression[operand.expression_index[0]]
        expression1: BinExport2.Expression = be2.expression[operand.expression_index[1]]

        if expression0.type == BinExport2.Expression.SIZE_PREFIX:
            if expression1.type == BinExport2.Expression.IMMEDIATE_INT:
                return expression1

    return None


def get_instruction_mnemonic(be2: BinExport2, instruction: BinExport2.Instruction) -> str:
    return be2.mnemonic[instruction.mnemonic_index].name.lower()


def get_instruction_operands(be2: BinExport2, instruction: BinExport2.Instruction) -> List[BinExport2.Operand]:
    return [be2.operand[operand_index] for operand_index in instruction.operand_index]


def split_with_delimiters(s: str, delimiters: Tuple[str, ...]) -> Iterator[str]:
    """
    Splits a string by any of the provided delimiter characters,
    including the delimiters in the results.

    Args:
        string: The string to split.
        delimiters: A string containing the characters to use as delimiters.
    """
    start = 0
    for i, char in enumerate(s):
        if char in delimiters:
            yield s[start:i]
            yield char
            start = i + 1

    if start < len(s):
        yield s[start:]


BinExport2OperandPattern = Union[str, Tuple[str, ...]]


@dataclass
class BinExport2InstructionPattern:
    """
    This describes a way to match disassembled instructions, with mnemonics and operands.

    You can specify constraints on the instruction, via:
      - the mnemonics, like "mov",
      - number of operands, and
      - format of each operand, "[reg, reg, #int]".

    During matching, you can also capture a single element, to see its concrete value.
    For example, given the pattern:

        mov reg0, #int0  ; capture int0

    and the instruction:

        mov eax, 1

    Then the capture will contain the immediate integer 1.

    This matcher uses the BinExport2 data layout under the hood.
    """

    mnemonics: Tuple[str, ...]
    operands: Tuple[Union[str, BinExport2OperandPattern], ...]
    capture: Optional[str]

    @classmethod
    def from_str(cls, query: str):
        """
        Parse a pattern string into a Pattern instance.
        The supported syntax is like this:

            br      reg
            br      reg                          ; capture reg
            br      reg(stack)                   ; capture reg
            br      reg(not-stack)               ; capture reg
            mov     reg0, reg1                   ; capture reg0
            adrp    reg, #int                    ; capture #int
            add     reg, reg, #int               ; capture #int
            ldr     reg0, [reg1]                 ; capture reg1
            ldr|str reg, [reg, #int]             ; capture #int
            ldr|str reg, [reg(stack), #int]      ; capture #int
            ldr|str reg, [reg(not-stack), #int]  ; capture #int
            ldr|str reg, [reg, #int]!            ; capture #int
            ldr|str reg, [reg], #int             ; capture #int
            ldp|stp reg, reg, [reg, #int]        ; capture #int
            ldp|stp reg, reg, [reg, #int]!       ; capture #int
            ldp|stp reg, reg, [reg], #int        ; capture #int
        """
        #
        # The implementation of the parser here is obviously ugly.
        # Its handwritten and probably fragile. But since we don't
        # expect this to be widely used, its probably ok.
        # Don't hesitate to rewrite this if it becomes more important.
        #
        # Note that this doesn't have to be very performant.
        # We expect these patterns to be parsed once upfront and then reused
        # (globally at the module level?) rather than within any loop.
        #

        pattern, _, comment = query.strip().partition(";")

        # we don't support fs: yet
        assert ":" not in pattern

        # from "capture #int" to "#int"
        if comment:
            comment = comment.strip()
            assert comment.startswith("capture ")
            capture = comment[len("capture ") :]
        else:
            capture = None

        # from "ldr|str ..." to ["ldr", "str"]
        pattern = pattern.strip()
        mnemonic, _, rest = pattern.partition(" ")
        mnemonics = mnemonic.split("|")

        operands: List[Union[str, Tuple[str, ...]]] = []
        while rest:
            rest = rest.strip()
            if not rest.startswith("["):
                # If its not a dereference, which looks like `[op, op, op, ...]`,
                # then its a simple operand, which we can split by the next comma.
                operand, _, rest = rest.partition(", ")
                rest = rest.strip()
                operands.append(operand)

            else:
                # This looks like a dereference, something like `[op, op, op, ...]`.
                # Since these can't be nested, look for the next ] and then parse backwards.
                deref_end = rest.index("]")
                try:
                    deref_end = rest.index(", ", deref_end)
                    deref_end += len(", ")
                except ValueError:
                    deref = rest
                    rest = ""
                else:
                    deref = rest[:deref_end]
                    rest = rest[deref_end:]
                    rest = rest.strip()
                    deref = deref.rstrip(" ")
                    deref = deref.rstrip(",")

                # like: [reg, #int]!
                has_postindex_writeback = deref.endswith("!")

                deref = deref.rstrip("!")
                deref = deref.rstrip("]")
                deref = deref.lstrip("[")

                parts = tuple(split_with_delimiters(deref, (",", "+", "*")))
                parts = tuple(s.strip() for s in parts)

                # emit operands in this order to match
                # how BinExport2 expressions are flatted
                # by get_operand_expressions
                if has_postindex_writeback:
                    operands.append(("!", "[") + parts)
                else:
                    operands.append(("[",) + parts)

        for operand in operands:  # type: ignore
            # Try to ensure we've parsed the operands correctly.
            # This is just sanity checking.
            for o in (operand,) if isinstance(operand, str) else operand:
                # operands can look like:
                #  - reg
                #  - reg0
                #  - reg(stack)
                #  - reg0(stack)
                #  - reg(not-stack)
                #  - reg0(not-stack)
                #  - #int
                #  - #int0
                # and a limited set of supported operators.
                # use an inline regex so that its easy to read. not perf critical.
                assert re.match(r"^(reg|#int)[0-9]?(\(stack\)|\(not-stack\))?$", o) or o in ("[", ",", "!", "+", "*")

        return cls(tuple(mnemonics), tuple(operands), capture)

    @dataclass
    class MatchResult:
        operand_index: int
        expression_index: int
        expression: BinExport2.Expression

    def match(
        self, mnemonic: str, operand_expressions: List[List[BinExport2.Expression]]
    ) -> Optional["BinExport2InstructionPattern.MatchResult"]:
        """
        Match the given BinExport2 data against this pattern.

        The BinExport2 expression tree must have been flattened, such as with
        capa.features.extractors.binexport2.helpers.get_operand_expressions.

        If there's a match, the captured Expression instance is returned.
        Otherwise, you get None back.
        """
        if mnemonic not in self.mnemonics:
            return None

        if len(self.operands) != len(operand_expressions):
            return None

        captured = None

        for operand_index, found_expressions in enumerate(operand_expressions):
            wanted_expressions = self.operands[operand_index]

            # from `"reg"` to `("reg", )`
            if isinstance(wanted_expressions, str):
                wanted_expressions = (wanted_expressions,)
            assert isinstance(wanted_expressions, tuple)

            if len(wanted_expressions) != len(found_expressions):
                return None

            for expression_index, (wanted_expression, found_expression) in enumerate(
                zip(wanted_expressions, found_expressions)
            ):
                if wanted_expression.startswith("reg"):
                    if found_expression.type != BinExport2.Expression.REGISTER:
                        return None

                    if wanted_expression.endswith(")"):
                        if wanted_expression.endswith("(not-stack)"):
                            # intel 64: rsp, esp, sp,
                            # intel 32: ebp, ebp, bp
                            # arm: sp
                            register_name = found_expression.symbol.lower()
                            if register_name in ("rsp", "esp", "sp", "rbp", "ebp", "bp"):
                                return None

                        elif wanted_expression.endswith("(stack)"):
                            register_name = found_expression.symbol.lower()
                            if register_name not in ("rsp", "esp", "sp", "rbp", "ebp", "bp"):
                                return None

                        else:
                            raise ValueError("unexpected expression suffix", wanted_expression)

                    if self.capture == wanted_expression:
                        captured = BinExport2InstructionPattern.MatchResult(
                            operand_index, expression_index, found_expression
                        )

                elif wanted_expression.startswith("#int"):
                    if found_expression.type != BinExport2.Expression.IMMEDIATE_INT:
                        return None

                    if self.capture == wanted_expression:
                        captured = BinExport2InstructionPattern.MatchResult(
                            operand_index, expression_index, found_expression
                        )

                elif wanted_expression == "[":
                    if found_expression.type != BinExport2.Expression.DEREFERENCE:
                        return None

                elif wanted_expression in (",", "!", "+", "*"):
                    if found_expression.type != BinExport2.Expression.OPERATOR:
                        return None

                    if found_expression.symbol != wanted_expression:
                        return None

                else:
                    raise ValueError(found_expression)

        if captured:
            return captured
        else:
            # There were no captures, so
            # return arbitrary non-None expression
            return BinExport2InstructionPattern.MatchResult(operand_index, expression_index, found_expression)


class BinExport2InstructionPatternMatcher:
    """Index and match a collection of instruction patterns."""

    def __init__(self, queries: List[BinExport2InstructionPattern]):
        self.queries = queries
        # shard the patterns by (mnemonic, #operands)
        self._index: Dict[Tuple[str, int], List[BinExport2InstructionPattern]] = defaultdict(list)

        for query in queries:
            for mnemonic in query.mnemonics:
                self._index[(mnemonic.lower(), len(query.operands))].append(query)

    @classmethod
    def from_str(cls, patterns: str):
        return cls(
            [
                BinExport2InstructionPattern.from_str(line)
                for line in filter(
                    lambda line: not line.startswith("#"), (line.strip() for line in patterns.split("\n"))
                )
            ]
        )

    def match(
        self, mnemonic: str, operand_expressions: List[List[BinExport2.Expression]]
    ) -> Optional[BinExport2InstructionPattern.MatchResult]:
        queries = self._index.get((mnemonic.lower(), len(operand_expressions)), [])
        for query in queries:
            captured = query.match(mnemonic.lower(), operand_expressions)
            if captured:
                return captured

        return None

    def match_with_be2(
        self, be2: BinExport2, instruction_index: int
    ) -> Optional[BinExport2InstructionPattern.MatchResult]:
        instruction: BinExport2.Instruction = be2.instruction[instruction_index]
        mnemonic: str = get_instruction_mnemonic(be2, instruction)

        if (mnemonic.lower(), len(instruction.operand_index)) not in self._index:
            # verify that we might have a hit before we realize the operand expression list
            return None

        operands = []
        for operand_index in instruction.operand_index:
            operands.append(get_operand_expressions(be2, be2.operand[operand_index]))

        return self.match(mnemonic, operands)
