# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Set, List, Iterator, Optional

import capa.features.extractors.helpers
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


def _get_operand_expression_list(
    be2: BinExport2,
    operand: BinExport2.Operand,
    expression_tree: List[List[int]],
    tree_index: int,
    expression_list: List[BinExport2.Expression],
):
    exp_index = operand.expression_index[tree_index]
    expression = be2.expression[exp_index]
    children_tree_indexes: List[int] = expression_tree[tree_index]

    if expression.type == BinExport2.Expression.REGISTER:
        expression_list.append(expression)
        assert len(children_tree_indexes) == 0
        return

    elif expression.type == BinExport2.Expression.SYMBOL:
        expression_list.append(expression)
        assert len(children_tree_indexes) <= 1

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
            _get_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
            return
        else:
            raise NotImplementedError(len(children_tree_indexes))

    elif expression.type == BinExport2.Expression.IMMEDIATE_INT:
        expression_list.append(expression)
        assert len(children_tree_indexes) == 0
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
        _get_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
        return

    elif expression.type == BinExport2.Expression.OPERATOR:

        if len(children_tree_indexes) == 1:
            # prefix operator, like "ds:"
            expression_list.append(expression)
            child_index = children_tree_indexes[0]
            _get_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
            return

        elif len(children_tree_indexes) == 2:
            # infix operator: like "+" in "ebp+10"
            child_a = children_tree_indexes[0]
            child_b = children_tree_indexes[1]
            _get_operand_expression_list(be2, operand, expression_tree, child_a, expression_list)
            expression_list.append(expression)
            _get_operand_expression_list(be2, operand, expression_tree, child_b, expression_list)
            return

        elif len(children_tree_indexes) == 3:
            # infix operator: like "+" in "ebp+ecx+10"
            child_a = children_tree_indexes[0]
            child_b = children_tree_indexes[1]
            child_c = children_tree_indexes[2]
            _get_operand_expression_list(be2, operand, expression_tree, child_a, expression_list)
            expression_list.append(expression)
            _get_operand_expression_list(be2, operand, expression_tree, child_b, expression_list)
            expression_list.append(expression)
            _get_operand_expression_list(be2, operand, expression_tree, child_c, expression_list)
            return

        else:
            raise NotImplementedError(len(children_tree_indexes))

    elif expression.type == BinExport2.Expression.DEREFERENCE:
        expression_list.append(expression)

        assert len(children_tree_indexes) == 1
        child_index = children_tree_indexes[0]
        _get_operand_expression_list(be2, operand, expression_tree, child_index, expression_list)
        return

    elif expression.type == BinExport2.Expression.IMMEDIATE_FLOAT:
        raise NotImplementedError(expression.type)

    else:
        raise NotImplementedError(expression.type)


def get_operand_expressions(be2: BinExport2, op: BinExport2.Operand) -> List[BinExport2.Expression]:
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
    exp_tree: List[List[int]] = []
    for i, exp_index in enumerate(op.expression_index):
        children = []

        # scan all subsequent expressions, looking for those that have parent_index == current.expression_index
        for j, candidate_index in enumerate(op.expression_index[i + 1 :]):
            candidate = be2.expression[candidate_index]

            if candidate.parent_index == exp_index:
                children.append(i + j + 1)

        exp_tree.append(children)

    exp_list: List[BinExport2.Expression] = []
    _get_operand_expression_list(be2, op, exp_tree, 0, exp_list)

    return exp_list


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
