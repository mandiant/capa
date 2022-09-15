# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import capa
import capa.engine as ceng
import capa.render.result_document as rdoc


def test_optional_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Some(
            0,
            [],
        )
    )
    assert isinstance(node.statement, rdoc.OptionalStatement)


def test_some_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Some(
            1,
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node.statement, rdoc.SomeStatement)


def test_range_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Range(
            capa.features.insn.Number(0),
        )
    )
    assert isinstance(node.statement, rdoc.RangeStatement)


def test_subscope_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Subscope(
            capa.rules.Scope.BASIC_BLOCK,
            capa.features.insn.Number(0),
        )
    )
    assert isinstance(node.statement, rdoc.SubscopeStatement)


def test_and_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.And(
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node.statement, rdoc.AndStatement)


def test_or_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Or(
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node.statement, rdoc.OrStatement)


def test_not_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Not(
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node.statement, rdoc.NotStatement)
