# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import copy

import pytest
import fixtures

import capa
import capa.engine as ceng
import capa.render.result_document as rdoc
import capa.features.freeze.features as frzf


def test_optional_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Some(
            0,
            [],
        )
    )
    assert isinstance(node, rdoc.StatementNode)
    assert isinstance(node.statement, rdoc.CompoundStatement)
    assert node.statement.type == rdoc.CompoundStatementType.OPTIONAL


def test_some_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Some(
            1,
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node, rdoc.StatementNode)
    assert isinstance(node.statement, rdoc.SomeStatement)


def test_range_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Range(
            capa.features.insn.Number(0),
        )
    )
    assert isinstance(node, rdoc.StatementNode)
    assert isinstance(node.statement, rdoc.RangeStatement)


def test_subscope_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Subscope(
            capa.rules.Scope.BASIC_BLOCK,
            capa.features.insn.Number(0),
        )
    )
    assert isinstance(node, rdoc.StatementNode)
    assert isinstance(node.statement, rdoc.SubscopeStatement)


def test_and_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.And(
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node, rdoc.StatementNode)
    assert isinstance(node.statement, rdoc.CompoundStatement)
    assert node.statement.type == rdoc.CompoundStatementType.AND


def test_or_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Or(
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node, rdoc.StatementNode)
    assert isinstance(node.statement, rdoc.CompoundStatement)
    assert node.statement.type == rdoc.CompoundStatementType.OR


def test_not_node_from_capa():
    node = rdoc.node_from_capa(
        ceng.Not(
            [
                capa.features.insn.Number(0),
            ],
        )
    )
    assert isinstance(node, rdoc.StatementNode)
    assert isinstance(node.statement, rdoc.CompoundStatement)
    assert node.statement.type == rdoc.CompoundStatementType.NOT


def test_os_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.OS(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.OSFeature)


def test_arch_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Arch(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.ArchFeature)


def test_format_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Format(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.FormatFeature)


def test_match_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.MatchedRule(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.MatchFeature)


def test_characteristic_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Characteristic(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.CharacteristicFeature)


def test_substring_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Substring(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.SubstringFeature)


def test_regex_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Regex(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.RegexFeature)


def test_class_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Class(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.ClassFeature)


def test_namespace_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Namespace(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.NamespaceFeature)


def test_bytes_node_from_capa():
    node = rdoc.node_from_capa(capa.features.common.Bytes(b""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.BytesFeature)


def test_export_node_from_capa():
    node = rdoc.node_from_capa(capa.features.file.Export(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.ExportFeature)


def test_import_node_from_capa():
    node = rdoc.node_from_capa(capa.features.file.Import(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.ImportFeature)


def test_section_node_from_capa():
    node = rdoc.node_from_capa(capa.features.file.Section(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.SectionFeature)


def test_function_name_node_from_capa():
    node = rdoc.node_from_capa(capa.features.file.FunctionName(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.FunctionNameFeature)


def test_api_node_from_capa():
    node = rdoc.node_from_capa(capa.features.insn.API(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.APIFeature)


def test_property_node_from_capa():
    node = rdoc.node_from_capa(capa.features.insn.Property(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.PropertyFeature)


def test_number_node_from_capa():
    node = rdoc.node_from_capa(capa.features.insn.Number(0))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.NumberFeature)


def test_offset_node_from_capa():
    node = rdoc.node_from_capa(capa.features.insn.Offset(0))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.OffsetFeature)


def test_mnemonic_node_from_capa():
    node = rdoc.node_from_capa(capa.features.insn.Mnemonic(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.MnemonicFeature)


def test_operand_number_node_from_capa():
    node = rdoc.node_from_capa(capa.features.insn.OperandNumber(0, 0))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.OperandNumberFeature)


def test_operand_offset_node_from_capa():
    node = rdoc.node_from_capa(capa.features.insn.OperandOffset(0, 0))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.OperandOffsetFeature)


def test_basic_block_node_from_capa():
    node = rdoc.node_from_capa(capa.features.basicblock.BasicBlock(""))
    assert isinstance(node, rdoc.FeatureNode)
    assert isinstance(node.feature, frzf.BasicBlockFeature)


def assert_round_trip(rd: rdoc.ResultDocument):
    one = rd

    doc = one.model_dump_json(exclude_none=True)
    two = rdoc.ResultDocument.model_validate_json(doc)

    # show the round trip works
    # first by comparing the objects directly,
    # which works thanks to pydantic model equality.
    assert one == two
    # second by showing their json representations are the same.
    assert one.model_dump_json(exclude_none=True) == two.model_dump_json(exclude_none=True)

    # now show that two different versions are not equal.
    three = copy.deepcopy(two)
    three.meta.__dict__.update({"version": "0.0.0"})
    assert one.meta.version != three.meta.version
    assert one != three
    assert one.model_dump_json(exclude_none=True) != three.model_dump_json(exclude_none=True)


@pytest.mark.parametrize(
    "rd_file",
    [
        pytest.param("a3f3bbc_rd"),
        pytest.param("al_khaserx86_rd"),
        pytest.param("al_khaserx64_rd"),
        pytest.param("a076114_rd"),
        pytest.param("pma0101_rd"),
        pytest.param("dotnet_1c444e_rd"),
    ],
)
def test_round_trip(request, rd_file):
    rd: rdoc.ResultDocument = request.getfixturevalue(rd_file)
    assert_round_trip(rd)


def test_json_to_rdoc():
    path = fixtures.get_data_path_by_name("pma01-01-rd")
    assert isinstance(rdoc.ResultDocument.from_file(path), rdoc.ResultDocument)


def test_rdoc_to_capa():
    path = fixtures.get_data_path_by_name("pma01-01-rd")

    rd = rdoc.ResultDocument.from_file(path)

    meta, capabilites = rd.to_capa()
    assert isinstance(meta, rdoc.Metadata)
    assert isinstance(capabilites, dict)
