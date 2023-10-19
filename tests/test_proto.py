# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import copy
from typing import Any

import pytest

import capa.rules
import capa.render
import capa.render.proto
import capa.render.utils
import capa.features.freeze
import capa.features.address
import capa.render.proto.capa_pb2 as capa_pb2
import capa.render.result_document as rd
import capa.features.freeze.features
from capa.helpers import assert_never


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
def test_doc_to_pb2(request, rd_file):
    src: rd.ResultDocument = request.getfixturevalue(rd_file)
    dst = capa.render.proto.doc_to_pb2(src)

    assert_meta(src.meta, dst.meta)

    for rule_name, matches in src.rules.items():
        assert rule_name in dst.rules

        m: capa_pb2.RuleMetadata = dst.rules[rule_name].meta
        assert matches.meta.name == m.name
        assert cmp_optional(matches.meta.namespace, m.namespace)
        assert list(matches.meta.authors) == m.authors
        assert capa.render.proto.scopes_to_pb2(matches.meta.scopes) == m.scopes

        assert len(matches.meta.attack) == len(m.attack)
        for rd_attack, proto_attack in zip(matches.meta.attack, m.attack):
            assert list(rd_attack.parts) == proto_attack.parts
            assert rd_attack.tactic == proto_attack.tactic
            assert rd_attack.technique == proto_attack.technique
            assert rd_attack.subtechnique == proto_attack.subtechnique

        assert len(matches.meta.mbc) == len(m.mbc)
        for rd_mbc, proto_mbc in zip(matches.meta.mbc, m.mbc):
            assert list(rd_mbc.parts) == proto_mbc.parts
            assert rd_mbc.objective == proto_mbc.objective
            assert rd_mbc.behavior == proto_mbc.behavior
            assert rd_mbc.method == proto_mbc.method
            assert rd_mbc.id == proto_mbc.id

        assert list(matches.meta.references) == m.references
        assert list(matches.meta.examples) == m.examples
        assert matches.meta.description == m.description
        assert matches.meta.lib == m.lib
        assert matches.meta.is_subscope_rule == m.is_subscope_rule

        assert cmp_optional(matches.meta.maec.analysis_conclusion, m.maec.analysis_conclusion)
        assert cmp_optional(matches.meta.maec.analysis_conclusion_ov, m.maec.analysis_conclusion_ov)
        assert cmp_optional(matches.meta.maec.malware_family, m.maec.malware_family)
        assert cmp_optional(matches.meta.maec.malware_category, m.maec.malware_category)
        assert cmp_optional(matches.meta.maec.malware_category_ov, m.maec.malware_category_ov)

        assert matches.source == dst.rules[rule_name].source

        assert len(matches.matches) == len(dst.rules[rule_name].matches)
        for (addr, match), proto_match in zip(matches.matches, dst.rules[rule_name].matches):
            assert capa.render.proto.addr_to_pb2(addr) == proto_match.address
            assert_match(match, proto_match.match)


def test_addr_to_pb2():
    a1 = capa.features.freeze.Address.from_capa(capa.features.address.AbsoluteVirtualAddress(0x400000))
    a = capa.render.proto.addr_to_pb2(a1)
    assert a.type == capa_pb2.ADDRESSTYPE_ABSOLUTE
    assert a.v.u == 0x400000

    a2 = capa.features.freeze.Address.from_capa(capa.features.address.RelativeVirtualAddress(0x100))
    a = capa.render.proto.addr_to_pb2(a2)
    assert a.type == capa_pb2.ADDRESSTYPE_RELATIVE
    assert a.v.u == 0x100

    a3 = capa.features.freeze.Address.from_capa(capa.features.address.FileOffsetAddress(0x200))
    a = capa.render.proto.addr_to_pb2(a3)
    assert a.type == capa_pb2.ADDRESSTYPE_FILE
    assert a.v.u == 0x200

    a4 = capa.features.freeze.Address.from_capa(capa.features.address.DNTokenAddress(0x123456))
    a = capa.render.proto.addr_to_pb2(a4)
    assert a.type == capa_pb2.ADDRESSTYPE_DN_TOKEN
    assert a.v.u == 0x123456

    a5 = capa.features.freeze.Address.from_capa(capa.features.address.DNTokenOffsetAddress(0x123456, 0x10))
    a = capa.render.proto.addr_to_pb2(a5)
    assert a.type == capa_pb2.ADDRESSTYPE_DN_TOKEN_OFFSET
    assert a.token_offset.token.u == 0x123456
    assert a.token_offset.offset == 0x10

    a6 = capa.features.freeze.Address.from_capa(capa.features.address._NoAddress())
    a = capa.render.proto.addr_to_pb2(a6)
    assert a.type == capa_pb2.ADDRESSTYPE_NO_ADDRESS


def test_scope_to_pb2():
    assert capa.render.proto.scope_to_pb2(capa.rules.Scope.FILE) == capa_pb2.SCOPE_FILE
    assert capa.render.proto.scope_to_pb2(capa.rules.Scope.FUNCTION) == capa_pb2.SCOPE_FUNCTION
    assert capa.render.proto.scope_to_pb2(capa.rules.Scope.BASIC_BLOCK) == capa_pb2.SCOPE_BASIC_BLOCK
    assert capa.render.proto.scope_to_pb2(capa.rules.Scope.INSTRUCTION) == capa_pb2.SCOPE_INSTRUCTION
    assert capa.render.proto.scope_to_pb2(capa.rules.Scope.PROCESS) == capa_pb2.SCOPE_PROCESS
    assert capa.render.proto.scope_to_pb2(capa.rules.Scope.THREAD) == capa_pb2.SCOPE_THREAD
    assert capa.render.proto.scope_to_pb2(capa.rules.Scope.CALL) == capa_pb2.SCOPE_CALL


def test_scopes_to_pb2():
    assert capa.render.proto.scopes_to_pb2(
        capa.rules.Scopes.from_dict({"static": "file", "dynamic": "file"})
    ) == capa_pb2.Scopes(
        static=capa_pb2.SCOPE_FILE,
        dynamic=capa_pb2.SCOPE_FILE,
    )
    assert capa.render.proto.scopes_to_pb2(
        capa.rules.Scopes.from_dict({"static": "file", "dynamic": "unsupported"})
    ) == capa_pb2.Scopes(
        static=capa_pb2.SCOPE_FILE,
    )


def cmp_optional(a: Any, b: Any) -> bool:
    # proto optional value gets deserialized to "" instead of None (used by pydantic)
    a = a if a is not None else ""
    return a == b


def assert_static_analyis(analysis: rd.StaticAnalysis, dst: capa_pb2.StaticAnalysis):
    assert analysis.format == dst.format
    assert analysis.arch == dst.arch
    assert analysis.os == dst.os
    assert analysis.extractor == dst.extractor
    assert list(analysis.rules) == dst.rules

    assert capa.render.proto.addr_to_pb2(analysis.base_address) == dst.base_address

    assert len(analysis.layout.functions) == len(dst.layout.functions)
    for rd_f, proto_f in zip(analysis.layout.functions, dst.layout.functions):
        assert capa.render.proto.addr_to_pb2(rd_f.address) == proto_f.address

        assert len(rd_f.matched_basic_blocks) == len(proto_f.matched_basic_blocks)
        for rd_bb, proto_bb in zip(rd_f.matched_basic_blocks, proto_f.matched_basic_blocks):
            assert capa.render.proto.addr_to_pb2(rd_bb.address) == proto_bb.address

    assert analysis.feature_counts.file == dst.feature_counts.file
    assert len(analysis.feature_counts.functions) == len(dst.feature_counts.functions)
    for rd_cf, proto_cf in zip(analysis.feature_counts.functions, dst.feature_counts.functions):
        assert capa.render.proto.addr_to_pb2(rd_cf.address) == proto_cf.address
        assert rd_cf.count == proto_cf.count

    assert len(analysis.library_functions) == len(dst.library_functions)
    for rd_lf, proto_lf in zip(analysis.library_functions, dst.library_functions):
        assert capa.render.proto.addr_to_pb2(rd_lf.address) == proto_lf.address
        assert rd_lf.name == proto_lf.name


def assert_dynamic_analyis(analysis: rd.DynamicAnalysis, dst: capa_pb2.DynamicAnalysis):
    assert analysis.format == dst.format
    assert analysis.arch == dst.arch
    assert analysis.os == dst.os
    assert analysis.extractor == dst.extractor
    assert list(analysis.rules) == dst.rules

    assert len(analysis.layout.processes) == len(dst.layout.processes)
    for rd_p, proto_p in zip(analysis.layout.processes, dst.layout.processes):
        assert capa.render.proto.addr_to_pb2(rd_p.address) == proto_p.address

        assert len(rd_p.matched_threads) == len(proto_p.matched_threads)
        for rd_t, proto_t in zip(rd_p.matched_threads, proto_p.matched_threads):
            assert capa.render.proto.addr_to_pb2(rd_t.address) == proto_t.address

    assert analysis.feature_counts.processes == dst.feature_counts.processes
    assert len(analysis.feature_counts.processes) == len(dst.feature_counts.processes)
    for rd_cp, proto_cp in zip(analysis.feature_counts.processes, dst.feature_counts.processes):
        assert capa.render.proto.addr_to_pb2(rd_cp.address) == proto_cp.address
        assert rd_cp.count == proto_cp.count


def assert_meta(meta: rd.Metadata, dst: capa_pb2.Metadata):
    assert isinstance(meta.analysis, rd.StaticAnalysis)
    assert str(meta.timestamp) == dst.timestamp
    assert meta.version == dst.version
    if meta.argv is None:
        assert [] == dst.argv
    else:
        assert list(meta.argv) == dst.argv

    assert meta.sample.md5 == dst.sample.md5
    assert meta.sample.sha1 == dst.sample.sha1
    assert meta.sample.sha256 == dst.sample.sha256
    assert meta.sample.path == dst.sample.path

    if meta.flavor == rd.Flavor.STATIC:
        assert dst.flavor == capa_pb2.FLAVOR_STATIC
        assert dst.WhichOneof("analysis2") == "static_analysis"
        assert isinstance(meta.analysis, rd.StaticAnalysis)
        assert_static_analyis(meta.analysis, dst.static_analysis)
    elif meta.flavor == rd.Flavor.DYNAMIC:
        assert dst.flavor == capa_pb2.FLAVOR_DYNAMIC
        assert dst.WhichOneof("analysis2") == "dynamic_analysis"
        assert isinstance(meta.analysis, rd.DynamicAnalysis)
        assert_dynamic_analyis(meta.analysis, dst.dynamic_analysis)
    else:
        assert_never(dst.flavor)


def assert_match(ma: rd.Match, mb: capa_pb2.Match):
    assert ma.success == mb.success

    # node
    if isinstance(ma.node, rd.StatementNode):
        assert_statement(ma.node, mb.statement)

    elif isinstance(ma.node, rd.FeatureNode):
        assert ma.node.type == mb.feature.type
        assert_feature(ma.node.feature, mb.feature)

    # children
    assert len(ma.children) == len(mb.children)
    for ca, cb in zip(ma.children, mb.children):
        assert_match(ca, cb)

    # locations
    assert list(map(capa.render.proto.addr_to_pb2, ma.locations)) == mb.locations

    # captures
    assert len(ma.captures) == len(mb.captures)
    for capture, locs in ma.captures.items():
        assert capture in mb.captures
        assert list(map(capa.render.proto.addr_to_pb2, locs)) == mb.captures[capture].address


def assert_feature(fa, fb):
    # get field that has been set, e.g., os or api, to access inner fields
    fb = getattr(fb, fb.WhichOneof("feature"))

    assert fa.type == fb.type
    assert cmp_optional(fa.description, fb.description)

    if isinstance(fa, capa.features.freeze.features.OSFeature):
        assert fa.os == fb.os

    elif isinstance(fa, capa.features.freeze.features.ArchFeature):
        assert fa.arch == fb.arch

    elif isinstance(fa, capa.features.freeze.features.FormatFeature):
        assert fa.format == fb.format

    elif isinstance(fa, capa.features.freeze.features.MatchFeature):
        assert fa.match == fb.match

    elif isinstance(fa, capa.features.freeze.features.CharacteristicFeature):
        assert fa.characteristic == fb.characteristic

    elif isinstance(fa, capa.features.freeze.features.ExportFeature):
        assert fa.export == fb.export

    elif isinstance(fa, capa.features.freeze.features.ImportFeature):
        assert fa.import_ == fb.import_  # or could use getattr

    elif isinstance(fa, capa.features.freeze.features.SectionFeature):
        assert fa.section == fb.section

    elif isinstance(fa, capa.features.freeze.features.FunctionNameFeature):
        assert fa.function_name == fb.function_name

    elif isinstance(fa, capa.features.freeze.features.SubstringFeature):
        assert fa.substring == fb.substring

    elif isinstance(fa, capa.features.freeze.features.RegexFeature):
        assert fa.regex == fb.regex

    elif isinstance(fa, capa.features.freeze.features.StringFeature):
        assert fa.string == fb.string

    elif isinstance(fa, capa.features.freeze.features.ClassFeature):
        assert fa.class_ == fb.class_

    elif isinstance(fa, capa.features.freeze.features.NamespaceFeature):
        assert fa.namespace == fb.namespace

    elif isinstance(fa, capa.features.freeze.features.BasicBlockFeature):
        pass

    elif isinstance(fa, capa.features.freeze.features.APIFeature):
        assert fa.api == fb.api

    elif isinstance(fa, capa.features.freeze.features.PropertyFeature):
        assert fa.property == fb.property_
        assert fa.access == fb.access

    elif isinstance(fa, capa.features.freeze.features.NumberFeature):
        # get number value of set field
        n = getattr(fb.number, fb.number.WhichOneof("value"))
        assert fa.number == n

    elif isinstance(fa, capa.features.freeze.features.BytesFeature):
        assert fa.bytes == fb.bytes

    elif isinstance(fa, capa.features.freeze.features.OffsetFeature):
        assert fa.offset == getattr(fb.offset, fb.offset.WhichOneof("value"))

    elif isinstance(fa, capa.features.freeze.features.MnemonicFeature):
        assert fa.mnemonic == fb.mnemonic

    elif isinstance(fa, capa.features.freeze.features.OperandNumberFeature):
        assert fa.index == fb.index
        assert fa.operand_number == getattr(fb.operand_number, fb.operand_number.WhichOneof("value"))

    elif isinstance(fa, capa.features.freeze.features.OperandOffsetFeature):
        assert fa.index == fb.index
        assert fa.operand_offset == getattr(fb.operand_offset, fb.operand_offset.WhichOneof("value"))

    else:
        raise NotImplementedError(f"unhandled feature: {type(fa)}: {fa}")


def assert_statement(a: rd.StatementNode, b: capa_pb2.StatementNode):
    assert a.type == b.type

    sa = a.statement
    sb = getattr(b, str(b.WhichOneof("statement")))

    assert sa.type == sb.type
    assert cmp_optional(sa.description, sb.description)

    if isinstance(sa, rd.RangeStatement):
        assert isinstance(sb, capa_pb2.RangeStatement)
        assert sa.min == sb.min
        assert sa.max == sa.max
        assert_feature(sa.child, sb.child)

    elif isinstance(sa, rd.SomeStatement):
        assert sa.count == sb.count

    elif isinstance(sa, rd.SubscopeStatement):
        assert capa.render.proto.scope_to_pb2(sa.scope) == sb.scope

    elif isinstance(sa, rd.CompoundStatement):
        # only has type and description tested above
        pass

    else:
        # unhandled statement
        assert_never(sa)


def assert_round_trip(doc: rd.ResultDocument):
    one = doc

    pb = capa.render.proto.doc_to_pb2(one)
    two = capa.render.proto.doc_from_pb2(pb)

    # show the round trip works
    # first by comparing the objects directly,
    # which works thanks to pydantic model equality.
    assert one.meta == two.meta
    assert one.rules == two.rules
    assert one == two

    # second by showing their protobuf representations are the same.
    one_bytes = capa.render.proto.doc_to_pb2(one).SerializeToString(deterministic=True)
    two_bytes = capa.render.proto.doc_to_pb2(two).SerializeToString(deterministic=True)
    assert one_bytes == two_bytes

    # now show that two different versions are not equal.
    three = copy.deepcopy(two)
    three.meta.__dict__.update({"version": "0.0.0"})
    assert one.meta.version != three.meta.version
    assert one != three
    three_bytes = capa.render.proto.doc_to_pb2(three).SerializeToString(deterministic=True)
    assert one_bytes != three_bytes


@pytest.mark.parametrize(
    "rd_file",
    [
        pytest.param("a3f3bbc_rd"),
        pytest.param("al_khaserx86_rd"),
        pytest.param("al_khaserx64_rd"),
        pytest.param("a076114_rd"),
        pytest.param("pma0101_rd"),
        pytest.param("dotnet_1c444e_rd"),
        pytest.param("dynamic_a0000a6_rd"),
    ],
)
def test_round_trip(request, rd_file):
    doc: rd.ResultDocument = request.getfixturevalue(rd_file)
    assert_round_trip(doc)
