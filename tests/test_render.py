# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import io
import textwrap
from unittest.mock import Mock

import fixtures
import rich.console

import capa.rules
import capa.render.utils
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.freeze
import capa.render.vverbose
import capa.features.address
import capa.features.basicblock
import capa.render.result_document
import capa.render.result_document as rd
import capa.features.freeze.features


def test_render_number():
    assert str(capa.features.insn.Number(1)) == "number(0x1)"


def test_render_offset():
    assert str(capa.features.insn.Offset(1)) == "offset(0x1)"


def test_render_property():
    assert (
        str(capa.features.insn.Property("System.IO.FileInfo::Length", access=capa.features.common.FeatureAccess.READ))
        == "property/read(System.IO.FileInfo::Length)"
    )


def test_render_meta_attack():
    # Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]
    id = "T1543.003"
    tactic = "Persistence"
    technique = "Create or Modify System Process"
    subtechnique = "Windows Service"
    canonical = "{:s}::{:s}::{:s} [{:s}]".format(tactic, technique, subtechnique, id)

    rule = textwrap.dedent(
        """
        rule:
          meta:
            name: test rule
            scopes:
                static: function
                dynamic: process
            authors:
              - foo
            att&ck:
              - {:s}
          features:
            - number: 1
        """.format(
            canonical
        )
    )
    r = capa.rules.Rule.from_yaml(rule)
    rule_meta = capa.render.result_document.RuleMetadata.from_capa(r)
    attack = rule_meta.attack[0]

    assert attack.id == id
    assert attack.tactic == tactic
    assert attack.technique == technique
    assert attack.subtechnique == subtechnique

    assert capa.render.utils.format_parts_id(attack) == canonical


def test_render_meta_mbc():
    # Defense Evasion::Disable or Evade Security Tools::Heavens Gate [F0004.008]
    id = "F0004.008"
    objective = "Defense Evasion"
    behavior = "Disable or Evade Security Tools"
    method = "Heavens Gate"
    canonical = "{:s}::{:s}::{:s} [{:s}]".format(objective, behavior, method, id)

    rule = textwrap.dedent(
        """
        rule:
          meta:
            name: test rule
            scopes:
                static: function
                dynamic: process
            authors:
              - foo
            mbc:
              - {:s}
          features:
            - number: 1
        """.format(
            canonical
        )
    )
    r = capa.rules.Rule.from_yaml(rule)
    rule_meta = capa.render.result_document.RuleMetadata.from_capa(r)
    mbc = rule_meta.mbc[0]

    assert mbc.id == id
    assert mbc.objective == objective
    assert mbc.behavior == behavior
    assert mbc.method == method

    assert capa.render.utils.format_parts_id(mbc) == canonical


def test_render_meta_maec():
    malware_family = "PlugX"
    malware_category = "downloader"
    analysis_conclusion = "malicious"

    rule_yaml = textwrap.dedent(
        """
        rule:
          meta:
            name: test rule
            scopes:
              static: function
              dynamic: process
            authors:
              - foo
            maec/malware-family: {:s}
            maec/malware-category: {:s}
            maec/analysis-conclusion: {:s}
          features:
            - number: 1
        """.format(
            malware_family, malware_category, analysis_conclusion
        )
    )
    rule = capa.rules.Rule.from_yaml(rule_yaml)
    rm = capa.render.result_document.RuleMatches(
        meta=capa.render.result_document.RuleMetadata.from_capa(rule),
        source=rule_yaml,
        matches=(),
    )

    # create a mock ResultDocument
    mock_rd = Mock(spec=rd.ResultDocument)
    mock_rd.rules = {"test rule": rm}

    # capture the output of render_maec
    f = io.StringIO()
    console = rich.console.Console(file=f)
    capa.render.default.render_maec(mock_rd, console)
    output = f.getvalue()

    assert "analysis-conclusion" in output
    assert analysis_conclusion in output
    assert "malware-category" in output
    assert malware_category in output
    assert "malware-family" in output
    assert malware_family in output


@fixtures.parametrize(
    "feature,expected",
    [
        (capa.features.common.OS("windows"), "os: windows"),
        (capa.features.common.Arch("i386"), "arch: i386"),
        (capa.features.common.Format("pe"), "format: pe"),
        (capa.features.common.MatchedRule("foo"), "match: foo @ 0x401000"),
        (capa.features.common.Characteristic("foo"), "characteristic: foo @ 0x401000"),
        (capa.features.file.Export("SvcMain"), "export: SvcMain @ 0x401000"),
        (capa.features.file.Import("CreateFileW"), "import: CreateFileW @ 0x401000"),
        (capa.features.file.Section(".detours"), "section: .detours @ 0x401000"),
        (capa.features.file.FunctionName("memcmp"), "function name: memcmp @ 0x401000"),
        (capa.features.common.Substring("foo"), "substring: foo"),
        (capa.features.common.Regex("^foo"), "regex: ^foo"),
        (capa.features.common.String("foo"), 'string: "foo" @ 0x401000'),
        (capa.features.common.Class("BeanFactory"), "class: BeanFactory @ 0x401000"),
        (capa.features.common.Namespace("std::enterprise"), "namespace: std::enterprise @ 0x401000"),
        (capa.features.insn.API("CreateFileW"), "api: CreateFileW @ 0x401000"),
        (capa.features.insn.Property("foo"), "property: foo @ 0x401000"),
        (capa.features.insn.Property("foo", "read"), "property/read: foo @ 0x401000"),
        (capa.features.insn.Property("foo", "write"), "property/write: foo @ 0x401000"),
        (capa.features.insn.Number(12), "number: 0xC @ 0x401000"),
        (capa.features.common.Bytes(b"AAAA"), "bytes: 41414141 @ 0x401000"),
        (capa.features.insn.Offset(12), "offset: 0xC @ 0x401000"),
        (capa.features.insn.Mnemonic("call"), "mnemonic: call @ 0x401000"),
        (capa.features.insn.OperandNumber(0, 12), "operand[0].number: 0xC @ 0x401000"),
        (capa.features.insn.OperandOffset(0, 12), "operand[0].offset: 0xC @ 0x401000"),
        # unsupported
        # (capa.features.basicblock.BasicBlock(), "basic block @ 0x401000"),
    ],
)
def test_render_vverbose_feature(feature, expected):
    ostream = capa.render.utils.StringIO()

    addr = capa.features.freeze.Address.from_capa(capa.features.address.AbsoluteVirtualAddress(0x401000))
    feature = capa.features.freeze.features.feature_from_capa(feature)

    matches = capa.render.result_document.Match(
        success=True,
        node=capa.render.result_document.FeatureNode(feature=feature),
        children=(),
        locations=(addr,),
        captures={},
    )

    layout = capa.render.result_document.StaticLayout(functions=())

    src = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                authors:
                    - user@domain.com
                scopes:
                    static: function
                    dynamic: process
                examples:
                    - foo1234
                    - bar5678
            features:
                - and:
                    - number: 1
                    - number: 2
        """
    )
    rule = capa.rules.Rule.from_yaml(src)

    rm = capa.render.result_document.RuleMatches(
        meta=capa.render.result_document.RuleMetadata.from_capa(rule),
        source=src,
        matches=(),
    )

    capa.render.vverbose.render_feature(ostream, layout, rm, matches, feature, indent=0)

    assert ostream.getvalue().strip() == expected
