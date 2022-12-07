import textwrap

import fixtures

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
            scope: function
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
            scope: function
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

    capa.render.vverbose.render_feature(ostream, matches, feature, indent=0)

    assert ostream.getvalue().strip() == expected
