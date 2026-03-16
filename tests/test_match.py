# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import textwrap

import pytest

import capa.rules
import capa.engine
import capa.features.insn
import capa.features.common
from capa.rules import Scope
from capa.features.common import (
    OS,
    OS_ANY,
    OS_LINUX,
    FORMAT_PE,
    ARCH_AMD64,
    OS_WINDOWS,
    Arch,
    Format,
    String,
    MatchedRule,
)
from capa.features.address import NO_ADDRESS


def match(rules, features, va, scope=Scope.FUNCTION):
    """
    use all matching algorithms and verify that they compute the same result.
    then, return those results to the caller so they can make their asserts.
    """
    features1, matches1 = capa.engine.match(rules, features, va)

    ruleset = capa.rules.RuleSet(rules)
    features2, matches2 = ruleset.match(scope, features, va)

    for feature, locations in features1.items():
        assert feature in features2
        assert locations == features2[feature]

    for rulename, results in matches1.items():
        assert rulename in matches2
        assert len(results) == len(matches2[rulename])

    return features1, matches1


def test_match_simple():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
                namespace: testns1/testns2
            features:
                - number: 100
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    features, matches = match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" in matches
    assert MatchedRule("test rule") in features
    assert MatchedRule("testns1") in features
    assert MatchedRule("testns1/testns2") in features


def test_match_range_exact():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - count(number(100)): 2
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # just enough matches
    _, matches = match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" in matches

    # not enough matches
    _, matches = match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert "test rule" not in matches

    # too many matches
    _, matches = match([r], {capa.features.insn.Number(100): {1, 2, 3}}, 0x0)
    assert "test rule" not in matches


def test_match_range_range():
    rule = textwrap.dedent(
        """
         rule:
             meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
             features:
                 - count(number(100)): (2, 3)
         """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # just enough matches
    _, matches = match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" in matches

    # enough matches
    _, matches = match([r], {capa.features.insn.Number(100): {1, 2, 3}}, 0x0)
    assert "test rule" in matches

    # not enough matches
    _, matches = match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert "test rule" not in matches

    # too many matches
    _, matches = match([r], {capa.features.insn.Number(100): {1, 2, 3, 4}}, 0x0)
    assert "test rule" not in matches


def test_match_range_exact_zero():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - count(number(100)): 0

                    # we can't have `count(foo): 0` at the top level,
                    # since we don't support top level NOT statements.
                    # so we have this additional trivial feature.
                    - mnemonic: mov

        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # feature isn't indexed - good.
    _, matches = match([r], {capa.features.insn.Mnemonic("mov"): {}}, 0x0)
    assert "test rule" in matches

    # feature is indexed, but no matches.
    # i don't think we should ever really have this case, but good to check anyways.
    _, matches = match([r], {capa.features.insn.Number(100): {}, capa.features.insn.Mnemonic("mov"): {}}, 0x0)
    assert "test rule" in matches

    # too many matches
    _, matches = match([r], {capa.features.insn.Number(100): {1}, capa.features.insn.Mnemonic("mov"): {1}}, 0x0)
    assert "test rule" not in matches


def test_match_range_with_zero():
    rule = textwrap.dedent(
        """
         rule:
             meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
             features:
                - and:
                    - count(number(100)): (0, 1)

                    # we can't have `count(foo): 0` at the top level,
                    # since we don't support top level NOT statements.
                    # so we have this additional trivial feature.
                    - mnemonic: mov
         """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # ok
    _, matches = match([r], {capa.features.insn.Mnemonic("mov"): {}}, 0x0)
    assert "test rule" in matches
    _, matches = match([r], {capa.features.insn.Number(100): {}, capa.features.insn.Mnemonic("mov"): {}}, 0x0)
    assert "test rule" in matches
    _, matches = match([r], {capa.features.insn.Number(100): {1}, capa.features.insn.Mnemonic("mov"): {1}}, 0x0)
    assert "test rule" in matches

    # too many matches
    _, matches = match([r], {capa.features.insn.Number(100): {1, 2}, capa.features.insn.Mnemonic("mov"): {1, 2}}, 0x0)
    assert "test rule" not in matches


def test_match_adds_matched_rule_feature():
    """show that using `match` adds a feature for matched rules."""
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - number: 100
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    features, _ = match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert capa.features.common.MatchedRule("test rule") in features


def test_match_matched_rules():
    """show that using `match` adds a feature for matched rules."""
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule1
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - number: 100
                """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule2
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - match: test rule1
                """
            )
        ),
    ]

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.insn.Number(100): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule1") in features
    assert capa.features.common.MatchedRule("test rule2") in features

    # the ordering of the rules must not matter,
    # the engine should match rules in an appropriate order.
    features, _ = match(
        capa.rules.topologically_order_rules(list(reversed(rules))),
        {capa.features.insn.Number(100): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule1") in features
    assert capa.features.common.MatchedRule("test rule2") in features


def test_match_namespace():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: CreateFile API
                        scopes:
                            static: function
                            dynamic: process
                        namespace: file/create/CreateFile
                    features:
                        - api: CreateFile
                """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: WriteFile API
                        scopes:
                            static: function
                            dynamic: process
                        namespace: file/write
                    features:
                        - api: WriteFile
                """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: file-create
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - match: file/create
                """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: filesystem-any
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - match: file
                """
            )
        ),
    ]

    features, matches = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.insn.API("CreateFile"): {1}},
        0x0,
    )
    assert "CreateFile API" in matches
    assert "file-create" in matches
    assert "filesystem-any" in matches
    assert capa.features.common.MatchedRule("file") in features
    assert capa.features.common.MatchedRule("file/create") in features
    assert capa.features.common.MatchedRule("file/create/CreateFile") in features

    features, matches = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.insn.API("WriteFile"): {1}},
        0x0,
    )
    assert "WriteFile API" in matches
    assert "file-create" not in matches
    assert "filesystem-any" in matches


def test_match_substring():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - and:
                            - substring: abc
                """
            )
        ),
    ]
    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("aaaa"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") not in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("abc"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("111abc222"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("111abc"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("abc222"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features


def test_match_regex():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - and:
                            - string: /.*bbbb.*/
                """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: rule with implied wildcards
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - and:
                            - string: /bbbb/
                """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: rule with anchor
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - and:
                            - string: /^bbbb/
                """
            )
        ),
    ]
    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.insn.Number(100): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") not in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("aaaa"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") not in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("aBBBBa"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") not in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("abbbba"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features
    assert capa.features.common.MatchedRule("rule with implied wildcards") in features
    assert capa.features.common.MatchedRule("rule with anchor") not in features


def test_match_regex_ignorecase():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - and:
                            - string: /.*bbbb.*/i
                """
            )
        ),
    ]
    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("aBBBBa"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features


def test_match_regex_complex():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                r"""
                rule:
                    meta:
                        name: test rule
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - or:
                            - string: /.*HARDWARE\\Key\\key with spaces\\.*/i
                """
            )
        ),
    ]
    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String(r"Hardware\Key\key with spaces\some value"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features


def test_match_regex_values_always_string():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        scopes:
                            static: function
                            dynamic: process
                    features:
                        - or:
                            - string: /123/
                            - string: /0x123/
                """
            )
        ),
    ]
    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("123"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features

    features, _ = match(
        capa.rules.topologically_order_rules(rules),
        {capa.features.common.String("0x123"): {1}},
        0x0,
    )
    assert capa.features.common.MatchedRule("test rule") in features


@pytest.mark.xfail(reason="can't have top level NOT")
def test_match_only_not():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
                namespace: testns1/testns2
            features:
                - not:
                    - number: 99
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    _, matches = match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" in matches


def test_match_not():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
                namespace: testns1/testns2
            features:
                - and:
                    - mnemonic: mov
                    - not:
                        - number: 99
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    _, matches = match([r], {capa.features.insn.Number(100): {1, 2}, capa.features.insn.Mnemonic("mov"): {1, 2}}, 0x0)
    assert "test rule" in matches


@pytest.mark.xfail(reason="can't have nested NOT")
def test_match_not_not():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
                namespace: testns1/testns2
            features:
                - not:
                    - not:
                        - number: 100
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    _, matches = match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" in matches


def test_match_operand_number():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - operand[0].number: 0x10
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    assert capa.features.insn.OperandNumber(0, 0x10) in {capa.features.insn.OperandNumber(0, 0x10)}

    _, matches = match([r], {capa.features.insn.OperandNumber(0, 0x10): {1, 2}}, 0x0)
    assert "test rule" in matches

    # mismatching index
    _, matches = match([r], {capa.features.insn.OperandNumber(1, 0x10): {1, 2}}, 0x0)
    assert "test rule" not in matches

    # mismatching value
    _, matches = match([r], {capa.features.insn.OperandNumber(0, 0x11): {1, 2}}, 0x0)
    assert "test rule" not in matches


def test_match_operand_offset():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - operand[0].offset: 0x10
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    assert capa.features.insn.OperandOffset(0, 0x10) in {capa.features.insn.OperandOffset(0, 0x10)}

    _, matches = match([r], {capa.features.insn.OperandOffset(0, 0x10): {1, 2}}, 0x0)
    assert "test rule" in matches

    # mismatching index
    _, matches = match([r], {capa.features.insn.OperandOffset(1, 0x10): {1, 2}}, 0x0)
    assert "test rule" not in matches

    # mismatching value
    _, matches = match([r], {capa.features.insn.OperandOffset(0, 0x11): {1, 2}}, 0x0)
    assert "test rule" not in matches


def test_match_property_access():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - property/read: System.IO.FileInfo::Length
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    assert capa.features.insn.Property("System.IO.FileInfo::Length", capa.features.common.FeatureAccess.READ) in {
        capa.features.insn.Property("System.IO.FileInfo::Length", capa.features.common.FeatureAccess.READ)
    }

    _, matches = match(
        [r],
        {capa.features.insn.Property("System.IO.FileInfo::Length", capa.features.common.FeatureAccess.READ): {1, 2}},
        0x0,
    )
    assert "test rule" in matches

    # mismatching access
    _, matches = match(
        [r],
        {capa.features.insn.Property("System.IO.FileInfo::Length", capa.features.common.FeatureAccess.WRITE): {1, 2}},
        0x0,
    )
    assert "test rule" not in matches

    # mismatching value
    _, matches = match(
        [r],
        {capa.features.insn.Property("System.IO.FileInfo::Size", capa.features.common.FeatureAccess.READ): {1, 2}},
        0x0,
    )
    assert "test rule" not in matches


def test_match_os_any():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - or:
                    - and:
                        - or:
                            - os: windows
                            - os: linux
                            - os: macos
                        - string: "Hello world"
                    - and:
                        - os: any
                        - string: "Goodbye world"
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    _, matches = match(
        [r],
        {OS(OS_ANY): {1}, String("Hello world"): {1}},
        0x0,
    )
    assert "test rule" in matches

    _, matches = match(
        [r],
        {OS(OS_WINDOWS): {1}, String("Hello world"): {1}},
        0x0,
    )
    assert "test rule" in matches

    _, matches = match(
        [r],
        {OS(OS_ANY): {1}, String("Goodbye world"): {1}},
        0x0,
    )
    assert "test rule" in matches

    _, matches = match(
        [r],
        {OS(OS_WINDOWS): {1}, String("Goodbye world"): {1}},
        0x0,
    )
    assert "test rule" in matches


# this test demonstrates the behavior of unstable features that may change before the next major release.
def test_index_features_and_unstable():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - mnemonic: mov
                    - api: CreateFileW
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    rr = capa.rules.RuleSet([r])
    index: capa.rules.RuleSet._RuleFeatureIndex = rr._feature_indexes_by_scopes[capa.rules.Scope.FUNCTION]

    # there's a single rule, and its indexed by a single feature
    assert len(index.rules_by_feature) == 1
    # and we index by the more uncommon API feature, not the common mnemonic feature
    assert capa.features.insn.API("CreateFileW") in index.rules_by_feature

    assert not index.string_rules
    assert not index.bytes_rules


# this test demonstrates the behavior of unstable features that may change before the next major release.
def test_index_features_or_unstable():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - or:
                    - mnemonic: mov
                    - api: CreateFileW
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    rr = capa.rules.RuleSet([r])
    index: capa.rules.RuleSet._RuleFeatureIndex = rr._feature_indexes_by_scopes[capa.rules.Scope.FUNCTION]

    # there's a single rule, and its indexed by both features,
    # because they fall under the single root OR node.
    assert len(index.rules_by_feature) == 2
    assert capa.features.insn.API("CreateFileW") in index.rules_by_feature
    assert capa.features.insn.Mnemonic("mov") in index.rules_by_feature

    assert not index.string_rules
    assert not index.bytes_rules


# this test demonstrates the behavior of unstable features that may change before the next major release.
def test_index_features_nested_unstable():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - mnemonic: mov
                    - or:
                        - api: CreateFileW
                        - string: foo
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    rr = capa.rules.RuleSet([r])
    index: capa.rules.RuleSet._RuleFeatureIndex = rr._feature_indexes_by_scopes[capa.rules.Scope.FUNCTION]

    # there's a single rule, and its indexed by the two uncommon features,
    # not the single common feature.
    assert len(index.rules_by_feature) == 2
    assert capa.features.insn.API("CreateFileW") in index.rules_by_feature
    assert capa.features.common.String("foo") in index.rules_by_feature
    assert capa.features.insn.Mnemonic("mov") not in index.rules_by_feature

    assert not index.string_rules
    assert not index.bytes_rules


def test_filter_rules_by_meta_features_prunes_incompatible_os():
    """Rules requiring a different OS than the binary's are removed from the RuleSet."""
    windows_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: windows only rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - os: windows
                    - api: CreateFile
        """
    )
    linux_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: linux only rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - os: linux
                    - api: open
        """
    )
    rr = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(windows_rule),
            capa.rules.Rule.from_yaml(linux_rule),
        ]
    )
    assert len(rr.rules) == 2

    # When analyzing a Linux binary, windows-only rules are pruned
    linux_features: capa.engine.FeatureSet = {OS(OS_LINUX): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(linux_features)
    assert "linux only rule" in filtered.rules
    assert "windows only rule" not in filtered.rules

    # When analyzing a Windows binary, linux-only rules are pruned
    windows_features: capa.engine.FeatureSet = {OS(OS_WINDOWS): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(windows_features)
    assert "windows only rule" in filtered.rules
    assert "linux only rule" not in filtered.rules


def test_filter_rules_by_meta_features_keeps_any_os():
    """Rules with os: any or no OS requirement are kept regardless of binary OS."""
    any_os_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: any os rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - os: any
                    - api: malloc
        """
    )
    no_os_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: no os rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - api: calloc
        """
    )
    rr = capa.rules.RuleSet([capa.rules.Rule.from_yaml(any_os_rule), capa.rules.Rule.from_yaml(no_os_rule)])

    windows_features: capa.engine.FeatureSet = {OS(OS_WINDOWS): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(windows_features)
    assert "any os rule" in filtered.rules
    assert "no os rule" in filtered.rules

    linux_features: capa.engine.FeatureSet = {OS(OS_LINUX): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(linux_features)
    assert "any os rule" in filtered.rules
    assert "no os rule" in filtered.rules


def test_filter_rules_by_meta_features_prunes_unreachable_some_count():
    """Rules with an unsatisfiable Some-count over global features are pruned."""
    unreachable_some_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: unreachable some rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - 3 or more:
                    - os: windows
                    - os: linux
                    - api: CreateFile
        """
    )
    baseline_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: baseline rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - api: ReadFile
        """
    )
    rr = capa.rules.RuleSet(
        [capa.rules.Rule.from_yaml(unreachable_some_rule), capa.rules.Rule.from_yaml(baseline_rule)]
    )

    windows_features: capa.engine.FeatureSet = {OS(OS_WINDOWS): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(windows_features)
    assert "unreachable some rule" not in filtered.rules
    assert "baseline rule" in filtered.rules


def test_filter_rules_by_meta_features_keeps_reachable_some_count():
    """Rules with a satisfiable Some-count over global features are kept."""
    reachable_some_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: reachable some rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - 2 or more:
                    - os: windows
                    - os: linux
                    - api: CreateFile
        """
    )
    rr = capa.rules.RuleSet([capa.rules.Rule.from_yaml(reachable_some_rule)])

    windows_features: capa.engine.FeatureSet = {OS(OS_WINDOWS): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(windows_features)
    assert "reachable some rule" in filtered.rules


def test_filter_rules_by_meta_features_prunes_incompatible_arch_and_format():
    """Rules with incompatible arch/format are pruned while compatible rules are kept."""
    incompatible_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: incompatible arch format rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - arch: i386
                    - format: elf
                    - api: open
        """
    )
    compatible_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: compatible arch format rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - arch: amd64
                    - format: pe
                    - api: CreateFile
        """
    )
    rr = capa.rules.RuleSet([capa.rules.Rule.from_yaml(incompatible_rule), capa.rules.Rule.from_yaml(compatible_rule)])

    features: capa.engine.FeatureSet = {Arch(ARCH_AMD64): {NO_ADDRESS}, Format(FORMAT_PE): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(features)
    assert "incompatible arch format rule" not in filtered.rules
    assert "compatible arch format rule" in filtered.rules


def test_filter_rules_by_meta_features_keeps_dependencies_of_surviving_rules():
    """Dependencies of compatible rules are retained even if dependency globals are incompatible."""
    dependency_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: linux dependency rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - os: linux
                    - api: open
        """
    )
    parent_rule = textwrap.dedent(
        """
        rule:
            meta:
                name: windows parent rule
                scopes:
                    static: function
                    dynamic: process
            features:
                - and:
                    - os: windows
                    - or:
                        - api: CreateFile
                        - match: linux dependency rule
        """
    )
    rr = capa.rules.RuleSet([capa.rules.Rule.from_yaml(dependency_rule), capa.rules.Rule.from_yaml(parent_rule)])

    windows_features: capa.engine.FeatureSet = {OS(OS_WINDOWS): {NO_ADDRESS}}
    filtered = rr.filter_rules_by_meta_features(windows_features)
    assert "windows parent rule" in filtered.rules
    assert "linux dependency rule" in filtered.rules
