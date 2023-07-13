# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import textwrap

import pytest

import capa.rules
import capa.engine
import capa.features.common
import capa.features.address
from capa.engine import Or
from capa.features.file import FunctionName
from capa.features.insn import Number, Offset, Property
from capa.features.common import (
    OS,
    OS_LINUX,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    FORMAT_ELF,
    OS_WINDOWS,
    Arch,
    Format,
    String,
    Substring,
    FeatureAccess,
)

ADDR1 = capa.features.address.AbsoluteVirtualAddress(0x401001)
ADDR2 = capa.features.address.AbsoluteVirtualAddress(0x401002)
ADDR3 = capa.features.address.AbsoluteVirtualAddress(0x401003)
ADDR4 = capa.features.address.AbsoluteVirtualAddress(0x401004)


def test_rule_ctor():
    r = capa.rules.Rule("test rule", capa.rules.FUNCTION_SCOPE, Or([Number(1)]), {})
    assert bool(r.evaluate({Number(0): {ADDR1}})) is False
    assert bool(r.evaluate({Number(1): {ADDR2}})) is True


def test_rule_yaml():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                authors:
                    - user@domain.com
                scope: function
                examples:
                    - foo1234
                    - bar5678
            features:
                - and:
                    - number: 1
                    - number: 2
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({Number(0): {ADDR1}})) is False
    assert bool(r.evaluate({Number(0): {ADDR1}, Number(1): {ADDR1}})) is False
    assert bool(r.evaluate({Number(0): {ADDR1}, Number(1): {ADDR1}, Number(2): {ADDR1}})) is True
    assert bool(r.evaluate({Number(0): {ADDR1}, Number(1): {ADDR1}, Number(2): {ADDR1}, Number(3): {ADDR1}})) is True


def test_rule_yaml_complex():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - and:
                        - number: 1
                        - number: 2
                    - or:
                        - number: 3
                        - 2 or more:
                            - number: 4
                            - number: 5
                            - number: 6
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({Number(5): {ADDR1}, Number(6): {ADDR1}, Number(7): {ADDR1}, Number(8): {ADDR1}})) is True
    assert bool(r.evaluate({Number(6): {ADDR1}, Number(7): {ADDR1}, Number(8): {ADDR1}})) is False


def test_rule_descriptions():
    rule = textwrap.dedent(
        """
        rule:
          meta:
            name: test rule
          features:
            - and:
              - description: and description
              - number: 1 = number description
              - string: mystring
                description: string description
              - string: '/myregex/'
                description: regex description
              - mnemonic: inc = mnemonic description
              # TODO - count(number(2 = number description)): 2
              - or:
                - description: or description
                - and:
                  - offset: 0x50 = offset description
                  - offset: 0x34 = offset description
                  - description: and description
                - and:
                  - description: and description
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    def rec(statement):
        if isinstance(statement, capa.engine.Statement):
            assert statement.description == statement.name.lower() + " description"
            for child in statement.get_children():
                rec(child)
        else:
            if isinstance(statement.value, str):
                assert "description" not in statement.value
            assert statement.description == statement.name + " description"

    rec(r.statement)


def test_invalid_rule_statement_descriptions():
    # statements can only have one description
    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                  meta:
                    name: test rule
                  features:
                    - or:
                      - number: 1 = This is the number 1
                      - description: description
                      - description: another description (invalid)
                """
            )
        )


def test_rule_yaml_not():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - and:
                    - number: 1
                    - not:
                        - number: 2
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({Number(1): {ADDR1}})) is True
    assert bool(r.evaluate({Number(1): {ADDR1}, Number(2): {ADDR1}})) is False


def test_rule_yaml_count():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - count(number(100)): 1
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({Number(100): set()})) is False
    assert bool(r.evaluate({Number(100): {ADDR1}})) is True
    assert bool(r.evaluate({Number(100): {ADDR1, ADDR2}})) is False


def test_rule_yaml_count_range():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - count(number(100)): (1, 2)
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({Number(100): set()})) is False
    assert bool(r.evaluate({Number(100): {ADDR1}})) is True
    assert bool(r.evaluate({Number(100): {ADDR1, ADDR2}})) is True
    assert bool(r.evaluate({Number(100): {ADDR1, ADDR2, ADDR3}})) is False


def test_rule_yaml_count_string():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - count(string(foo)): 2
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({String("foo"): set()})) is False
    assert bool(r.evaluate({String("foo"): {ADDR1}})) is False
    assert bool(r.evaluate({String("foo"): {ADDR1, ADDR2}})) is True
    assert bool(r.evaluate({String("foo"): {ADDR1, ADDR2, ADDR3}})) is False


def test_invalid_rule_feature():
    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - foo: true
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        scope: file
                    features:
                        - characteristic: nzxor
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        scope: function
                    features:
                        - characteristic: embedded pe
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        scope: basic block
                    features:
                        - characteristic: embedded pe
                """
            )
        )


def test_lib_rules():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: a lib rule
                            lib: true
                        features:
                            - api: CreateFileA
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: a standard rule
                            lib: false
                        features:
                            - api: CreateFileW
                    """
                )
            ),
        ]
    )
    # lib rules are added to the rule set
    assert len(rules.function_rules) == 2


def test_subscope_rules():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: test rule
                            scope: file
                        features:
                            - and:
                                - characteristic: embedded pe
                                - function:
                                    - and:
                                        - characteristic: nzxor
                                        - characteristic: loop
                    """
                )
            )
        ]
    )
    # the file rule scope will have one rules:
    #  - `test rule`
    assert len(rules.file_rules) == 1

    # the function rule scope have one rule:
    #  - the rule on which `test rule` depends
    assert len(rules.function_rules) == 1


def test_duplicate_rules():
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.RuleSet(
            [
                capa.rules.Rule.from_yaml(
                    textwrap.dedent(
                        """
                        rule:
                            meta:
                                name: rule-name
                            features:
                                - api: CreateFileA
                        """
                    )
                ),
                capa.rules.Rule.from_yaml(
                    textwrap.dedent(
                        """
                        rule:
                            meta:
                                name: rule-name
                            features:
                                - api: CreateFileW
                        """
                    )
                ),
            ]
        )


def test_missing_dependency():
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.RuleSet(
            [
                capa.rules.Rule.from_yaml(
                    textwrap.dedent(
                        """
                        rule:
                            meta:
                                name: dependent rule
                            features:
                                - match: missing rule
                        """
                    )
                ),
            ]
        )


def test_invalid_rules():
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - characteristic: number(1)
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - characteristic: count(number(100))
                """
            )
        )

    # att&ck and mbc must be lists
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        att&ck: Tactic::Technique::Subtechnique [Identifier]
                    features:
                        - number: 1
                """
            )
        )
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                        mbc: Objective::Behavior::Method [Identifier]
                    features:
                        - number: 1
                """
            )
        )


def test_number_symbol():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - and:
                    - number: 1
                    - number: 0xFFFFFFFF
                    - number: 2 = symbol name
                    - number: 3  =  symbol name
                    - number: 4  =  symbol name = another name
                    - number: 0x100 = symbol name
                    - number: 0x11 = (FLAG_A | FLAG_B)
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Number(1) in children) is True
    assert (Number(0xFFFFFFFF) in children) is True
    assert (Number(2, description="symbol name") in children) is True
    assert (Number(3, description="symbol name") in children) is True
    assert (Number(4, description="symbol name = another name") in children) is True
    assert (Number(0x100, description="symbol name") in children) is True


def test_count_number_symbol():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - count(number(2 = symbol name)): 1
                    - count(number(0x100 = symbol name)): 2 or more
                    - count(number(0x11 = (FLAG_A | FLAG_B))): 2 or more
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({Number(2): set()})) is False
    assert bool(r.evaluate({Number(2): {ADDR1}})) is True
    assert bool(r.evaluate({Number(2): {ADDR1, ADDR2}})) is False
    assert bool(r.evaluate({Number(0x100, description="symbol name"): {ADDR1}})) is False
    assert bool(r.evaluate({Number(0x100, description="symbol name"): {ADDR1, ADDR2, ADDR3}})) is True


def test_invalid_number():
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - number: "this is a string"
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - number: 2=
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - number: symbol name = 2
                """
            )
        )


def test_offset_symbol():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - and:
                    - offset: 1
                    - offset: 2 = symbol name
                    - offset: 3  =  symbol name
                    - offset: 4  =  symbol name = another name
                    - offset: 0x100 = symbol name
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Offset(1) in children) is True
    assert (Offset(2, description="symbol name") in children) is True
    assert (Offset(3, description="symbol name") in children) is True
    assert (Offset(4, description="symbol name = another name") in children) is True
    assert (Offset(0x100, description="symbol name") in children) is True


def test_count_offset_symbol():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - count(offset(2 = symbol name)): 1
                    - count(offset(0x100 = symbol name)): 2 or more
                    - count(offset(0x11 = (FLAG_A | FLAG_B))): 2 or more
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    assert bool(r.evaluate({Offset(2): set()})) is False
    assert bool(r.evaluate({Offset(2): {ADDR1}})) is True
    assert bool(r.evaluate({Offset(2): {ADDR1, ADDR2}})) is False
    assert bool(r.evaluate({Offset(0x100, description="symbol name"): {ADDR1}})) is False
    assert bool(r.evaluate({Offset(0x100, description="symbol name"): {ADDR1, ADDR2, ADDR3}})) is True


def test_invalid_offset():
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - offset: "this is a string"
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - offset: 2=
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - offset: symbol name = 2
                """
            )
        )


def test_invalid_string_values_int():
    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - string: 123
                """
            )
        )

    with pytest.raises(capa.rules.InvalidRule):
        _ = capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - string: 0x123
                """
            )
        )


def test_explicit_string_values_int():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - string: "123"
                    - string: "0x123"
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (String("123") in children) is True
    assert (String("0x123") in children) is True


def test_string_values_special_characters():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - string: "hello\\r\\nworld"
                    - string: "bye\\nbye"
                      description: "test description"
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (String("hello\r\nworld") in children) is True
    assert (String("bye\nbye") in children) is True


def test_substring_feature():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - substring: abc
                    - substring: "def"
                    - substring: "gh\\ni"
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Substring("abc") in children) is True
    assert (Substring("def") in children) is True
    assert (Substring("gh\ni") in children) is True


def test_substring_description():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - substring: abc
                      description: the start of the alphabet
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Substring("abc") in children) is True


def test_filter_rules():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: rule 1
                            authors:
                              - joe
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
                            name: rule 2
                        features:
                            - string: joe
                    """
                )
            ),
        ]
    )
    rules = rules.filter_rules_by_meta("joe")
    assert len(rules) == 1
    assert "rule 1" in rules.rules


def test_filter_rules_dependencies():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: rule 1
                        features:
                            - match: rule 2
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: rule 2
                        features:
                            - match: rule 3
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: rule 3
                        features:
                            - api: CreateFile
                    """
                )
            ),
        ]
    )
    rules = rules.filter_rules_by_meta("rule 1")
    assert len(rules.rules) == 3
    assert "rule 1" in rules.rules
    assert "rule 2" in rules.rules
    assert "rule 3" in rules.rules


def test_filter_rules_missing_dependency():
    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.RuleSet(
            [
                capa.rules.Rule.from_yaml(
                    textwrap.dedent(
                        """
                        rule:
                            meta:
                                name: rule 1
                                authors:
                                  - joe
                            features:
                                - match: rule 2
                        """
                    )
                ),
            ]
        )


def test_rules_namespace_dependencies():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: rule 1
                        namespace: ns1/nsA
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
                        name: rule 2
                        namespace: ns1/nsB
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
                        name: rule 3
                    features:
                        - match: ns1/nsA
                """
            )
        ),
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: rule 4
                    features:
                        - match: ns1
                """
            )
        ),
    ]

    r3 = {r.name for r in capa.rules.get_rules_and_dependencies(rules, "rule 3")}
    assert "rule 1" in r3
    assert "rule 2" not in r3
    assert "rule 4" not in r3

    r4 = {r.name for r in capa.rules.get_rules_and_dependencies(rules, "rule 4")}
    assert "rule 1" in r4
    assert "rule 2" in r4
    assert "rule 3" not in r4


def test_function_name_features():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scope: file
            features:
                - and:
                    - function-name: strcpy
                    - function-name: strcmp = copy from here to there
                    - function-name: strdup
                      description: duplicate a string
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (FunctionName("strcpy") in children) is True
    assert (FunctionName("strcmp", description="copy from here to there") in children) is True
    assert (FunctionName("strdup", description="duplicate a string") in children) is True


def test_os_features():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scope: file
            features:
                - and:
                    - os: windows
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (OS(OS_WINDOWS) in children) is True
    assert (OS(OS_LINUX) not in children) is True


def test_format_features():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scope: file
            features:
                - and:
                    - format: pe
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Format(FORMAT_PE) in children) is True
    assert (Format(FORMAT_ELF) not in children) is True


def test_arch_features():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scope: file
            features:
                - and:
                    - arch: amd64
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Arch(ARCH_AMD64) in children) is True
    assert (Arch(ARCH_I386) not in children) is True


def test_property_access():
    r = capa.rules.Rule.from_yaml(
        textwrap.dedent(
            """
            rule:
                meta:
                    name: test rule
                features:
                    - property/read: System.IO.FileInfo::Length
            """
        )
    )
    assert bool(r.evaluate({Property("System.IO.FileInfo::Length", access=FeatureAccess.READ): {ADDR1}})) is True

    assert bool(r.evaluate({Property("System.IO.FileInfo::Length"): {ADDR1}})) is False
    assert bool(r.evaluate({Property("System.IO.FileInfo::Length", access=FeatureAccess.WRITE): {ADDR1}})) is False


def test_property_access_symbol():
    r = capa.rules.Rule.from_yaml(
        textwrap.dedent(
            """
            rule:
                meta:
                    name: test rule
                features:
                    - property/read: System.IO.FileInfo::Length = some property
            """
        )
    )
    assert (
        bool(
            r.evaluate(
                {
                    Property("System.IO.FileInfo::Length", access=FeatureAccess.READ, description="some property"): {
                        ADDR1
                    }
                }
            )
        )
        is True
    )
