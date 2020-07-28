# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import textwrap

import capa.rules
import capa.engine
from capa.engine import *
from capa.features import *
from capa.features.insn import *


def test_number():
    assert Number(1).evaluate({Number(0): {1}}) == False
    assert Number(1).evaluate({Number(1): {1}}) == True
    assert Number(1).evaluate({Number(2): {1, 2}}) == False


def test_and():
    assert And([Number(1)]).evaluate({Number(0): {1}}) == False
    assert And([Number(1)]).evaluate({Number(1): {1}}) == True
    assert And([Number(1), Number(2)]).evaluate({Number(0): {1}}) == False
    assert And([Number(1), Number(2)]).evaluate({Number(1): {1}}) == False
    assert And([Number(1), Number(2)]).evaluate({Number(2): {1}}) == False
    assert And([Number(1), Number(2)]).evaluate({Number(1): {1}, Number(2): {2}}) == True


def test_or():
    assert Or([Number(1)]).evaluate({Number(0): {1}}) == False
    assert Or([Number(1)]).evaluate({Number(1): {1}}) == True
    assert Or([Number(1), Number(2)]).evaluate({Number(0): {1}}) == False
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {1}}) == True
    assert Or([Number(1), Number(2)]).evaluate({Number(2): {1}}) == True
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {1}, Number(2): {2}}) == True


def test_not():
    assert Not(Number(1)).evaluate({Number(0): {1}}) == True
    assert Not(Number(1)).evaluate({Number(1): {1}}) == False


def test_some():
    assert Some(0, [Number(1)]).evaluate({Number(0): {1}}) == True
    assert Some(1, [Number(1)]).evaluate({Number(0): {1}}) == False

    assert Some(2, [Number(1), Number(2), Number(3)]).evaluate({Number(0): {1}}) == False
    assert Some(2, [Number(1), Number(2), Number(3)]).evaluate({Number(0): {1}, Number(1): {1}}) == False
    assert Some(2, [Number(1), Number(2), Number(3)]).evaluate({Number(0): {1}, Number(1): {1}, Number(2): {1}}) == True
    assert (
        Some(2, [Number(1), Number(2), Number(3)]).evaluate(
            {Number(0): {1}, Number(1): {1}, Number(2): {1}, Number(3): {1}}
        )
        == True
    )
    assert (
        Some(2, [Number(1), Number(2), Number(3)]).evaluate(
            {Number(0): {1}, Number(1): {1}, Number(2): {1}, Number(3): {1}, Number(4): {1},}
        )
        == True
    )


def test_complex():
    assert True == Or(
        [And([Number(1), Number(2)]), Or([Number(3), Some(2, [Number(4), Number(5), Number(6)])])]
    ).evaluate({Number(5): {1}, Number(6): {1}, Number(7): {1}, Number(8): {1}})

    assert False == Or([And([Number(1), Number(2)]), Or([Number(3), Some(2, [Number(4), Number(5)])])]).evaluate(
        {Number(5): {1}, Number(6): {1}, Number(7): {1}, Number(8): {1}}
    )


def test_range():
    # unbounded range, but no matching feature
    # since the lower bound is zero, and there are zero matches, ok
    assert Range(Number(1)).evaluate({Number(2): {}}) == True

    # unbounded range with matching feature should always match
    assert Range(Number(1)).evaluate({Number(1): {}}) == True
    assert Range(Number(1)).evaluate({Number(1): {0}}) == True

    # unbounded max
    assert Range(Number(1), min=1).evaluate({Number(1): {0}}) == True
    assert Range(Number(1), min=2).evaluate({Number(1): {0}}) == False
    assert Range(Number(1), min=2).evaluate({Number(1): {0, 1}}) == True

    # unbounded min
    assert Range(Number(1), max=0).evaluate({Number(1): {0}}) == False
    assert Range(Number(1), max=1).evaluate({Number(1): {0}}) == True
    assert Range(Number(1), max=2).evaluate({Number(1): {0}}) == True
    assert Range(Number(1), max=2).evaluate({Number(1): {0, 1}}) == True
    assert Range(Number(1), max=2).evaluate({Number(1): {0, 1, 3}}) == False

    # we can do an exact match by setting min==max
    assert Range(Number(1), min=1, max=1).evaluate({Number(1): {}}) == False
    assert Range(Number(1), min=1, max=1).evaluate({Number(1): {1}}) == True
    assert Range(Number(1), min=1, max=1).evaluate({Number(1): {1, 2}}) == False

    # bounded range
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {}}) == False
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {1}}) == True
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {1, 2}}) == True
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {1, 2, 3}}) == True
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {1, 2, 3, 4}}) == False


def test_range_exact():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - count(number(100)): 2
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # just enough matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" in matches

    # not enough matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert "test rule" not in matches

    # too many matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1, 2, 3}}, 0x0)
    assert "test rule" not in matches


def test_range_range():
    rule = textwrap.dedent(
        """
         rule:
             meta:
                 name: test rule
             features:
                 - count(number(100)): (2, 3)
         """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # just enough matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" in matches

    # enough matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1, 2, 3}}, 0x0)
    assert "test rule" in matches

    # not enough matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert "test rule" not in matches

    # too many matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1, 2, 3, 4}}, 0x0)
    assert "test rule" not in matches


def test_range_exact_zero():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - count(number(100)): 0
        """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # feature isn't indexed - good.
    features, matches = capa.engine.match([r], {}, 0x0)
    assert "test rule" in matches

    # feature is indexed, but no matches.
    # i don't think we should ever really have this case, but good to check anyways.
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {}}, 0x0)
    assert "test rule" in matches

    # too many matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert "test rule" not in matches


def test_range_with_zero():
    rule = textwrap.dedent(
        """
         rule:
             meta:
                 name: test rule
             features:
                 - count(number(100)): (0, 1)
         """
    )
    r = capa.rules.Rule.from_yaml(rule)

    # ok
    features, matches = capa.engine.match([r], {}, 0x0)
    assert "test rule" in matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {}}, 0x0)
    assert "test rule" in matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert "test rule" in matches

    # too many matches
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1, 2}}, 0x0)
    assert "test rule" not in matches


def test_match_adds_matched_rule_feature():
    """show that using `match` adds a feature for matched rules."""
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
            features:
                - number: 100
        """
    )
    r = capa.rules.Rule.from_yaml(rule)
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert capa.features.MatchedRule("test rule") in features


def test_match_matched_rules():
    """show that using `match` adds a feature for matched rules."""
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule1
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
                    features:
                        - match: test rule1
                """
            )
        ),
    ]

    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.insn.Number(100): {1}}, 0x0,
    )
    assert capa.features.MatchedRule("test rule1") in features
    assert capa.features.MatchedRule("test rule2") in features

    # the ordering of the rules must not matter,
    # the engine should match rules in an appropriate order.
    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(reversed(rules)), {capa.features.insn.Number(100): {1}}, 0x0,
    )
    assert capa.features.MatchedRule("test rule1") in features
    assert capa.features.MatchedRule("test rule2") in features


def test_regex():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
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
                    features:
                        - and:
                            - string: /^bbbb/
                """
            )
        ),
    ]
    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.insn.Number(100): {1}}, 0x0,
    )
    assert capa.features.MatchedRule("test rule") not in features

    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.String("aaaa"): {1}}, 0x0,
    )
    assert capa.features.MatchedRule("test rule") not in features

    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.String("aBBBBa"): {1}}, 0x0,
    )
    assert capa.features.MatchedRule("test rule") not in features

    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.String("abbbba"): {1}}, 0x0,
    )
    assert capa.features.MatchedRule("test rule") in features
    assert capa.features.MatchedRule("rule with implied wildcards") in features
    assert capa.features.MatchedRule("rule with anchor") not in features


def test_regex_ignorecase():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: test rule
                    features:
                        - and:
                            - string: /.*bbbb.*/i
                """
            )
        ),
    ]
    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.String("aBBBBa"): {1}}, 0x0,
    )
    assert capa.features.MatchedRule("test rule") in features


def test_regex_complex():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                r"""
                rule:
                    meta:
                        name: test rule
                    features:
                        - or:
                            - string: /.*HARDWARE\\Key\\key with spaces\\.*/i
                """
            )
        ),
    ]
    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules),
        {capa.features.String(r"Hardware\Key\key with spaces\some value"): {1}},
        0x0,
    )
    assert capa.features.MatchedRule("test rule") in features


def test_match_namespace():
    rules = [
        capa.rules.Rule.from_yaml(
            textwrap.dedent(
                """
                rule:
                    meta:
                        name: CreateFile API
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
                    features:
                        - match: file
                """
            )
        ),
    ]

    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.insn.API("CreateFile"): {1}}, 0x0,
    )
    assert "CreateFile API" in matches
    assert "file-create" in matches
    assert "filesystem-any" in matches
    assert capa.features.MatchedRule("file") in features
    assert capa.features.MatchedRule("file/create") in features
    assert capa.features.MatchedRule("file/create/CreateFile") in features

    features, matches = capa.engine.match(
        capa.engine.topologically_order_rules(rules), {capa.features.insn.API("WriteFile"): {1}}, 0x0,
    )
    assert "WriteFile API" in matches
    assert "file-create" not in matches
    assert "filesystem-any" in matches
