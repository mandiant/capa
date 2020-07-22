# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import textwrap

from fixtures import *

import capa.main
import capa.rules
import capa.engine
import capa.features
import capa.features.extractors.viv
from capa.engine import *


def test_main(sample_9324d1a8ae37a36ae560c37448c9705a):
    # tests rules can be loaded successfully and all output modes
    assert capa.main.main([sample_9324d1a8ae37a36ae560c37448c9705a.path, "-vv"]) == 0
    assert capa.main.main([sample_9324d1a8ae37a36ae560c37448c9705a.path, "-v"]) == 0
    assert capa.main.main([sample_9324d1a8ae37a36ae560c37448c9705a.path, "-j"]) == 0
    assert capa.main.main([sample_9324d1a8ae37a36ae560c37448c9705a.path]) == 0


def test_main_single_rule(sample_9324d1a8ae37a36ae560c37448c9705a, tmpdir):
    # tests a single rule can be loaded successfully
    RULE_CONTENT = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scope: file
            features:
              - string: test
        """
    )
    rule_file = tmpdir.mkdir("capa").join("rule.yml")
    rule_file.write(RULE_CONTENT)
    assert capa.main.main([sample_9324d1a8ae37a36ae560c37448c9705a.path, "-v", "-r", rule_file.strpath,]) == 0


def test_main_shellcode(sample_499c2a85f6e8142c3f48d4251c9c7cd6_raw32):
    assert capa.main.main([sample_499c2a85f6e8142c3f48d4251c9c7cd6_raw32.path, "-vv", "-f", "sc32"]) == 0
    assert capa.main.main([sample_499c2a85f6e8142c3f48d4251c9c7cd6_raw32.path, "-v", "-f", "sc32"]) == 0
    assert capa.main.main([sample_499c2a85f6e8142c3f48d4251c9c7cd6_raw32.path, "-j", "-f", "sc32"]) == 0
    assert capa.main.main([sample_499c2a85f6e8142c3f48d4251c9c7cd6_raw32.path, "-f", "sc32"]) == 0


def test_ruleset():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: file rule
                            scope: file
                        features:
                          - characteristic: embedded pe
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: function rule
                            scope: function
                        features:
                          - characteristic: switch
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: basic block rule
                            scope: basic block
                        features:
                          - characteristic: nzxor
                    """
                )
            ),
        ]
    )
    assert len(rules.file_rules) == 1
    assert len(rules.function_rules) == 1
    assert len(rules.basic_block_rules) == 1


def test_match_across_scopes_file_function(sample_9324d1a8ae37a36ae560c37448c9705a):
    rules = capa.rules.RuleSet(
        [
            # this rule should match on a function (0x4073F0)
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: install service
                            scope: function
                            examples:
                              - 9324d1a8ae37a36ae560c37448c9705a:0x4073F0
                        features:
                            - and:
                                - api: advapi32.OpenSCManagerA
                                - api: advapi32.CreateServiceA
                                - api: advapi32.StartServiceA
                    """
                )
            ),
            # this rule should match on a file feature
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: .text section
                            scope: file
                            examples:
                              - 9324d1a8ae37a36ae560c37448c9705a
                        features:
                            - section: .text
                    """
                )
            ),
            # this rule should match on earlier rule matches:
            #  - install service, with function scope
            #  - .text section, with file scope
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: .text section and install service
                            scope: file
                            examples:
                              - 9324d1a8ae37a36ae560c37448c9705a
                        features:
                            - and:
                              - match: install service
                              - match: .text section
                    """
                )
            ),
        ]
    )
    extractor = capa.features.extractors.viv.VivisectFeatureExtractor(
        sample_9324d1a8ae37a36ae560c37448c9705a.vw, sample_9324d1a8ae37a36ae560c37448c9705a.path,
    )
    capabilities, meta = capa.main.find_capabilities(rules, extractor)
    assert "install service" in capabilities
    assert ".text section" in capabilities
    assert ".text section and install service" in capabilities


def test_match_across_scopes(sample_9324d1a8ae37a36ae560c37448c9705a):
    rules = capa.rules.RuleSet(
        [
            # this rule should match on a basic block (including at least 0x403685)
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: tight loop
                            scope: basic block
                            examples:
                              - 9324d1a8ae37a36ae560c37448c9705a:0x403685
                        features:
                          - characteristic: tight loop
                    """
                )
            ),
            # this rule should match on a function (0x403660)
            # based on API, as well as prior basic block rule match
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: kill thread loop
                            scope: function
                            examples:
                              - 9324d1a8ae37a36ae560c37448c9705a:0x403660
                        features:
                          - and:
                            - api: kernel32.TerminateThread
                            - api: kernel32.CloseHandle
                            - match: tight loop
                    """
                )
            ),
            # this rule should match on a file feature and a prior function rule match
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: kill thread program
                            scope: file
                            examples:
                              - 9324d1a8ae37a36ae560c37448c9705a
                        features:
                          - and:
                            - section: .text
                            - match: kill thread loop
                    """
                )
            ),
        ]
    )
    extractor = capa.features.extractors.viv.VivisectFeatureExtractor(
        sample_9324d1a8ae37a36ae560c37448c9705a.vw, sample_9324d1a8ae37a36ae560c37448c9705a.path
    )
    capabilities, meta = capa.main.find_capabilities(rules, extractor)
    assert "tight loop" in capabilities
    assert "kill thread loop" in capabilities
    assert "kill thread program" in capabilities


def test_subscope_bb_rules(sample_9324d1a8ae37a36ae560c37448c9705a):
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: test rule
                            scope: function
                        features:
                            - and:
                                - basic block:
                                    - characteristic: tight loop
                    """
                )
            )
        ]
    )
    # tight loop at 0x403685
    extractor = capa.features.extractors.viv.VivisectFeatureExtractor(
        sample_9324d1a8ae37a36ae560c37448c9705a.vw, sample_9324d1a8ae37a36ae560c37448c9705a.path,
    )
    capabilities, meta = capa.main.find_capabilities(rules, extractor)
    assert "test rule" in capabilities


def test_byte_matching(sample_9324d1a8ae37a36ae560c37448c9705a):
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: byte match test
                            scope: function
                        features:
                            - and:
                                - bytes: ED 24 9E F4 52 A9 07 47 55 8E E1 AB 30 8E 23 61
                    """
                )
            )
        ]
    )

    extractor = capa.features.extractors.viv.VivisectFeatureExtractor(
        sample_9324d1a8ae37a36ae560c37448c9705a.vw, sample_9324d1a8ae37a36ae560c37448c9705a.path,
    )
    capabilities, meta = capa.main.find_capabilities(rules, extractor)
    assert "byte match test" in capabilities


def test_count_bb(sample_9324d1a8ae37a36ae560c37448c9705a):
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                      meta:
                        name: count bb
                        namespace: test
                        scope: function
                      features:
                        - and:
                          - count(basic blocks): 1 or more
                    """
                )
            )
        ]
    )

    extractor = capa.features.extractors.viv.VivisectFeatureExtractor(
        sample_9324d1a8ae37a36ae560c37448c9705a.vw, sample_9324d1a8ae37a36ae560c37448c9705a.path,
    )
    capabilities, meta = capa.main.find_capabilities(rules, extractor)
    assert "count bb" in capabilities
