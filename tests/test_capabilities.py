# -*- coding: utf-8 -*-
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import textwrap

import capa.capabilities.common
from capa.features.extractors.base_extractor import FunctionFilter


def test_match_across_scopes_file_function(z9324d_extractor):
    rules = capa.rules.RuleSet(
        [
            # this rule should match on a function (0x4073F0)
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: install service
                            scopes:
                                static: function
                                dynamic: process
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
                            scopes:
                                static: file
                                dynamic: process
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
                            scopes:
                                static: file
                                dynamic: process
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
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, z9324d_extractor)
    assert "install service" in capabilities
    assert ".text section" in capabilities
    assert ".text section and install service" in capabilities


def test_match_across_scopes(z9324d_extractor):
    rules = capa.rules.RuleSet(
        [
            # this rule should match on a basic block (including at least 0x403685)
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: tight loop
                            scopes:
                                static: basic block
                                dynamic: process
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
                            scopes:
                                static: function
                                dynamic: process
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
                            scopes:
                                static: file
                                dynamic: process
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
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, z9324d_extractor)
    assert "tight loop" in capabilities
    assert "kill thread loop" in capabilities
    assert "kill thread program" in capabilities


def test_subscope_bb_rules(z9324d_extractor):
    rules = capa.rules.RuleSet(
        [
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
                                - basic block:
                                    - characteristic: tight loop
                    """
                )
            )
        ]
    )
    # tight loop at 0x403685
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, z9324d_extractor)
    assert "test rule" in capabilities


def test_match_specific_functions(z9324d_extractor):
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: receive data
                            scopes:
                                static: function
                                dynamic: call
                            examples:
                            - 9324d1a8ae37a36ae560c37448c9705a:0x401CD0
                        features:
                            - or:
                                - api: recv
                    """
                )
            )
        ]
    )
    extractor = FunctionFilter(z9324d_extractor, {0x4019C0})
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, extractor)
    matches = capabilities["receive data"]
    # test that we received only one match
    assert len(matches) == 1
    # and that this match is from the specified function
    assert matches[0][0] == 0x4019C0


def test_byte_matching(z9324d_extractor):
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: byte match test
                            scopes:
                                static: function
                                dynamic: process
                        features:
                            - and:
                                - bytes: ED 24 9E F4 52 A9 07 47 55 8E E1 AB 30 8E 23 61
                    """
                )
            )
        ]
    )
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, z9324d_extractor)
    assert "byte match test" in capabilities


def test_com_feature_matching(z395eb_extractor):
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: initialize IWebBrowser2
                            scopes:
                              static: basic block
                              dynamic: unsupported
                        features:
                            - and:
                                - api: ole32.CoCreateInstance
                                - com/class: InternetExplorer #bytes: 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = CLSID_InternetExplorer
                                - com/interface: IWebBrowser2 #bytes: 61 16 0C D3 AF CD D0 11 8A 3E 00 C0 4F C9 E2 6E = IID_IWebBrowser2
                    """
                )
            )
        ]
    )
    capabilities, meta = capa.main.find_capabilities(rules, z395eb_extractor)
    assert "initialize IWebBrowser2" in capabilities


def test_count_bb(z9324d_extractor):
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                      meta:
                        name: count bb
                        namespace: test
                        scopes:
                            static: function
                            dynamic: process
                      features:
                        - and:
                          - count(basic blocks): 1 or more
                    """
                )
            )
        ]
    )
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, z9324d_extractor)
    assert "count bb" in capabilities


def test_instruction_scope(z9324d_extractor):
    # .text:004071A4 68 E8 03 00 00          push    3E8h
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                      meta:
                        name: push 1000
                        namespace: test
                        scopes:
                            static: instruction
                            dynamic: process
                      features:
                        - and:
                          - mnemonic: push
                          - number: 1000
                    """
                )
            )
        ]
    )
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, z9324d_extractor)
    assert "push 1000" in capabilities
    assert 0x4071A4 in {result[0] for result in capabilities["push 1000"]}


def test_instruction_subscope(z9324d_extractor):
    # .text:00406F60                         sub_406F60 proc near
    # [...]
    # .text:004071A4 68 E8 03 00 00          push    3E8h
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                      meta:
                        name: push 1000 on i386
                        namespace: test
                        scopes:
                            static: function
                            dynamic: process
                      features:
                        - and:
                          - arch: i386
                          - instruction:
                            - mnemonic: push
                            - number: 1000
                    """
                )
            )
        ]
    )
    capabilities, meta = capa.capabilities.common.find_capabilities(rules, z9324d_extractor)
    assert "push 1000 on i386" in capabilities
    assert 0x406F60 in {result[0] for result in capabilities["push 1000 on i386"]}
