# -*- coding: utf-8 -*-
# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import textwrap

import pytest
from fixtures import *

import capa.main
import capa.rules
import capa.engine
import capa.features
from capa.engine import *


def test_main(z9324d_extractor):
    # tests rules can be loaded successfully and all output modes
    path = z9324d_extractor.path
    assert capa.main.main([path, "-vv"]) == 0
    assert capa.main.main([path, "-v"]) == 0
    assert capa.main.main([path, "-j"]) == 0
    assert capa.main.main([path]) == 0


def test_main_single_rule(z9324d_extractor, tmpdir):
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
    path = z9324d_extractor.path
    rule_file = tmpdir.mkdir("capa").join("rule.yml")
    rule_file.write(RULE_CONTENT)
    assert (
        capa.main.main(
            [
                path,
                "-v",
                "-r",
                rule_file.strpath,
            ]
        )
        == 0
    )


def test_main_non_ascii_filename(pingtaest_extractor, tmpdir, capsys):
    # on py2.7, need to be careful about str (which can hold bytes)
    #  vs unicode (which is only unicode characters).
    # on py3, this should not be needed.
    #
    # here we print a string with unicode characters in it
    # (specifically, a byte string with utf-8 bytes in it, see file encoding)
    assert capa.main.main(["-q", pingtaest_extractor.path]) == 0

    std = capsys.readouterr()
    # but here, we have to use a unicode instance,
    # because capsys has decoded the output for us.
    if sys.version_info >= (3, 0):
        assert pingtaest_extractor.path in std.out
    else:
        assert pingtaest_extractor.path.decode("utf-8") in std.out


def test_main_non_ascii_filename_nonexistent(tmpdir, caplog):
    NON_ASCII_FILENAME = "täst_not_there.exe"
    assert capa.main.main(["-q", NON_ASCII_FILENAME]) == -1

    if sys.version_info >= (3, 0):
        assert NON_ASCII_FILENAME in caplog.text
    else:
        assert NON_ASCII_FILENAME.decode("utf-8") in caplog.text


def test_main_shellcode(z499c2_extractor):
    path = z499c2_extractor.path
    assert capa.main.main([path, "-vv", "-f", "sc32"]) == 0
    assert capa.main.main([path, "-v", "-f", "sc32"]) == 0
    assert capa.main.main([path, "-j", "-f", "sc32"]) == 0
    assert capa.main.main([path, "-f", "sc32"]) == 0


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
                          - characteristic: tight loop
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
    capabilities, meta = capa.main.find_capabilities(rules, z9324d_extractor)
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
    capabilities, meta = capa.main.find_capabilities(rules, z9324d_extractor)
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
    capabilities, meta = capa.main.find_capabilities(rules, z9324d_extractor)
    assert "test rule" in capabilities


def test_byte_matching(z9324d_extractor):
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
    capabilities, meta = capa.main.find_capabilities(rules, z9324d_extractor)
    assert "byte match test" in capabilities


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
                        scope: function
                      features:
                        - and:
                          - count(basic blocks): 1 or more
                    """
                )
            )
        ]
    )
    capabilities, meta = capa.main.find_capabilities(rules, z9324d_extractor)
    assert "count bb" in capabilities


def test_fix262(pma16_01_extractor, capsys):
    # tests rules can be loaded successfully and all output modes
    path = pma16_01_extractor.path
    assert capa.main.main([path, "-vv", "-t", "send HTTP request", "-q"]) == 0

    std = capsys.readouterr()
    assert "HTTP/1.0" in std.out
    assert "www.practicalmalwareanalysis.com" not in std.out


def test_not_render_rules_also_matched(z9324d_extractor, capsys):
    # rules that are also matched by other rules should not get rendered by default.
    # this cuts down on the amount of output while giving approx the same detail.
    # see #224
    path = z9324d_extractor.path

    # `act as TCP client` matches on
    # `connect TCP client` matches on
    # `create TCP socket`
    #
    # so only `act as TCP client` should be displayed
    assert capa.main.main([path]) == 0
    std = capsys.readouterr()
    assert "act as TCP client" in std.out
    assert "connect TCP socket" not in std.out
    assert "create TCP socket" not in std.out

    # this strategy only applies to the default renderer, not any verbose renderer
    assert capa.main.main([path, "-v"]) == 0
    std = capsys.readouterr()
    assert "act as TCP client" in std.out
    assert "connect TCP socket" in std.out
    assert "create TCP socket" in std.out
