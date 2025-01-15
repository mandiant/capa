# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

import gzip
import json
import textwrap
from pathlib import Path

import fixtures

import capa.main
import capa.rules
import capa.engine
import capa.features


def test_main(z9324d_extractor):
    # tests rules can be loaded successfully and all output modes
    path = z9324d_extractor.path
    assert capa.main.main([path, "-vv"]) == 0
    assert capa.main.main([path, "-v"]) == 0
    assert capa.main.main([path, "-j"]) == 0
    assert capa.main.main([path, "-q"]) == 0
    assert capa.main.main([path]) == 0


def test_main_single_rule(z9324d_extractor, tmpdir):
    # tests a single rule can be loaded successfully
    RULE_CONTENT = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: file
                    dynamic: file
                authors:
                  - test
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
    # here we print a string with unicode characters in it
    # (specifically, a byte string with utf-8 bytes in it, see file encoding)
    # only use one rule to speed up analysis
    assert capa.main.main(["-q", pingtaest_extractor.path, "-r", "rules/communication/icmp"]) == 0

    std = capsys.readouterr()
    # but here, we have to use a unicode instance,
    # because capsys has decoded the output for us.
    assert pingtaest_extractor.path in std.out


def test_main_non_ascii_filename_nonexistent(tmpdir, caplog):
    NON_ASCII_FILENAME = "täst_not_there.exe"
    assert capa.main.main(["-q", NON_ASCII_FILENAME]) == capa.main.E_MISSING_FILE

    assert NON_ASCII_FILENAME in caplog.text


def test_main_shellcode(z499c2_extractor):
    path = z499c2_extractor.path
    assert capa.main.main([path, "-vv", "-f", "sc32"]) == 0
    assert capa.main.main([path, "-v", "-f", "sc32"]) == 0
    assert capa.main.main([path, "-j", "-f", "sc32"]) == 0
    assert capa.main.main([path, "-q", "-f", "sc32"]) == 0
    # auto detect shellcode based on file extension, same as -f sc32
    assert capa.main.main([path]) == 0


def test_ruleset():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: file rule
                            scopes:
                                static: file
                                dynamic: process
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
                            scopes:
                                static: function
                                dynamic: process
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
                            scopes:
                                static: basic block
                                dynamic: process
                        features:
                          - characteristic: nzxor
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: process rule
                            scopes:
                                static: file
                                dynamic: process
                        features:
                          - string: "explorer.exe"
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                        rule:
                            meta:
                                name: thread rule
                                scopes:
                                    static: function
                                    dynamic: thread
                            features:
                              - api: RegDeleteKey
                        """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: test call subscope
                            scopes:
                                static: basic block
                                dynamic: thread
                        features:
                          - and:
                            - string: "explorer.exe"
                            - call:
                              - api: HttpOpenRequestW
                    """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: test rule
                            scopes:
                                static: instruction
                                dynamic: call
                        features:
                          - and:
                            - or:
                              - api: socket
                              - and:
                                - os: linux
                                - mnemonic: syscall
                                - number: 41 = socket()
                            - number: 6 = IPPROTO_TCP
                            - number: 1 = SOCK_STREAM
                            - number: 2 = AF_INET
                    """
                )
            ),
        ]
    )
    assert len(rules.file_rules) == 2
    assert len(rules.function_rules) == 2
    assert len(rules.basic_block_rules) == 2
    assert len(rules.instruction_rules) == 1
    assert len(rules.process_rules) == 4
    assert len(rules.thread_rules) == 2
    assert len(rules.call_rules) == 2


def test_fix262(pma16_01_extractor, capsys):
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
    # filter rules to speed up matching
    assert capa.main.main([path, "-t", "act as TCP client"]) == 0
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


def test_json_meta(capsys):
    path = str(fixtures.get_data_path_by_name("pma01-01"))
    assert capa.main.main([path, "-j"]) == 0
    std = capsys.readouterr()
    std_json = json.loads(std.out)

    assert {"type": "absolute", "value": 0x10001010} in [
        f["address"] for f in std_json["meta"]["analysis"]["layout"]["functions"]
    ]

    for addr, info in std_json["meta"]["analysis"]["layout"]["functions"]:
        if addr == ["absolute", 0x10001010]:
            assert {"address": ["absolute", 0x10001179]} in info["matched_basic_blocks"]


def test_main_dotnet(_1c444_dotnetfile_extractor):
    # tests successful execution and all output modes
    path = _1c444_dotnetfile_extractor.path
    assert capa.main.main([path, "-vv"]) == 0
    assert capa.main.main([path, "-v"]) == 0
    assert capa.main.main([path, "-j"]) == 0
    assert capa.main.main([path, "-q"]) == 0
    assert capa.main.main([path]) == 0


def test_main_dotnet2(_692f_dotnetfile_extractor):
    # tests successful execution and one rendering
    # above covers all output modes
    path = _692f_dotnetfile_extractor.path
    assert capa.main.main([path, "-vv"]) == 0


def test_main_dotnet3(_0953c_dotnetfile_extractor):
    # tests successful execution and one rendering
    path = _0953c_dotnetfile_extractor.path
    assert capa.main.main([path, "-vv"]) == 0


def test_main_dotnet4(_039a6_dotnetfile_extractor):
    # tests successful execution and one rendering
    path = _039a6_dotnetfile_extractor.path
    assert capa.main.main([path, "-vv"]) == 0


def test_main_rd():
    path = str(fixtures.get_data_path_by_name("pma01-01-rd"))
    assert capa.main.main([path, "-vv"]) == 0
    assert capa.main.main([path, "-v"]) == 0
    assert capa.main.main([path, "-j"]) == 0
    assert capa.main.main([path, "-q"]) == 0
    assert capa.main.main([path]) == 0


def extract_cape_report(tmp_path: Path, gz: Path) -> Path:
    report = tmp_path / "report.json"
    report.write_bytes(gzip.decompress(gz.read_bytes()))
    return report


def test_main_cape1(tmp_path):
    path = extract_cape_report(tmp_path, fixtures.get_data_path_by_name("0000a657"))

    # TODO(williballenthin): use default rules set
    # https://github.com/mandiant/capa/pull/1696
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "create-or-open-registry-key.yml").write_text(
        textwrap.dedent(
            """
        rule:
          meta:
            name: create or open registry key
            authors:
              - testing
            scopes:
              static: instruction
              dynamic: call
          features:
            - or:
              - api: advapi32.RegOpenKey
              - api: advapi32.RegOpenKeyEx
              - api: advapi32.RegCreateKey
              - api: advapi32.RegCreateKeyEx
              - api: advapi32.RegOpenCurrentUser
              - api: advapi32.RegOpenKeyTransacted
              - api: advapi32.RegOpenUserClassesRoot
              - api: advapi32.RegCreateKeyTransacted
              - api: ZwOpenKey
              - api: ZwOpenKeyEx
              - api: ZwCreateKey
              - api: ZwOpenKeyTransacted
              - api: ZwOpenKeyTransactedEx
              - api: ZwCreateKeyTransacted
              - api: NtOpenKey
              - api: NtCreateKey
              - api: SHRegOpenUSKey
              - api: SHRegCreateUSKey
              - api: RtlCreateRegistryKey
    """
        )
    )

    assert capa.main.main([str(path), "-r", str(rules)]) == 0
    assert capa.main.main([str(path), "-q", "-r", str(rules)]) == 0
    assert capa.main.main([str(path), "-j", "-r", str(rules)]) == 0
    assert capa.main.main([str(path), "-v", "-r", str(rules)]) == 0
    assert capa.main.main([str(path), "-vv", "-r", str(rules)]) == 0


def test_main_cape_gzip():
    # tests successful execution of .json.gz
    path = str(fixtures.get_data_path_by_name("0000a657"))
    assert capa.main.main([path]) == 0
