# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import sys
import logging
import textwrap
import subprocess

import pytest

logger = logging.getLogger(__name__)

CD = os.path.dirname(__file__)


def get_script_path(s):
    return os.path.join(CD, "..", "scripts", s)


def get_file_path():
    return os.path.join(CD, "data", "9324d1a8ae37a36ae560c37448c9705a.exe_")


def get_rules_path():
    return os.path.join(CD, "..", "rules")


def get_rule_path():
    return os.path.join(get_rules_path(), "lib", "allocate-memory.yml")


@pytest.mark.parametrize(
    "script,args",
    [
        pytest.param("capa2yara.py", [get_rules_path()]),
        pytest.param("capafmt.py", [get_rule_path()]),
        # not testing lint.py as it runs regularly anyway
        pytest.param("match-function-id.py", [get_file_path()]),
        pytest.param("show-capabilities-by-function.py", [get_file_path()]),
        pytest.param("show-features.py", [get_file_path()]),
        pytest.param("show-features.py", ["-F", "0x407970", get_file_path()]),
        pytest.param("capa_as_library.py", [get_file_path()]),
    ],
)
def test_scripts(script, args):
    script_path = get_script_path(script)
    p = run_program(script_path, args)
    assert p.returncode == 0


def test_bulk_process(tmpdir):
    # create test directory to recursively analyze
    t = tmpdir.mkdir("test")
    with open(os.path.join(CD, "data", "ping_täst.exe_"), "rb") as f:
        t.join("test.exe_").write_binary(f.read())

    p = run_program(get_script_path("bulk-process.py"), [t.dirname])
    assert p.returncode == 0


def run_program(script_path, args):
    args = [sys.executable] + [script_path] + args
    logger.debug("running: %r", args)
    return subprocess.run(args, stdout=subprocess.PIPE)


def test_proto_conversion(tmpdir):
    t = tmpdir.mkdir("proto-test")

    json = os.path.join(CD, "data", "rd", "Practical Malware Analysis Lab 01-01.dll_.json")

    p = run_program(get_script_path("proto-from-results.py"), [json])
    assert p.returncode == 0

    pb = os.path.join(t, "pma.pb")
    with open(pb, "wb") as f:
        f.write(p.stdout)

    p = run_program(get_script_path("proto-to-results.py"), [pb])
    assert p.returncode == 0

    assert p.stdout.startswith(b'{\n  "meta": ') or p.stdout.startswith(b'{\r\n  "meta": ')


def test_detect_duplicate_features(tmpdir):
    TEST_RULE_0 = textwrap.dedent(
        """
        rule:
            meta:
                name: Test Rule 0
                scope: function
            features:
              - and:
                - number: 1
                - not:
                  - string: process
        """
    )

    TEST_RULESET = {
        "rule_1": textwrap.dedent(
            """
                rule:
                    meta:
                        name: Test Rule 1
                    features:
                      - or:
                        - string: unique
                        - number: 2
                        - and:
                          - or:
                            - arch: i386
                            - number: 4
                            - not:
                              - count(mnemonic(xor)): 5
                          - not:
                            - os: linux
            """
        ),
        "rule_2": textwrap.dedent(
            """
                rule:
                    meta:
                        name: Test Rule 2
                    features:
                      - and:
                        - string: "sites.ini"
                        - basic block:
                          - and:
                            - api: CreateFile
                            - mnemonic: xor
            """
        ),
        "rule_3": textwrap.dedent(
            """
                rule:
                    meta:
                        name: Test Rule 3
                    features:
                      - or:
                        - not:
                          - number: 4
                        - basic block:
                          - and:
                            - api: bind
                            - number: 2
            """
        ),
        "rule_4": textwrap.dedent(
            """
                rule:
                    meta:
                        name: Test Rule 4
                    features:
                      - not:
                        - string: "expa"
            """
        ),
    }

    """
        The rule_overlaps list represents the number of overlaps between each rule in the RULESET.
        An overlap includes a rule overlap with itself.
        The scripts
        The overlaps are like:
        - Rule 0 has zero overlaps in RULESET
        - Rule 1 overlaps with 3 other rules in RULESET
        - Rule 4 overlaps with itself in RULESET
        These overlap values indicate the number of rules with which
        each rule in RULESET has overlapping features.
    """
    rule_overlaps = [0, 4, 3, 3, 1]

    rule_dir = tmpdir.mkdir("capa_rule_overlap_test")
    rule_paths = []

    rule_file = tmpdir.join("rule_0.yml")
    rule_file.write(TEST_RULE_0)
    rule_paths.append(rule_file.strpath)

    for rule_name, RULE_CONTENT in TEST_RULESET.items():
        rule_file = rule_dir.join("%s.yml" % rule_name)
        rule_file.write(RULE_CONTENT)
        rule_paths.append(rule_file.strpath)

    # tests if number of overlaps for rules in RULESET found are correct.
    script_path = get_script_path("detect_duplicate_features.py")
    for expected_overlaps, rule_path in zip(rule_overlaps, rule_paths):
        args = [rule_dir.strpath, rule_path]
        overlaps_found = run_program(script_path, args)
        assert overlaps_found.returncode == expected_overlaps
