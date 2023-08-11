# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import logging
import textwrap
import subprocess
from datetime import date
from pathlib import Path

import pytest

logger = logging.getLogger(__name__)

CD = Path(__file__).resolve().parent


def get_script_path(s: str):
    return str(CD / ".." / "scripts" / s)


def get_file_path():
    return str(CD / "data" / "9324d1a8ae37a36ae560c37448c9705a.exe_")

def get_data_path(p: str):
    return str(CD / "data" / p )

def get_rules_path():
    return str(CD / ".." / "rules")


def get_rule_path():
    return str(Path(get_rules_path()) / "lib" / "allocate-memory.yml")


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
        pytest.param("show-unused-features.py", [get_file_path()]),
        pytest.param("capa_as_library.py", [get_file_path()]),
    ],
)
def test_scripts(script, args):
    script_path = get_script_path(script)
    p = run_program(script_path, args)
    assert p.returncode == 0


def test_bulk_process(tmp_path):
    # create test directory to recursively analyze
    t = tmp_path / "test"
    t.mkdir()

    source_file = Path(__file__).resolve().parent / "data" / "ping_täst.exe_"
    dest_file = t / "test.exe_"

    dest_file.write_bytes(source_file.read_bytes())

    p = run_program(get_script_path("bulk-process.py"), [str(t.parent)])
    assert p.returncode == 0

@pytest.mark.parametrize(
    "script,args,expected_output_path",
    [
        # Test match-2-yar x86 EXE
        pytest.param(
            "match-2-yar.py", 
            [
                get_data_path("9324d1a8ae37a36ae560c37448c9705a.exe_")
            ], 
            "yara/expected_9324d1a8ae37a36ae560c37448c9705a.exe_.yar"
        ),
        # Test match-2-yar x64 EXE
        pytest.param(
            "match-2-yar.py", 
            [
                get_data_path("c2bb17c12975ea61ff43a71afd9c3ff111d018af161859abae0bdb0b3dae98f9.exe_")
            ], 
            "yara/expected_c2bb17c12975e.yar"
        ),
        # Test match-2-yar x86 .NET EXE
        pytest.param(
            "match-2-yar.py", 
            [
                "-f", 
                "dotnet", 
                get_data_path("dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_"),

            ], 
            "yara/expected_1c444ebeba24dcba8628b7dfe5fec7c6.exe_.yar"
        ),
        # Test match-2-yar files with multiple X86 PEs
        pytest.param(
            "match-2-yar.py", 
            [ 
                get_data_path("Practical Malware Analysis Lab 03-04.exe_"),
                get_data_path("Practical Malware Analysis Lab 11-03.exe_"),
                get_data_path("Practical Malware Analysis Lab 16-01.exe_")
            ], 
            "yara/expected_pma_03-04.exe_11-03.exe_16-01.exe"
        ),
        # Test match-2-yar files with CAPA file limitations are filtered out of multi sample
        pytest.param(
            "match-2-yar.py", 
            [ 
                get_data_path("Practical Malware Analysis Lab 01-01.exe_"),
                get_data_path("Practical Malware Analysis Lab 01-02.exe_")
            ], 
            "yara/expected_pma_01-01.exe_01-02.exe"
        ),
        
        # Test match-2-yar multiple x86 .NET PE
        pytest.param(
            "match-2-yar.py", 
            [
                "-f", 
                "dotnet", 
                get_data_path("dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_"),
                get_data_path("dotnet/692f7fd6d198e804d6af98eb9e390d61.exe_"),

            ], 
            "yara/expected_1c444ebe_692f7fd6.yar"
        ),
    ],
)
def test_script_expected_output(script, args, expected_output_path):
    script_path = get_script_path(script)
    with open(get_data_path(expected_output_path), 'rb') as f:
        expected_output = f.read()
    
    # Update dates in expected output to be todays date
    dates_to_replace = [
        b"2023-08-10",
    ]
    for dt in dates_to_replace:
        expected_output = expected_output.replace(dt, date.today().isoformat().encode('utf8'))

    p = run_program(script_path, args)

    assert p.returncode == 0
    assert p.stdout.decode('utf8') == expected_output.decode('utf8')
    

def run_program(script_path, args):
    args = [sys.executable] + [script_path] + args
    logger.debug("running: %r", args)
    return subprocess.run(args, stdout=subprocess.PIPE)


def test_proto_conversion(tmp_path):
    t = tmp_path / "proto-test"
    t.mkdir()
    json_file = Path(__file__).resolve().parent / "data" / "rd" / "Practical Malware Analysis Lab 01-01.dll_.json"

    p = run_program(get_script_path("proto-from-results.py"), [json_file])
    assert p.returncode == 0

    pb_file = t / "pma.pb"
    pb_file.write_bytes(p.stdout)

    p = run_program(get_script_path("proto-to-results.py"), [pb_file])
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
