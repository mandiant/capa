# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import json
import logging
import textwrap
import subprocess
from pathlib import Path
from datetime import date
from functools import lru_cache

import pytest

import capa.rules

logger = logging.getLogger(__name__)

CD = Path(__file__).resolve().parent


def get_script_path(s: str):
    return str(CD / ".." / "scripts" / s)


def get_file_path():
    return str(CD / "data" / "9324d1a8ae37a36ae560c37448c9705a.exe_")


def get_data_path(p: str):
    return str(CD / "data" / p)


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
            [get_data_path("9324d1a8ae37a36ae560c37448c9705a.exe_")],
            "yara/expected_9324d1a8ae37a36ae560c37448c9705a.exe_.yar",
        ),
        # Test match-2-yar x64 EXE
        pytest.param(
            "match-2-yar.py",
            [get_data_path("c2bb17c12975ea61ff43a71afd9c3ff111d018af161859abae0bdb0b3dae98f9.exe_")],
            "yara/expected_c2bb17c12975e.yar",
        ),
        # Test match-2-yar x86 .NET EXE
        pytest.param(
            "match-2-yar.py",
            [
                "-f",
                "dotnet",
                get_data_path("dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_"),
            ],
            "yara/expected_1c444ebeba24dcba8628b7dfe5fec7c6.exe_.yar",
        ),
        # Test match-2-yar files with multiple X86 PEs
        pytest.param(
            "match-2-yar.py",
            [
                get_data_path("Practical Malware Analysis Lab 03-04.exe_"),
                get_data_path("Practical Malware Analysis Lab 11-03.exe_"),
                get_data_path("Practical Malware Analysis Lab 16-01.exe_"),
            ],
            "yara/expected_pma_03-04.exe_11-03.exe_16-01.exe",
        ),
        # Test match-2-yar files with CAPA file limitations are filtered out of multi sample
        pytest.param(
            "match-2-yar.py",
            [
                get_data_path("Practical Malware Analysis Lab 01-01.exe_"),
                get_data_path("Practical Malware Analysis Lab 01-02.exe_"),
            ],
            "yara/expected_pma_01-01.exe_01-02.exe",
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
            "yara/expected_1c444ebe_692f7fd6.yar",
        ),
    ],
)
def test_script_expected_output(script, args, expected_output_path):
    script_path = get_script_path(script)

    expected_output = Path(get_data_path(expected_output_path)).read_bytes()
    # Update dates in expected output to be todays date
    expected_output = expected_output.replace(b"EXPECTED_DATE", date.today().isoformat().encode("utf8"))

    p = run_program(script_path, args)

    assert p.returncode == 0
    assert p.stdout.decode("utf8") == expected_output.decode("utf8")


def run_program(script_path, args):
    args = [sys.executable] + [script_path] + args
    logger.debug("running: %r", args)
    return subprocess.run(args, stdout=subprocess.PIPE)


@lru_cache(maxsize=1)
def get_match_2_yar_features(path, is_dotnet):
    script_path = get_script_path("match-2-yar.py")
    args = ["--dump-features", path]
    if is_dotnet:
        args.extend(["-f", "dotnet"])
    p = run_program(script_path, args)
    return p.stdout


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


# Rough outline for function extract bytes, function length, function masking
# Use importlib to import the script
# Use fixtures vivisect to get a vivisect workspace for a given path
# We can use known functions from the yara matches to extract out  length, bytes, and masked sig
@pytest.mark.parametrize(
    "path,is_dotnet,filemd5,addr,scope,expected_bytestring,expected_sig",
    [
        # Test match-2-yar x86 EXE - Basic Block Extraction
        pytest.param(
            get_data_path("9324d1a8ae37a36ae560c37448c9705a.exe_"),
            False,
            "9324d1a8ae37a36ae560c37448c9705a",
            0x004031A0,
            capa.rules.BASIC_BLOCK_SCOPE,
            "83 EC 10 B0 6C 8B 15 24 A0 40 00 88 44 24 01 88 44 24 02 B0 6F 8D 4C 24 00 88 44 24 04 88 44 24 0B 8B 44 24 14 C6 44 24 00 44 50 51 52 6A 00 C6 44 24 13 53 C6 44 24 15 72 C6 44 24 16 74 C6 44 24 17 57 C6 44 24 18 69 C6 44 24 19 6E C6 44 24 1A 64 C6 44 24 1C 77 C6 44 24 1D 00 E8 EF F7 FF FF A3 C4 A9 40 00 33 C0 83 C4 20 C2 04 00",
            "83 EC 10 B0 6C 8B 15 ?? ?? ?? ?? 88 44 24 ?? 88 44 24 ?? B0 6F 8D 4C 24 ?? 88 44 24 ?? 88 44 24 ?? 8B 44 24 ?? C6 44 24 ?? 44 50 51 52 6A 00 C6 44 24 ?? 53 C6 44 24 ?? 72 C6 44 24 ?? 74 C6 44 24 ?? 57 C6 44 24 ?? 69 C6 44 24 ?? 6E C6 44 24 ?? 64 C6 44 24 ?? 77 C6 44 24 ?? 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 83 C4 20 C2 04 00",
        ),
        # Test match-2-yar x86 EXE - Function Extraction
        pytest.param(
            get_data_path("9324d1a8ae37a36ae560c37448c9705a.exe_"),
            False,
            "9324d1a8ae37a36ae560c37448c9705a",
            0x004019C0,
            capa.rules.FUNCTION_SCOPE,
            "81 EC 7C 04 00 00 53 55 8B 2D 14 92 40 00 56 8B F1 57 6A 00 8D 44 24 14 8B 8E A8 00 00 00 6A 04 B3 02 50 51 C7 44 24 28 03 00 00 00 C7 44 24 2C 00 00 00 00 C6 44 24 20 05 88 5C 24 21 C6 44 24 22 00 88 5C 24 23 FF D5 B9 96 00 00 00 33 C0 8D BC 24 34 02 00 00 8B 96 A8 00 00 00 F3 AB 8D 44 24 18 8D 4C 24 2C 50 6A 00 6A 00 51 6A 00 89 54 24 44 C7 44 24 40 01 00 00 00 FF 15 10 92 40 00 85 C0 7F 0C 8B 96 A8 00 00 00 52 E9 5D 02 00 00 8B 8E A8 00 00 00 6A 00 8D 84 24 38 02 00 00 68 58 02 00 00 50 51 FF 15 0C 92 40 00 80 BC 24 34 02 00 00 05 0F 85 2C 02 00 00 8A 84 24 35 02 00 00 84 C0 74 0A 3A C3 0F 85 19 02 00 00 EB 08 3A C3 0F 85 30 01 00 00 8B 0D D4 AA 40 00 68 A0 A5 40 00 E8 49 2C 00 00 85 C0 0F 86 18 01 00 00 8B 0D D4 AA 40 00 68 A0 A5 40 00 E8 31 2C 00 00 8B 0D D4 AA 40 00 68 A0 A6 40 00 8B D8 E8 1F 2C 00 00 89 44 24 14 B9 40 00 00 00 33 C0 8D BC 24 30 01 00 00 F3 AB 66 AB 8B 3D 94 90 40 00 8D 94 24 32 01 00 00 68 A0 A5 40 00 52 C6 84 24 38 01 00 00 05 88 9C 24 39 01 00 00 FF D7 8D 44 24 14 6A 04 8D 8C 1C 36 01 00 00 50 51 8B 0D D4 AA 40 00 E8 3B 2A 00 00 8D 94 1C 33 01 00 00 68 A0 A6 40 00 52 FF D7 8B 44 24 14 6A 00 8D 94 24 34 01 00 00 8D 4C 18 03 8B 86 A8 00 00 00 51 52 50 FF D5 8D 54 24 18 33 C0 B9 96 00 00 00 8D BC 24 34 02 00 00 52 50 F3 AB 8B 8E A8 00 00 00 50 8D 44 24 38 89 4C 24 3C 50 6A 00 C7 44 24 40 01 00 00 00 FF 15 10 92 40 00 85 C0 0F 8E 18 01 00 00 8B 86 A8 00 00 00 6A 00 8D 94 24 38 02 00 00 68 58 02 00 00 52 50 FF 15 0C 92 40 00 80 BC 24 34 02 00 00 05 0F 85 EE 00 00 00 8A 84 24 35 02 00 00 84 C0 0F 85 DF 00 00 00 8B 94 24 90 04 00 00 52 FF 15 FC 91 40 00 85 C0 0F 84 D6 00 00 00 C6 44 24 20 05 C6 44 24 21 01 C6 44 24 22 00 C6 44 24 23 01 8B 40 0C 8B 08 8B 84 24 94 04 00 00 50 8B 11 89 54 24 28 FF 15 08 92 40 00 8B 96 A8 00 00 00 6A 00 8D 4C 24 24 6A 0A 51 52 66 89 44 24 38 FF D5 B9 96 00 00 00 33 C0 8D BC 24 34 02 00 00 8D 54 24 2C F3 AB 8B 86 A8 00 00 00 8D 4C 24 18 51 6A 00 6A 00 52 6A 00 89 44 24 44 C7 44 24 40 01 00 00 00 FF 15 10 92 40 00 85 C0 7F 09 8B 86 A8 00 00 00 50 EB 47 8B 96 A8 00 00 00 6A 00 8D 8C 24 38 02 00 00 68 58 02 00 00 51 52 FF 15 0C 92 40 00 80 BC 24 34 02 00 00 05 75 D1 8A 84 24 35 02 00 00 84 C0 75 C6 5F 5E 5D B0 01 5B 81 C4 7C 04 00 00 C2 08 00 8B 8E A8 00 00 00 51 FF 15 04 92 40 00 5F 5E 5D 32 C0 5B 81 C4 7C 04 00 00 C2 08 00",
            "81 EC 7C 04 00 00 53 55 8B 2D ?? ?? ?? ?? 56 8B F1 57 6A 00 8D 44 24 ?? 8B 8E ?? ?? ?? ?? 6A 04 B3 02 50 51 C7 44 24 ?? 03 00 00 00 C7 44 24 ?? 00 00 00 00 C6 44 24 ?? 05 88 5C 24 ?? C6 44 24 ?? 00 88 5C 24 ?? FF D5 B9 96 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? 8B 96 ?? ?? ?? ?? F3 AB 8D 44 24 ?? 8D 4C 24 ?? 50 6A 00 6A 00 51 6A 00 89 54 24 ?? C7 44 24 ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 7F ?? 8B 96 ?? ?? ?? ?? 52 E9 ?? ?? ?? ?? 8B 8E ?? ?? ?? ?? 6A 00 8D 84 24 ?? ?? ?? ?? 68 58 02 00 00 50 51 FF 15 ?? ?? ?? ?? 80 BC 24 ?? ?? ?? ?? 05 0F 85 ?? ?? ?? ?? 8A 84 24 ?? ?? ?? ?? 84 C0 74 ?? 3A C3 0F 85 ?? ?? ?? ?? EB ?? 3A C3 0F 85 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 A0 A5 40 00 E8 ?? ?? ?? ?? 85 C0 0F 86 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 A0 A5 40 00 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 A0 A6 40 00 8B D8 E8 ?? ?? ?? ?? 89 44 24 ?? B9 40 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? F3 AB 66 AB 8B 3D ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 68 A0 A5 40 00 52 C6 84 24 ?? ?? ?? ?? 05 88 9C 24 ?? ?? ?? ?? FF D7 8D 44 24 ?? 6A 04 8D 8C 1C ?? ?? ?? ?? 50 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 94 1C ?? ?? ?? ?? 68 A0 A6 40 00 52 FF D7 8B 44 24 ?? 6A 00 8D 94 24 ?? ?? ?? ?? 8D 4C 18 ?? 8B 86 ?? ?? ?? ?? 51 52 50 FF D5 8D 54 24 ?? 33 C0 B9 96 00 00 00 8D BC 24 ?? ?? ?? ?? 52 50 F3 AB 8B 8E ?? ?? ?? ?? 50 8D 44 24 ?? 89 4C 24 ?? 50 6A 00 C7 44 24 ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 0F 8E ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 6A 00 8D 94 24 ?? ?? ?? ?? 68 58 02 00 00 52 50 FF 15 ?? ?? ?? ?? 80 BC 24 ?? ?? ?? ?? 05 0F 85 ?? ?? ?? ?? 8A 84 24 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? C6 44 24 ?? 05 C6 44 24 ?? 01 C6 44 24 ?? 00 C6 44 24 ?? 01 8B 40 ?? 8B 08 8B 84 24 ?? ?? ?? ?? 50 8B 11 89 54 24 ?? FF 15 ?? ?? ?? ?? 8B 96 ?? ?? ?? ?? 6A 00 8D 4C 24 ?? 6A 0A 51 52 66 89 44 24 ?? FF D5 B9 96 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? 8D 54 24 ?? F3 AB 8B 86 ?? ?? ?? ?? 8D 4C 24 ?? 51 6A 00 6A 00 52 6A 00 89 44 24 ?? C7 44 24 ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 7F ?? 8B 86 ?? ?? ?? ?? 50 EB ?? 8B 96 ?? ?? ?? ?? 6A 00 8D 8C 24 ?? ?? ?? ?? 68 58 02 00 00 51 52 FF 15 ?? ?? ?? ?? 80 BC 24 ?? ?? ?? ?? 05 75 ?? 8A 84 24 ?? ?? ?? ?? 84 C0 75 ?? 5F 5E 5D B0 01 5B 81 C4 7C 04 00 00 C2 08 00 8B 8E ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 5F 5E 5D 32 C0 5B 81 C4 7C 04 00 00 C2 08 00",
        ),
        # Test match-2-yar x64 EXE - Basic Block Extraction
        pytest.param(
            get_data_path("c2bb17c12975ea61ff43a71afd9c3ff111d018af161859abae0bdb0b3dae98f9.exe_"),
            False,
            "50580ef0b882905316c4569162ea07d9",
            0x14000109F,
            capa.rules.BASIC_BLOCK_SCOPE,
            "33 C9 BA 1F 03 00 00 41 B8 00 10 00 00 44 8D 49 40 FF 15 4A 0F 00 00 41 B8 1F 03 00 00 48 8B D7 48 8B C8 48 8B D8 E8 65 0D 00 00 48 8D 0D 7F 11 00 00 C7 44 24 20 20 00 00 00 C7 44 24 24 01 00 00 00 48 C7 44 24 28 00 00 00 00 48 89 5C 24 30 48 C7 44 24 38 00 00 00 00 FF 15 0A 0F 00 00 4C 8D 44 24 20 48 8D 15 46 11 00 00 48 8D 0D 77 11 00 00 FF 15 F9 0E 00 00 33 C0 48 8B 4C 24 40 48 33 CC E8 2A 00 00 00 48 8B 5C 24 60 48 83 C4 50 5F C3",
            "33 C9 BA 1F 03 00 00 41 B8 00 10 00 00 44 8D 49 ?? FF 15 ?? ?? ?? ?? 41 B8 1F 03 00 00 48 8B D7 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? C7 44 24 ?? 20 00 00 00 C7 44 24 ?? 01 00 00 00 48 C7 44 24 ?? 00 00 00 00 48 89 5C 24 ?? 48 C7 44 24 ?? 00 00 00 00 FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C0 48 8B 4C 24 ?? 48 33 CC E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 50 5F C3",
        ),
        # Test match-2-yar x64 EXE - Function Extraction
        pytest.param(
            get_data_path("c2bb17c12975ea61ff43a71afd9c3ff111d018af161859abae0bdb0b3dae98f9.exe_"),
            False,
            "50580ef0b882905316c4569162ea07d9",
            0x140001010,
            capa.rules.FUNCTION_SCOPE,
            "48 89 5C 24 08 57 48 83 EC 50 48 8B 05 DF 1F 00 00 48 33 C4 48 89 44 24 40 66 0F 6F 15 8F 12 00 00 48 8D 3D 08 20 00 00 33 C9 B8 00 03 00 00 90 F3 0F 6F 04 39 66 0F EF C2 F3 0F 7F 04 39 F3 0F 6F 4C 39 10 66 0F EF CA F3 0F 7F 4C 39 10 F3 0F 6F 44 39 20 66 0F EF C2 F3 0F 7F 44 39 20 F3 0F 6F 44 39 30 66 0F EF C2 F3 0F 7F 44 39 30 48 83 C1 40 48 3B C8 7C B9 66 0F 1F 84 00 00 00 00 00 80 34 38 62 48 FF C0 48 3D 1F 03 00 00 7C F1 33 C9 BA 1F 03 00 00 41 B8 00 10 00 00 44 8D 49 40 FF 15 4A 0F 00 00 41 B8 1F 03 00 00 48 8B D7 48 8B C8 48 8B D8 E8 65 0D 00 00 48 8D 0D 7F 11 00 00 C7 44 24 20 20 00 00 00 C7 44 24 24 01 00 00 00 48 C7 44 24 28 00 00 00 00 48 89 5C 24 30 48 C7 44 24 38 00 00 00 00 FF 15 0A 0F 00 00 4C 8D 44 24 20 48 8D 15 46 11 00 00 48 8D 0D 77 11 00 00 FF 15 F9 0E 00 00 33 C0 48 8B 4C 24 40 48 33 CC E8 2A 00 00 00 48 8B 5C 24 60 48 83 C4 50 5F C3",
            "48 89 5C 24 ?? 57 48 83 EC 50 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 ?? 66 0F 6F 15 ?? ?? 00 00 48 8D 3D ?? ?? ?? ?? 33 C9 B8 00 03 00 00 90 F3 0F 6F 04 39 66 0F EF C2 F3 0F 7F 04 39 F3 0F 6F 4C 39 ?? 66 0F EF CA F3 0F 7F 4C 39 ?? F3 0F 6F 44 39 ?? 66 0F EF C2 F3 0F 7F 44 39 ?? F3 0F 6F 44 39 ?? 66 0F EF C2 F3 0F 7F 44 39 ?? 48 83 C1 40 48 3B C8 7C ?? 66 0F 1F 84 00 ?? ?? 00 00 80 34 38 62 48 FF C0 48 3D 1F 03 00 00 7C ?? 33 C9 BA 1F 03 00 00 41 B8 00 10 00 00 44 8D 49 ?? FF 15 ?? ?? ?? ?? 41 B8 1F 03 00 00 48 8B D7 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? C7 44 24 ?? 20 00 00 00 C7 44 24 ?? 01 00 00 00 48 C7 44 24 ?? 00 00 00 00 48 89 5C 24 ?? 48 C7 44 24 ?? 00 00 00 00 FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C0 48 8B 4C 24 ?? 48 33 CC E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 50 5F C3",
        ),
        # Test match-2-yar .NET EXE - Function Extraction
        pytest.param(
            get_data_path("dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_"),
            True,
            "1c444ebeba24dcba8628b7dfe5fec7c6",
            0x06000073,
            capa.rules.FUNCTION_SCOPE,
            "03 28 7D 00 00 06 0A 12 01 FE 15 0A 00 00 02 03 12 01 28 7F 00 00 06 26 12 01 7B 7B 00 00 04 12 01 7B 79 00 00 04 59 0C 12 01 7B 7C 00 00 04 12 01 7B 7A 00 00 04 59 0D 06 28 77 00 00 06 13 04 06 08 09 28 76 00 00 06 13 05 11 04 11 05 28 7A 00 00 06 13 06 11 04 16 16 08 09 06 16 16 20 20 00 CC 00 28 75 00 00 06 26 11 04 11 06 28 7A 00 00 06 26 11 04 28 78 00 00 06 26 03 06 28 7E 00 00 06 26 11 05 28 65 00 00 0A 13 07 11 05 28 79 00 00 06 26 11 07 2A",
            "03 28 ?? ?? ?? ?? 0A 12 ?? FE 15 ?? ?? ?? ?? 03 12 ?? 28 ?? ?? ?? ?? 26 12 ?? 7B ?? ?? ?? ?? 12 ?? 7B ?? ?? ?? ?? 59 0C 12 ?? 7B ?? ?? ?? ?? 12 ?? 7B ?? ?? ?? ?? 59 0D 06 28 ?? ?? ?? ?? 13 ?? 06 08 09 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 16 16 08 09 06 16 16 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 11 ?? 11 ?? 28 ?? ?? ?? ?? 26 11 ?? 28 ?? ?? ?? ?? 26 03 06 28 ?? ?? ?? ?? 26 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 26 11 ?? 2A",
        ),
    ],
)
def test_match2yar_feature_extraction(path, is_dotnet, filemd5, addr, scope, expected_bytestring, expected_sig):
    """Test extracting a function byte string using vivisect workspaces"""
    output = get_match_2_yar_features(path, is_dotnet)

    output = output.decode("utf8")
    output_data = json.loads(output)

    # Get data for filemd5:
    file_features = output_data[filemd5]

    # Filter for addr with correct scope
    addr_features = [x for x in file_features if x["addr"] == addr and x["scope"] == scope]

    # This should be unique
    assert len(addr_features) == 1

    # Check extraction and masking
    assert addr_features[0]["bytez"] == expected_bytestring
    assert addr_features[0]["sig"] == expected_sig
