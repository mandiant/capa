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


import os
import sys
import logging
import textwrap
import subprocess
from pathlib import Path

import pytest

import capa.rules

logger = logging.getLogger(__name__)

CD = Path(__file__).resolve().parent


def get_script_path(s: str):
    return str(CD / ".." / "scripts" / s)


def get_binary_file_path():
    return str(CD / "data" / "9324d1a8ae37a36ae560c37448c9705a.exe_")


def get_cape_report_file_path():
    return str(
        CD
        / "data"
        / "dynamic"
        / "cape"
        / "v2.4"
        / "fb7ade52dc5a1d6128b9c217114a46d0089147610f99f5122face29e429a1e74.json.gz"
    )


def get_binexport2_file_path():
    return str(CD / "data" / "binexport2" / "mimikatz.exe_.ghidra.BinExport")


def get_rules_path():
    return str(CD / ".." / "rules")


def get_rule_path():
    return str(Path(get_rules_path()) / "lib" / "allocate-memory.yml")


@pytest.mark.parametrize(
    "script,args",
    [
        pytest.param("capa2yara.py", [get_rules_path()]),
        pytest.param("capafmt.py", [get_rule_path()]),
        pytest.param(
            "capa2sarif.py",
            [Path(__file__).resolve().parent / "data" / "rd" / "Practical Malware Analysis Lab 01-01.dll_.json"],
        ),
        # testing some variations of linter script
        pytest.param("lint.py", ["-t", "create directory", get_rules_path()]),
        # `create directory` rule has native and .NET example PEs
        pytest.param("lint.py", ["--thorough", "-t", "create directory", get_rules_path()]),
        pytest.param("match-function-id.py", [get_binary_file_path()]),
        pytest.param("show-capabilities-by-function.py", [get_binary_file_path()]),
        pytest.param("show-features.py", [get_binary_file_path()]),
        pytest.param("show-features.py", ["-F", "0x407970", get_binary_file_path()]),
        pytest.param("show-features.py", ["-P", "MicrosoftEdgeUpdate.exe", get_cape_report_file_path()]),
        pytest.param("show-unused-features.py", [get_binary_file_path()]),
        pytest.param("capa-as-library.py", [get_binary_file_path()]),
        # not testing "minimize-vmray-results.py" as we don't currently upload full VMRay analysis archives
    ],
)
def test_scripts(script, args):
    script_path = get_script_path(script)
    p = run_program(script_path, args)
    assert p.returncode == 0


@pytest.mark.parametrize(
    "script,args",
    [
        pytest.param("inspect-binexport2.py", [get_binexport2_file_path()]),
        pytest.param("detect-binexport2-capabilities.py", [get_binexport2_file_path()]),
    ],
)
def test_binexport_scripts(script, args):
    # define sample bytes location
    os.environ["CAPA_SAMPLES_DIR"] = str(Path(CD / "data"))

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


def run_program(script_path, args):
    args = [sys.executable] + [script_path] + args
    logger.debug("running: %r", args)
    return subprocess.run(args, stdout=subprocess.PIPE)


@pytest.mark.xfail(reason="result document test files haven't been updated yet")
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
    TEST_RULE_0 = textwrap.dedent("""
        rule:
            meta:
                name: Test Rule 0
                scopes:
                    static: function
                    dynamic: process
            features:
              - and:
                - number: 1
                - not:
                  - string: process
        """)

    TEST_RULESET = {
        "rule_1": textwrap.dedent("""
                rule:
                    meta:
                        name: Test Rule 1
                        scopes:
                            static: function
                            dynamic: process
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
            """),
        "rule_2": textwrap.dedent("""
                rule:
                    meta:
                        name: Test Rule 2
                        scopes:
                            static: function
                            dynamic: process
                    features:
                      - and:
                        - string: "sites.ini"
                        - basic block:
                          - and:
                            - api: CreateFile
                            - mnemonic: xor
            """),
        "rule_3": textwrap.dedent("""
                rule:
                    meta:
                        name: Test Rule 3
                        scopes:
                            static: function
                            dynamic: process
                    features:
                      - and:
                        - not:
                          - number: 4
                        - basic block:
                          - and:
                            - api: bind
                            - number: 2
            """),
    }

    rule_overlaps = [0, 4, 3, 3]

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


def test_missing_static_dynamic_scope_no_crash_when_scopes_absent():
    sys.path.insert(0, str(CD / ".." / "scripts"))
    import lint as lint_module

    import capa.engine
    import capa.features.common

    scopes = capa.rules.Scopes(static=capa.rules.Scope.FUNCTION, dynamic=capa.rules.Scope.PROCESS)
    statement = capa.engine.And([])
    rule = capa.rules.Rule("test rule no scopes", scopes, statement, {"name": "test rule no scopes"})

    ctx = lint_module.Context(samples={}, rules=capa.rules.RuleSet([]), is_thorough=False)
    assert lint_module.MissingStaticScope().check_rule(ctx, rule) is False
    assert lint_module.MissingDynamicScope().check_rule(ctx, rule) is False


def test_missing_example_offset_uses_scopes():
    sys.path.insert(0, str(CD / ".." / "scripts"))
    import lint as lint_module

    lint_instance = lint_module.MissingExampleOffset()
    ctx = lint_module.Context(samples={}, rules=capa.rules.RuleSet([]), is_thorough=False)

    function_scope_rule_missing_offset = capa.rules.Rule.from_yaml(
        textwrap.dedent("""
            rule:
                meta:
                    name: test rule function scope no offset
                    scopes:
                        static: function
                        dynamic: process
                    examples:
                        - 9324d1a8ae37a36ae560c37448c9705a.exe_
                features:
                    - api: CreateFile
        """)
    )
    assert lint_instance.check_rule(ctx, function_scope_rule_missing_offset) is True

    function_scope_rule_with_offset = capa.rules.Rule.from_yaml(
        textwrap.dedent("""
            rule:
                meta:
                    name: test rule function scope with offset
                    scopes:
                        static: function
                        dynamic: process
                    examples:
                        - 9324d1a8ae37a36ae560c37448c9705a.exe_:0x407970
                features:
                    - api: CreateFile
        """)
    )
    assert lint_instance.check_rule(ctx, function_scope_rule_with_offset) is not True

    file_scope_rule_no_offset = capa.rules.Rule.from_yaml(
        textwrap.dedent("""
            rule:
                meta:
                    name: test rule file scope no offset
                    scopes:
                        static: file
                        dynamic: process
                    examples:
                        - 9324d1a8ae37a36ae560c37448c9705a.exe_
                features:
                    - api: CreateFile
        """)
    )
    assert lint_instance.check_rule(ctx, file_scope_rule_no_offset) is not True
