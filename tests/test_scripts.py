# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import sys
import subprocess

import pytest

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
    print("running: '%s'" % args)
    return subprocess.run(args)
