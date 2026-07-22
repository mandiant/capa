# Copyright 2026 Google LLC
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

import json
from pathlib import Path

import pytest

import capa.features.extractors.elf as elf

CD = Path(__file__).resolve().parent

ALGORITHM_FUNCTIONS = {
    "osabi": elf.guess_os_from_osabi,
    "ph_notes": elf.guess_os_from_ph_notes,
    "sh_notes": elf.guess_os_from_sh_notes,
    "ident_directive": elf.guess_os_from_ident_directive,
    "linker": elf.guess_os_from_linker,
    "abi_versions_needed": elf.guess_os_from_abi_versions_needed,
    "needed_dependencies": elf.guess_os_from_needed_dependencies,
    "symtab": elf.guess_os_from_symtab,
    "go_buildinfo": elf.guess_os_from_go_buildinfo,
    "go_source": elf.guess_os_from_go_source,
    "vdso_strings": elf.guess_os_from_vdso_strings,
}

FIXTURES_FILE = CD / "fixtures/elf/os-detection.json"
FIXTURES = json.loads(FIXTURES_FILE.read_text(encoding="utf-8"))


def _generate_algorithm_params():
    params = []
    for fixture in FIXTURES:
        path = fixture["path"]
        short_id = path[:8]
        algorithms = fixture.get("algorithms", {})
        for alg_name in ALGORITHM_FUNCTIONS:
            expected = algorithms.get(alg_name)
            test_id = f"{short_id}-{alg_name}"
            params.append(pytest.param(path, alg_name, expected, id=test_id))
    return params


def _generate_detection_params():
    return [pytest.param(f["path"], f["os"], id=f["path"][:8]) for f in FIXTURES]


@pytest.mark.parametrize("path,algorithm,expected", _generate_algorithm_params())
def test_elf_os_algorithm(path, algorithm, expected):
    with (CD / "data" / path).open("rb") as f:
        e = elf.ELF(f)
        result = ALGORITHM_FUNCTIONS[algorithm](e)
    if expected is None:
        assert result is None, f"{algorithm} should return None, got {result}"
    else:
        assert result is not None, f"{algorithm} should return {expected}, got None"
        assert result.value == expected


@pytest.mark.parametrize("path,expected_os", _generate_detection_params())
def test_elf_os_detection(path, expected_os):
    with (CD / "data" / path).open("rb") as f:
        assert elf.detect_elf_os(f) == expected_os
