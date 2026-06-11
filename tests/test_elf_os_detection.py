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

FIXTURES = json.loads(
    """
[
    {
        "path": "2f7f5fb5de175e770d7eae87666f9831.elf_",
        "os": "linux",
        "algorithms": {
            "sh_notes": "linux",
            "ident_directive": "linux",
            "vdso_strings": "linux"
        }
    },
    {
        "path": "7351f8a40c5450557b24622417fc478d.elf_",
        "os": "linux",
        "algorithms": {
            "ph_notes": "linux",
            "sh_notes": "linux",
            "ident_directive": "linux",
            "linker": "linux",
            "abi_versions_needed": "linux"
        }
    },
    {
        "path": "b5f0524e69b3a3cf636c7ac366ca57bf5e3a8fdc8a9f01caf196c611a7918a87.elf_",
        "os": "hurd",
        "algorithms": {
            "sh_notes": "hurd",
            "abi_versions_needed": "hurd",
            "needed_dependencies": "hurd"
        }
    },
    {
        "path": "bf7a9c8bdfa6d47e01ad2b056264acc3fd90cf43fe0ed8deec93ab46b47d76cb.elf_",
        "os": "hurd",
        "algorithms": {
            "sh_notes": "hurd",
            "abi_versions_needed": "hurd"
        }
    },
    {
        "path": "2bf18d0403677378adad9001b1243211.elf_",
        "os": "linux",
        "algorithms": {
            "symtab": "linux"
        }
    },
    {
        "path": "1038a23daad86042c66bfe6c9d052d27048de9653bde5750dc0f240c792d9ac8.elf_",
        "os": "android",
        "algorithms": {
            "ph_notes": "android",
            "needed_dependencies": "android"
        }
    },
    {
        "path": "3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_",
        "os": "linux",
        "algorithms": {
            "go_buildinfo": "linux",
            "go_source": "linux",
            "vdso_strings": "linux"
        }
    },
    {
        "path": "9486f2c5d514c1f39833b852ab03f4c0297e9e82b456b0dccad1a2d7d15c3385.elf_",
        "os": "freebsd",
        "algorithms": {
            "osabi": "freebsd"
        }
    },
    {
        "path": "a72ac9f1cf6cc01103765f866aae2dd85ea48208fb180c01076ca982684a4032.elf_",
        "os": "openbsd",
        "algorithms": {
            "osabi": "openbsd"
        }
    },
    {
        "path": "5e4263575796c6ea2445505a843e616111e0e540ec49441e3bb3fc99be7d3afb.elf_",
        "os": "hpux",
        "algorithms": {
            "osabi": "hpux"
        }
    },
    {
        "path": "ccb5eefc47d09672c6d62368a55f48a80259b1408b4f3d260b131d40b487f262.elf_",
        "os": "linux",
        "algorithms": {
            "ident_directive": "linux",
            "vdso_strings": "linux"
        }
    },
    {
        "path": "c2b2d7cea94179e6c2b6913205e37c45b67ccc0156d8f266548f7f1f95144285.elf_",
        "os": "linux",
        "algorithms": {
            "ph_notes": "linux",
            "linker": "linux"
        }
    },
    {
        "path": "fb5cf3df103336ca6b84a5d0f314bdd394ce7465adac3cf1914d390d62884582.elf_",
        "os": "freebsd",
        "algorithms": {
            "osabi": "freebsd",
            "go_source": "freebsd"
        }
    },
    {
        "path": "ef0ef9693ac433b768dc4cd260132788c3d95afa12addab711c15de61f3631bf.elf_",
        "os": "openbsd",
        "algorithms": {
            "osabi": "openbsd",
            "ph_notes": "openbsd",
            "sh_notes": "openbsd",
            "go_buildinfo": "openbsd"
        }
    }
]
"""
)


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
