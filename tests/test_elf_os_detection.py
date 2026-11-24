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

import io
import json
import struct
from pathlib import Path

import pytest

import capa.features.extractors.elf as elf
import capa.features.extractors.common

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


def _make_elf64(e_phoff: int = 0, e_shoff: int = 0, sections: tuple[tuple[int, int], ...] = ()) -> bytes:
    """
    build a minimal little-endian ELF64 (x86-64) header,
    optionally followed by section headers, given as (sh_offset, sh_size) pairs.
    """
    header = bytearray(0x40)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # ELFDATA2LSB
    header[6] = 1  # EV_CURRENT
    struct.pack_into("<HHI", header, 0x10, 2, 0x3E, 1)  # ET_EXEC, EM_X86_64, EV_CURRENT
    if sections and not e_shoff:
        e_shoff = len(header)
    struct.pack_into("<QQ", header, 0x20, e_phoff, e_shoff)
    # e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    struct.pack_into("<HHHHHH", header, 0x34, 0x40, 0x38, 1 if e_phoff else 0, 0x40, len(sections), 0)

    shdrs = b"".join(
        # sh_name, sh_type=SHT_PROGBITS, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
        struct.pack("<IIQQQQIIQQ", 0, 1, 0, 0, sh_offset, sh_size, 0, 0, 1, 0)
        for sh_offset, sh_size in sections
    )
    return bytes(header) + shdrs


@pytest.mark.parametrize("field", ["e_phoff", "e_shoff"])
@pytest.mark.parametrize("value", [0x8000000000000000, 0xFFFFFFFFFFFFFFFF])
def test_elf_huge_header_table_offset(field, value):
    # offsets beyond what seek() supports must be treated like any other out-of-bounds offset,
    # not crash capa with an OverflowError: the architecture is still known from the ELF header.
    buf = _make_elf64(**{field: value})
    assert elf.detect_elf_arch(io.BytesIO(buf)) == "amd64"
    assert elf.detect_elf_os(io.BytesIO(buf)) == "unknown"
    assert [f.value for f, _ in capa.features.extractors.common.extract_arch(buf)] == ["amd64"]


def test_elf_huge_section_offset_and_size():
    # an unreadable section is skipped, and the remaining sections are still parsed.
    buf = _make_elf64(sections=((0xFFFFFFFFFFFFFFFF, 0x10), (0x0, 0xFFFFFFFFFFFFFFFF), (0x0, 0x4)))
    e = elf.ELF(io.BytesIO(buf))
    assert [shdr.buf for shdr in e.section_headers] == [b"\x7fELF"]
