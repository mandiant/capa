# Copyright 2023 Google LLC
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
import struct
from pathlib import Path

import fixtures
from elftools.elf.elffile import ELFFile

from capa.features.file import Export, Section
from capa.features.common import FORMAT_ELF, Format
from capa.features.extractors.elffile import ElfFeatureExtractor, extract_file_export_names, extract_file_import_names

SAMPLE_PATH = fixtures.CD / "data" / "055da8e6ccfe5a9380231ea04b850e18.elf_"
STRIPPED_SAMPLE_PATH = fixtures.CD / "data" / "bb38149ff4b5c95722b83f24ca27a42b.elf_"


def check_import_features(sample_path, expected_imports):
    path = Path(sample_path)
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    # Extract imports
    imports = list(extract_file_import_names(elf))

    # Verify that at least one import was found
    assert len(imports) > 0, "No imports were found."

    # Extract the symbol names from the extracted imports
    extracted_symbol_names = [imported[0].value for imported in imports]

    # Check if all expected symbol names are found
    for symbol_name in expected_imports:
        assert symbol_name in extracted_symbol_names, f"Symbol '{symbol_name}' not found in imports."


def check_export_features(sample_path, expected_exports):
    path = Path(sample_path)
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    # Extract imports
    exports = list(extract_file_export_names(elf))

    # Verify that at least one export was found
    assert len(exports) > 0, "No exports were found."

    # Extract the symbol names from the extracted imports
    extracted_symbol_names = [exported[0].value for exported in exports]

    # Check if all expected symbol names are found
    for symbol_name in expected_exports:
        assert symbol_name in extracted_symbol_names, f"Symbol '{symbol_name}' not found in exports."


def test_stripped_elffile_import_features():
    expected_imports = ["__cxa_atexit", "__cxa_finalize", "__stack_chk_fail", "fclose", "fopen", "__android_log_print"]
    check_import_features(STRIPPED_SAMPLE_PATH, expected_imports)


def test_stripped_elffile_export_features():
    expected_exports = [
        "_ZN7_JNIEnv14GetArrayLengthEP7_jarray",
        "Java_o_ac_a",
        "Java_o_ac_b",
        "_Z6existsPKc",
        "_ZN7_JNIEnv17GetStringUTFCharsEP8_jstringPh",
        "_ZN7_JNIEnv21GetObjectArrayElementEP13_jobjectArrayi",
        "_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc",
    ]
    check_export_features(STRIPPED_SAMPLE_PATH, expected_exports)


def test_elffile_import_features():
    expected_imports = [
        "memfrob",
        "puts",
        "__libc_start_main",
        "malloc",
        "__cxa_finalize",
    ]
    check_import_features(SAMPLE_PATH, expected_imports)


def test_elffile_export_features():
    expected_exports = [
        "deregister_tm_clones",
        "register_tm_clones",
        "__do_global_dtors_aux",
        "completed.8060",
        "__do_global_dtors_aux_fini_array_entry",
        "frame_dummy",
        "_init",
        "__libc_csu_fini",
        "_fini",
        "__dso_handle",
        "_IO_stdin_used",
        "__libc_csu_init",
    ]
    check_export_features(SAMPLE_PATH, expected_exports)


def test_elffile_invalid_utf8_dynamic_symbol_name(tmp_path: Path):
    # build a section-header-less ELF whose first dynamic symbol has a non-UTF-8
    # name (0xff) and whose second symbol has a valid name ("good").
    dyn_off, sym_off, str_off = 0xC0, 0x110, 0x180
    data = bytearray(0x300)
    data[0:16] = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    data[16:64] = (
        struct.pack("<HHI", 3, 0x3E, 1)
        + struct.pack("<QQQ", 0, 0x40, 0)
        + struct.pack("<IHHHHHH", 0, 64, 56, 2, 64, 0, 0)
    )
    data[0x40:0x78] = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x10000, 0x10000, 0x300, 0x300, 0x1000)
    data[0x78:0xB0] = struct.pack("<IIQQQQQQ", 2, 6, dyn_off, 0x10000 + dyn_off, 0x10000 + dyn_off, 0x50, 0x50, 8)
    data[dyn_off : dyn_off + 0x50] = (
        struct.pack("<qQ", 5, 0x10000 + str_off)
        + struct.pack("<qQ", 6, 0x10000 + sym_off)
        + struct.pack("<qQ", 11, 24)
        + struct.pack("<qQ", 10, 64)
        + struct.pack("<qQ", 0, 0)
    )
    data[sym_off : sym_off + 24] = struct.pack("<IBBHQQ", 2, 0x12, 0, 1, 0x2000, 0)
    data[sym_off + 24 : sym_off + 48] = struct.pack("<IBBHQQ", 8, 0x12, 0, 1, 0x3000, 0)
    data[str_off : str_off + 4] = b"\x00\x00\xff\x00"
    data[str_off + 8 : str_off + 13] = b"good\x00"

    path = tmp_path / "invalid_utf8_name.elf"
    path.write_bytes(bytes(data))

    extractor = ElfFeatureExtractor(path)
    features = list(extractor.extract_file_features())

    assert any(isinstance(feature, Format) and feature.value == FORMAT_ELF for feature, _ in features)
    assert any(isinstance(feature, Export) and feature.value == "good" for feature, _ in features)


def test_elffile_missing_shlink_section(tmp_path: Path):
    # build a minimal ELF whose .dynamic section points its sh_link at a
    # section header that doesn't exist (index 999).
    shstrtab = b"\x00.text\x00.shstrtab\x00.dynamic\x00"
    data = bytearray(0x200)
    data[0:16] = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    data[16:64] = (
        struct.pack("<HHI", 2, 0x3E, 1)
        + struct.pack("<QQQ", 0, 0, 0x100)
        + struct.pack("<IHHHHHH", 0, 64, 56, 0, 64, 4, 2)
    )
    data[0x40 : 0x40 + len(shstrtab)] = shstrtab

    def section_header(name, type_, flags, addr, offset, size, link, info, align, entsize):
        return struct.pack("<IIQQQQIIQQ", name, type_, flags, addr, offset, size, link, info, align, entsize)

    headers = [
        section_header(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        section_header(1, 1, 6, 0x1000, 0, 0, 0, 0, 1, 0),
        section_header(7, 3, 0, 0, 0x40, len(shstrtab), 0, 0, 1, 0),
        section_header(17, 6, 0, 0, 0, 0, 999, 0, 8, 0),
    ]
    for index, header in enumerate(headers):
        start = 0x100 + index * 64
        data[start : start + 64] = header

    path = tmp_path / "missing_shlink.elf"
    path.write_bytes(bytes(data))

    # capa must skip the unreadable section instead of aborting.
    extractor = ElfFeatureExtractor(path)
    features = list(extractor.extract_file_features())

    assert any(isinstance(feature, Format) and feature.value == FORMAT_ELF for feature, _ in features)
    assert any(isinstance(feature, Section) and feature.value == ".text" for feature, _ in features)
    assert extractor.get_base_address() is not None
