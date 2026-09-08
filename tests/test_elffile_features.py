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
from pathlib import Path

import fixtures
import pytest
from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile

from capa.features.extractors.elffile import extract_file_export_names, extract_file_import_names

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


class _RaisingDynamicSegment(DynamicSegment):
    """A dynamic segment whose tables cannot be read.

    pyelftools reaches for companion tags with bare next() calls and sizes the
    symbol table from a hash section that may have been stripped, so a malformed
    file raises out of these two methods rather than returning nothing.
    """

    def __init__(self, exception):
        self.exception = exception

    def get_table_offset(self, name):
        # DT_SYMTAB is present; it is the tables read off it that are broken.
        return (0x1000, 0x1000)

    def num_symbols(self):
        # This is where the DT_GNU_HASH failure actually surfaces: pyelftools
        # resolves the count through the hash table.
        raise self.exception

    def iter_symbols(self):
        raise self.exception
        yield  # pragma: no cover - unreachable, keeps this a generator

    def get_relocation_tables(self):
        raise self.exception


@pytest.mark.parametrize(
    "exception",
    [
        # DT_GNU_HASH left pointing at a zeroed region, capa#3170
        ValueError("max() iterable argument is empty"),
        # a relocation table tag with no companion size tag, capa#3171. The bare
        # StopIteration is what escapes pyelftools; PEP 479 only rewrites it
        # into a RuntimeError at the generator boundary above the call site.
        StopIteration(),
        RuntimeError("generator raised StopIteration"),
        ELFError("bad section header"),
    ],
    ids=["gnu-hash", "stop-iteration", "runtime-error", "elf-error"],
)
def test_malformed_dynamic_segment_does_not_abort(exception, monkeypatch):
    segment = _RaisingDynamicSegment(exception)

    class FakeELF:
        def iter_sections(self):
            return iter(())

        def iter_segments(self):
            return iter((segment,))

    # A file capa cannot fully parse should yield no exports or imports rather
    # than ending the run, since the remaining features are still extractable.
    assert list(extract_file_export_names(FakeELF())) == []
    assert list(extract_file_import_names(FakeELF())) == []
