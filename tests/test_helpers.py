# Copyright 2020 Google LLC
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


import codecs

import capa.helpers
from capa.features.extractors import helpers


def test_all_zeros():
    a = b"\x00\x00\x00\x00"
    b = codecs.decode(b"00000000", "hex")
    c = b"\x01\x00\x00\x00"
    d = codecs.decode(b"01000000", "hex")
    assert helpers.all_zeros(a) is True
    assert helpers.all_zeros(b) is True
    assert helpers.all_zeros(c) is False
    assert helpers.all_zeros(d) is False


class TestIsAwFunction:
    """test the is_aw_function helper that detects A/W API variants."""

    def test_a_suffix(self):
        assert helpers.is_aw_function("CreateFileA") is True

    def test_w_suffix(self):
        assert helpers.is_aw_function("CreateFileW") is True

    def test_no_suffix(self):
        assert helpers.is_aw_function("WriteFile") is False

    def test_lowercase_a_suffix(self):
        # only uppercase A/W should match
        assert helpers.is_aw_function("somethinga") is False

    def test_lowercase_w_suffix(self):
        assert helpers.is_aw_function("somethingw") is False

    def test_single_char_a(self):
        # single character is too short to be an A/W function
        assert helpers.is_aw_function("A") is False

    def test_single_char_w(self):
        assert helpers.is_aw_function("W") is False

    def test_empty_string(self):
        assert helpers.is_aw_function("") is False

    def test_two_char_function(self):
        # two characters is the minimum length
        assert helpers.is_aw_function("xA") is True
        assert helpers.is_aw_function("xW") is True

    def test_longer_w_suffix(self):
        assert helpers.is_aw_function("LoadLibraryExW") is True

    def test_ends_with_non_aw(self):
        assert helpers.is_aw_function("CreateFileB") is False


class TestIsOrdinal:
    """test the is_ordinal helper that detects #-prefixed ordinal imports."""

    def test_ordinal(self):
        assert helpers.is_ordinal("#1") is True

    def test_multi_digit_ordinal(self):
        assert helpers.is_ordinal("#123") is True

    def test_regular_symbol(self):
        assert helpers.is_ordinal("CreateFile") is False

    def test_empty_string(self):
        assert helpers.is_ordinal("") is False

    def test_hash_only(self):
        assert helpers.is_ordinal("#") is True

    def test_no_hash_prefix(self):
        assert helpers.is_ordinal("1") is False


class TestGenerateSymbols:
    """test the generate_symbols function that produces API name variants."""

    # --- DLL extension stripping ---

    def test_dll_extension_stripped(self):
        """DLL extension should be stripped and results equivalent."""
        assert list(
            helpers.generate_symbols("name.dll", "api", include_dll=True)
        ) == list(helpers.generate_symbols("name", "api", include_dll=True))
        assert list(
            helpers.generate_symbols("name.dll", "api", include_dll=False)
        ) == list(helpers.generate_symbols("name", "api", include_dll=False))

    def test_drv_extension_stripped(self):
        """Driver extensions (.drv) should be stripped like .dll."""
        assert list(
            helpers.generate_symbols("winspool.drv", "OpenPrinterA", include_dll=True)
        ) == list(
            helpers.generate_symbols("winspool", "OpenPrinterA", include_dll=True)
        )

    def test_so_extension_stripped(self):
        """Shared object extensions (.so) should be stripped."""
        assert list(
            helpers.generate_symbols("libc.so", "printf", include_dll=True)
        ) == list(helpers.generate_symbols("libc", "printf", include_dll=True))

    # --- DLL name case normalization ---

    def test_uppercase_dll_normalized(self):
        """DLL names should be lowercased."""
        symbols = list(
            helpers.generate_symbols("KERNEL32", "WriteFile", include_dll=True)
        )
        assert "kernel32.WriteFile" in symbols
        # should not contain uppercase DLL
        assert "KERNEL32.WriteFile" not in symbols

    def test_mixed_case_dll_normalized(self):
        """Mixed case DLL names should be lowercased."""
        symbols = list(
            helpers.generate_symbols("Kernel32.DLL", "WriteFile", include_dll=True)
        )
        assert "kernel32.WriteFile" in symbols

    # --- A/W import with include_dll=True ---

    def test_aw_import_with_dll(self):
        symbols = list(
            helpers.generate_symbols("kernel32", "CreateFileA", include_dll=True)
        )
        assert len(symbols) == 4
        assert "kernel32.CreateFileA" in symbols
        assert "kernel32.CreateFile" in symbols
        assert "CreateFileA" in symbols
        assert "CreateFile" in symbols

    def test_aw_import_w_variant_with_dll(self):
        symbols = list(
            helpers.generate_symbols("kernel32", "CreateFileW", include_dll=True)
        )
        assert len(symbols) == 4
        assert "kernel32.CreateFileW" in symbols
        assert "kernel32.CreateFile" in symbols
        assert "CreateFileW" in symbols
        assert "CreateFile" in symbols

    # --- Regular import with include_dll=True ---

    def test_regular_import_with_dll(self):
        symbols = list(
            helpers.generate_symbols("kernel32", "WriteFile", include_dll=True)
        )
        assert len(symbols) == 2
        assert "kernel32.WriteFile" in symbols
        assert "WriteFile" in symbols

    # --- Ordinal import with include_dll=True ---

    def test_ordinal_import_with_dll(self):
        symbols = list(helpers.generate_symbols("ws2_32", "#1", include_dll=True))
        assert len(symbols) == 1
        assert "ws2_32.#1" in symbols

    # --- A/W api with include_dll=False ---

    def test_aw_api_without_dll(self):
        symbols = list(
            helpers.generate_symbols("kernel32", "CreateFileA", include_dll=False)
        )
        assert len(symbols) == 2
        assert "CreateFileA" in symbols
        assert "CreateFile" in symbols

    # --- Regular api with include_dll=False ---

    def test_regular_api_without_dll(self):
        symbols = list(
            helpers.generate_symbols("kernel32", "WriteFile", include_dll=False)
        )
        assert len(symbols) == 1
        assert "WriteFile" in symbols

    # --- Ordinal api with include_dll=False (still includes DLL prefix for context) ---

    def test_ordinal_api_without_dll(self):
        symbols = list(helpers.generate_symbols("ws2_32", "#1", include_dll=False))
        assert len(symbols) == 1
        assert "ws2_32.#1" in symbols

    # --- Empty DLL name (dynamic analysis backends: CAPE, VMRay, Drakvuf) ---

    def test_empty_dll_aw_api(self):
        """Dynamic analysis backends may pass empty DLL name."""
        symbols = list(helpers.generate_symbols("", "CreateFileA"))
        assert "CreateFileA" in symbols
        assert "CreateFile" in symbols

    def test_empty_dll_regular_api(self):
        symbols = list(helpers.generate_symbols("", "WriteFile"))
        assert "WriteFile" in symbols


class TestReformatForwardedExportName:
    """test the reformat_forwarded_export_name helper for forwarded exports."""

    def test_simple_forward(self):
        """DLL part should be lowercased, symbol kept verbatim."""
        result = helpers.reformat_forwarded_export_name("NTDLL.RtlAllocateHeap")
        assert result == "ntdll.RtlAllocateHeap"

    def test_already_lowercase(self):
        result = helpers.reformat_forwarded_export_name("ntdll.RtlAllocateHeap")
        assert result == "ntdll.RtlAllocateHeap"

    def test_api_ms_dll(self):
        """DLL names with dashes and multiple segments should be lowercased correctly."""
        result = helpers.reformat_forwarded_export_name(
            "api-ms-win-core-synch-l1-1-0.SleepEx"
        )
        assert result == "api-ms-win-core-synch-l1-1-0.SleepEx"

    def test_full_path_forward(self):
        """Forwarded names can include full paths with embedded periods.

        rpartition should split on the *last* period, keeping the path intact.
        """
        result = helpers.reformat_forwarded_export_name(
            "C:\\Windows\\System32\\NTDLL.RtlFreeHeap"
        )
        assert result == "c:\\windows\\system32\\ntdll.RtlFreeHeap"

    def test_mixed_case_symbol_preserved(self):
        """The symbol name (after last dot) should not be modified."""
        result = helpers.reformat_forwarded_export_name("ADVAPI32.RegOpenKeyExW")
        assert result == "advapi32.RegOpenKeyExW"


class TestXorStatic:
    """test the xor_static helper used for PE carving."""

    def test_xor_with_zero(self):
        """XOR with 0 should return the same bytes."""
        data = b"MZ\x90\x00"
        assert helpers.xor_static(data, 0) == data

    def test_xor_with_ff(self):
        """XOR with 0xFF should invert all bytes."""
        data = b"\x00\x01\x02\x03"
        result = helpers.xor_static(data, 0xFF)
        assert result == b"\xff\xfe\xfd\xfc"

    def test_xor_roundtrip(self):
        """XOR applied twice with the same key should return original bytes."""
        data = b"Hello, World!"
        key = 0x42
        assert helpers.xor_static(helpers.xor_static(data, key), key) == data

    def test_xor_empty(self):
        """XOR of empty bytes should return empty bytes."""
        assert helpers.xor_static(b"", 0x42) == b""


class TestTwosComplement:
    """test the twos_complement helper for signed integer conversion."""

    def test_positive_value(self):
        """Positive values within range should stay positive."""
        assert helpers.twos_complement(1, 8) == 1
        assert helpers.twos_complement(127, 8) == 127

    def test_negative_value(self):
        """Values with the sign bit set should become negative."""
        # 0x80 = 128 in 8-bit is -128
        assert helpers.twos_complement(0x80, 8) == -128
        # 0xFF = 255 in 8-bit is -1
        assert helpers.twos_complement(0xFF, 8) == -1

    def test_zero(self):
        assert helpers.twos_complement(0, 8) == 0
        assert helpers.twos_complement(0, 32) == 0

    def test_32bit(self):
        # 0x80000000 in 32-bit is -2147483648
        assert helpers.twos_complement(0x80000000, 32) == -2147483648
        # 0xFFFFFFFF in 32-bit is -1
        assert helpers.twos_complement(0xFFFFFFFF, 32) == -1

    def test_16bit(self):
        assert helpers.twos_complement(0x7FFF, 16) == 32767
        assert helpers.twos_complement(0x8000, 16) == -32768


class TestCarvePe:
    """test the carve_pe helper for finding embedded PE files."""

    def test_empty_buffer(self):
        """Empty buffer should yield no results."""
        assert list(helpers.carve_pe(b"")) == []

    def test_no_pe(self):
        """Buffer without MZ header should yield no results."""
        assert list(helpers.carve_pe(b"\x00" * 1024)) == []

    def test_truncated_mz(self):
        """Buffer with MZ but too short for e_lfanew should yield no results."""
        assert list(helpers.carve_pe(b"MZ" + b"\x00" * 10)) == []


def test_is_dev_environment():
    # testing environment should be a dev environment
    assert capa.helpers.is_dev_environment() is True
