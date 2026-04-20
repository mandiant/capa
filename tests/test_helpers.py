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
from capa.rules import trim_dll_part
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


def test_is_aw_function():
    # A-suffixed function
    assert helpers.is_aw_function("CreateFileA") is True
    # W-suffixed function
    assert helpers.is_aw_function("CreateFileW") is True
    # longer name ending with W
    assert helpers.is_aw_function("LoadLibraryExW") is True

    # does not end with A or W
    assert helpers.is_aw_function("WriteFile") is False
    assert helpers.is_aw_function("recv") is False

    # too short (length < 2)
    assert helpers.is_aw_function("A") is False
    assert helpers.is_aw_function("W") is False
    assert helpers.is_aw_function("") is False


def test_is_ordinal():
    # ordinal symbols start with #
    assert helpers.is_ordinal("#1") is True
    assert helpers.is_ordinal("#42") is True

    # normal symbol names
    assert helpers.is_ordinal("CreateFileA") is False

    # empty string
    assert helpers.is_ordinal("") is False

    # # not at the start
    assert helpers.is_ordinal("foo#1") is False


def test_generate_symbols():
    # .dll extension is stripped
    assert list(helpers.generate_symbols("name.dll", "api", include_dll=True)) == list(
        helpers.generate_symbols("name", "api", include_dll=True)
    )
    assert list(helpers.generate_symbols("name.dll", "api", include_dll=False)) == list(
        helpers.generate_symbols("name", "api", include_dll=False)
    )

    # .drv extension is stripped
    assert list(helpers.generate_symbols("winspool.drv", "OpenPrinterA", include_dll=True)) == list(
        helpers.generate_symbols("winspool", "OpenPrinterA", include_dll=True)
    )

    # .so extension is stripped
    assert list(helpers.generate_symbols("libc.so", "printf", include_dll=True)) == list(
        helpers.generate_symbols("libc", "printf", include_dll=True)
    )

    # uppercase DLL name is lowercased
    symbols = list(helpers.generate_symbols("KERNEL32", "CreateFileA", include_dll=True))
    assert "kernel32.CreateFileA" in symbols
    assert "KERNEL32.CreateFileA" not in symbols

    # A/W import
    symbols = list(helpers.generate_symbols("kernel32", "CreateFileA", include_dll=True))
    assert len(symbols) == 4
    assert "kernel32.CreateFileA" in symbols
    assert "kernel32.CreateFile" in symbols
    assert "CreateFileA" in symbols
    assert "CreateFile" in symbols

    # W-suffixed import
    symbols = list(helpers.generate_symbols("kernel32", "CreateFileW", include_dll=True))
    assert len(symbols) == 4
    assert "kernel32.CreateFileW" in symbols
    assert "kernel32.CreateFile" in symbols
    assert "CreateFileW" in symbols
    assert "CreateFile" in symbols

    # import (non-A/W)
    symbols = list(helpers.generate_symbols("kernel32", "WriteFile", include_dll=True))
    assert len(symbols) == 2
    assert "kernel32.WriteFile" in symbols
    assert "WriteFile" in symbols

    # ordinal import
    symbols = list(helpers.generate_symbols("ws2_32", "#1", include_dll=True))
    assert len(symbols) == 1
    assert "ws2_32.#1" in symbols

    # A/W api (no DLL prefix in output)
    symbols = list(helpers.generate_symbols("kernel32", "CreateFileA", include_dll=False))
    assert len(symbols) == 2
    assert "CreateFileA" in symbols
    assert "CreateFile" in symbols

    # api (non-A/W, no DLL prefix in output)
    symbols = list(helpers.generate_symbols("kernel32", "WriteFile", include_dll=False))
    assert len(symbols) == 1
    assert "WriteFile" in symbols

    # ordinal api (DLL prefix always included for ordinals)
    symbols = list(helpers.generate_symbols("ws2_32", "#1", include_dll=False))
    assert len(symbols) == 1
    assert "ws2_32.#1" in symbols


def test_trim_dll_part():
    # normal DLL.API: strip DLL prefix
    assert trim_dll_part("kernel32.CreateFileA") == "CreateFileA"

    # ordinal import: keep as-is
    assert trim_dll_part("ws2_32.#1") == "ws2_32.#1"

    # .NET namespace with :: keep as-is
    assert trim_dll_part("System.Convert::FromBase64String") == "System.Convert::FromBase64String"

    # .NET multi-dot namespace with :: keep as-is
    assert trim_dll_part("System.Diagnostics.Debugger::IsLogging") == "System.Diagnostics.Debugger::IsLogging"

    # no dot: unchanged
    assert trim_dll_part("CreateFileA") == "CreateFileA"

    # multiple dots (count > 1), no :: unchanged
    assert trim_dll_part("a.b.c.CreateFile") == "a.b.c.CreateFile"


def test_reformat_forwarded_export_name():
    # uppercase DLL is lowercased, symbol is preserved verbatim
    assert helpers.reformat_forwarded_export_name("NTDLL.RtlAllocateHeap") == "ntdll.RtlAllocateHeap"

    # already lowercase
    assert helpers.reformat_forwarded_export_name("kernel32.HeapAlloc") == "kernel32.HeapAlloc"

    # DLL name with hyphens
    assert (
        helpers.reformat_forwarded_export_name("api-ms-win-core-file-l1-1-0.CreateFileW")
        == "api-ms-win-core-file-l1-1-0.CreateFileW"
    )

    # full path with embedded dots: rpartition splits on last dot
    assert (
        helpers.reformat_forwarded_export_name("C:\\Windows\\NTDLL.RtlAllocateHeap")
        == "c:\\windows\\ntdll.RtlAllocateHeap"
    )


def test_is_dev_environment():
    # testing environment should be a dev environment
    assert capa.helpers.is_dev_environment() is True
