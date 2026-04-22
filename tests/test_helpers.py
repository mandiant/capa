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
import dataclasses
from pathlib import Path

import pytest

import capa.helpers
from capa.helpers import (
    EXTENSIONS_ELF,
    EXTENSIONS_FREEZE,
    EXTENSIONS_DYNAMIC,
    EXTENSIONS_BINJA_DB,
    EXTENSIONS_BINEXPORT2,
    EXTENSIONS_SHELLCODE_32,
    EXTENSIONS_SHELLCODE_64,
    get_file_taste,
    get_format_from_extension,
)
from capa.features.common import (
    FORMAT_ELF,
    FORMAT_SC32,
    FORMAT_SC64,
    FORMAT_FREEZE,
    FORMAT_UNKNOWN,
    FORMAT_BINJA_DB,
    FORMAT_BINEXPORT2,
)
from capa.features.extractors import helpers
from capa.features.extractors.viv.basicblock import (
    get_printable_len,
    is_printable_ascii,
    is_printable_utf16le,
)

CD = Path(__file__).resolve().parent
DRAKVUF_LOG_GZ = (
    CD / "data" / "dynamic" / "drakvuf" / "93b2d1840566f45fab674ebc79a9d19c88993bcb645e0357f3cb584d16e7c795.log.gz"
)


def test_all_zeros():
    a = b"\x00\x00\x00\x00"
    b = codecs.decode(b"00000000", "hex")
    c = b"\x01\x00\x00\x00"
    d = codecs.decode(b"01000000", "hex")
    assert helpers.all_zeros(a) is True
    assert helpers.all_zeros(b) is True
    assert helpers.all_zeros(c) is False
    assert helpers.all_zeros(d) is False


def test_generate_symbols():
    assert list(helpers.generate_symbols("name.dll", "api", include_dll=True)) == list(
        helpers.generate_symbols("name", "api", include_dll=True)
    )
    assert list(helpers.generate_symbols("name.dll", "api", include_dll=False)) == list(
        helpers.generate_symbols("name", "api", include_dll=False)
    )

    # A/W import
    symbols = list(helpers.generate_symbols("kernel32", "CreateFileA", include_dll=True))
    assert len(symbols) == 4
    assert "kernel32.CreateFileA" in symbols
    assert "kernel32.CreateFile" in symbols
    assert "CreateFileA" in symbols
    assert "CreateFile" in symbols

    # import
    symbols = list(helpers.generate_symbols("kernel32", "WriteFile", include_dll=True))
    assert len(symbols) == 2
    assert "kernel32.WriteFile" in symbols
    assert "WriteFile" in symbols

    # ordinal import
    symbols = list(helpers.generate_symbols("ws2_32", "#1", include_dll=True))
    assert len(symbols) == 1
    assert "ws2_32.#1" in symbols

    # A/W api
    symbols = list(helpers.generate_symbols("kernel32", "CreateFileA", include_dll=False))
    assert len(symbols) == 2
    assert "CreateFileA" in symbols
    assert "CreateFile" in symbols

    # api
    symbols = list(helpers.generate_symbols("kernel32", "WriteFile", include_dll=False))
    assert len(symbols) == 1
    assert "WriteFile" in symbols

    # ordinal api
    symbols = list(helpers.generate_symbols("ws2_32", "#1", include_dll=False))
    assert len(symbols) == 1
    assert "ws2_32.#1" in symbols


def test_is_dev_environment():
    # testing environment should be a dev environment
    assert capa.helpers.is_dev_environment() is True


def test_load_one_jsonl_from_path_gz():
    result = capa.helpers.load_one_jsonl_from_path(DRAKVUF_LOG_GZ)
    assert isinstance(result, dict)
    assert "Plugin" in result


def test_load_one_jsonl_from_path_plain(tmp_path):
    p = tmp_path / "sample.jsonl"
    p.write_bytes(b'{"key": "value"}\n{"key": "second"}\n')
    result = capa.helpers.load_one_jsonl_from_path(p)
    assert result == {"key": "value"}


def test_load_one_jsonl_from_path_empty_raises(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_bytes(b"")
    with pytest.raises(StopIteration):
        capa.helpers.load_one_jsonl_from_path(p)


def test_extensions_dot_prefix():
    for ext_group in (
        EXTENSIONS_SHELLCODE_32,
        EXTENSIONS_SHELLCODE_64,
        EXTENSIONS_DYNAMIC,
        EXTENSIONS_BINEXPORT2,
        (EXTENSIONS_ELF,),
        (EXTENSIONS_FREEZE,),
        (EXTENSIONS_BINJA_DB,),
    ):
        for ext in ext_group:
            assert ext.startswith("."), f"extension {ext!r} must start with a dot"

    assert Path("sample.log").name.endswith(EXTENSIONS_DYNAMIC)
    assert not Path("dialog").name.endswith(EXTENSIONS_DYNAMIC)
    assert not Path("catalog").name.endswith(EXTENSIONS_DYNAMIC)
    assert Path("report.json").name.endswith(EXTENSIONS_DYNAMIC)
    assert not Path("notajson").name.endswith(EXTENSIONS_DYNAMIC)
    assert Path("sample.sc32").name.endswith(EXTENSIONS_SHELLCODE_32)
    assert Path("sample.raw32").name.endswith(EXTENSIONS_SHELLCODE_32)
    assert Path("sample.sc64").name.endswith(EXTENSIONS_SHELLCODE_64)
    assert Path("sample.raw64").name.endswith(EXTENSIONS_SHELLCODE_64)
    assert Path("sample.BinExport").name.endswith(EXTENSIONS_BINEXPORT2)
    assert Path("sample.BinExport2").name.endswith(EXTENSIONS_BINEXPORT2)
    assert Path("sample.elf_").name.endswith(EXTENSIONS_ELF)
    assert Path("sample.frz").name.endswith(EXTENSIONS_FREEZE)
    assert Path("sample.bndb").name.endswith(EXTENSIONS_BINJA_DB)


def test_get_format_from_extension():
    assert get_format_from_extension(Path("sample.sc32")) == FORMAT_SC32
    assert get_format_from_extension(Path("sample.raw32")) == FORMAT_SC32
    assert get_format_from_extension(Path("sample.sc64")) == FORMAT_SC64
    assert get_format_from_extension(Path("sample.raw64")) == FORMAT_SC64
    assert get_format_from_extension(Path("sample.elf_")) == FORMAT_ELF
    assert get_format_from_extension(Path("sample.frz")) == FORMAT_FREEZE
    assert get_format_from_extension(Path("sample.BinExport")) == FORMAT_BINEXPORT2
    assert get_format_from_extension(Path("sample.BinExport2")) == FORMAT_BINEXPORT2
    assert get_format_from_extension(Path("sample.bndb")) == FORMAT_BINJA_DB
    assert get_format_from_extension(Path("sample.exe")) == FORMAT_UNKNOWN


def test_get_file_taste_reads_first_bytes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x4d\x5a\x90\x00\x01\x02\x03\x04\xff\xfe")
    taste = get_file_taste(sample)
    assert taste == b"\x4d\x5a\x90\x00\x01\x02\x03\x04"
    assert len(taste) == 8


def test_get_file_taste_missing_file_raises():
    with pytest.raises(IOError):
        get_file_taste(Path("/nonexistent/path/sample.exe"))


def test_is_printable_ascii():
    assert is_printable_ascii(b"AB") is True
    assert is_printable_ascii(b"A\x00") is False
    assert is_printable_ascii(b"\x80\x81") is False


def test_is_printable_utf16le():
    assert is_printable_utf16le(b"A\x00B\x00") is True
    assert is_printable_utf16le(b"AB") is False
    assert is_printable_utf16le(b"\x80\x00\x81\x00") is False


def test_get_printable_len_returns_int():
    @dataclasses.dataclass
    class FakeOper:
        tsize: int
        imm: int

    ascii_oper = FakeOper(tsize=4, imm=int.from_bytes(b"ABCD", "little"))
    result = get_printable_len(ascii_oper)
    assert isinstance(result, int)
    assert result == 4

    utf16_oper = FakeOper(tsize=4, imm=int.from_bytes(b"A\x00B\x00", "little"))
    result = get_printable_len(utf16_oper)
    assert isinstance(result, int)
    assert result == 2

    utf16_oper_8 = FakeOper(tsize=8, imm=int.from_bytes(b"A\x00B\x00C\x00D\x00", "little"))
    result = get_printable_len(utf16_oper_8)
    assert isinstance(result, int)
    assert result == 4
