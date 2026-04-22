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
import tempfile
from pathlib import Path

import pytest

import capa.helpers
from capa.helpers import get_file_taste, get_format_from_extension
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


def test_get_file_taste_reads_first_bytes():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"\x4d\x5a\x90\x00\x01\x02\x03\x04\xff\xfe")
        tmp_path = Path(tmp.name)
    try:
        taste = get_file_taste(tmp_path)
        assert taste == b"\x4d\x5a\x90\x00\x01\x02\x03\x04"
        assert len(taste) == 8
    finally:
        tmp_path.unlink()


def test_get_file_taste_missing_file_raises():
    with pytest.raises(IOError):
        get_file_taste(Path("/nonexistent/path/sample.exe"))
