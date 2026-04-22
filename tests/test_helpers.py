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

import capa.helpers
from capa.features.extractors import helpers
from capa.features.extractors.viv.basicblock import (
    get_printable_len,
    is_printable_ascii,
    is_printable_utf16le,
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
    symbols = list(
        helpers.generate_symbols("kernel32", "CreateFileA", include_dll=True)
    )
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
    symbols = list(
        helpers.generate_symbols("kernel32", "CreateFileA", include_dll=False)
    )
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
