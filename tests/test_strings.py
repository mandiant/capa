# Copyright 2025 Google LLC
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

from capa.features.extractors.strings import (
    String,
    buf_filled_with,
    is_printable_str,
    extract_ascii_strings,
    extract_unicode_strings,
)


def test_buf_filled_with():
    # single repeating byte
    assert buf_filled_with(b"\x00" * 8, 0x00) is True
    assert buf_filled_with(b"\xff" * 8, 0xFF) is True

    # mixed bytes
    assert buf_filled_with(b"\x00\x01" * 8, 0x00) is False
    assert buf_filled_with(b"ABCD" * 8, ord("A")) is False

    # edge cases
    assert buf_filled_with(b"", 0x00) is False  # Empty buffer
    assert buf_filled_with(b"\x00", 0x00) is True  # Single byte


def test_extract_ascii_strings():
    # test empty buffer
    assert list(extract_ascii_strings(b"")) == []

    buf = b"Hello World\x00This is a test\x00"
    strings = list(extract_ascii_strings(buf))
    assert len(strings) == 2
    assert strings[0] == String("Hello World", 0)
    assert strings[1] == String("This is a test", 12)

    # min length
    buf = b"Hi\x00Test\x00"
    strings = list(extract_ascii_strings(buf, n=4))
    assert len(strings) == 1
    assert strings[0] == String("Test", 3)

    # non-ASCII strings
    buf = b"Hello\xffWorld\x00"
    strings = list(extract_ascii_strings(buf))
    assert len(strings) == 2
    assert strings[0] == String("Hello", 0)
    assert strings[1] == String("World", 6)

    # only non-ASCII
    assert list(extract_ascii_strings(b"\xff\xff\xff")) == []

    buf = b"\x00" * 8 + b"ValidString\x00"
    strings = list(extract_ascii_strings(buf))
    assert len(strings) == 1
    assert strings[0] == String("ValidString", 8)


def test_extract_unicode_strings():
    buf = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"
    strings = list(extract_unicode_strings(buf))
    assert len(strings) == 1
    assert strings[0] == String("Hello", 0)

    # min length
    buf = b"H\x00i\x00\x00\x00T\x00e\x00s\x00t\x00\x00\x00"
    strings = list(extract_unicode_strings(buf, n=4))
    assert len(strings) == 1
    assert strings[0] == String("Test", 6)

    # invalid Unicode sequences
    buf = b"H\x00\xff\x00l\x00l\x00o\x00\x00\x00"
    strings = list(extract_unicode_strings(buf))
    assert len(strings) == 0

    # repeating bytes (should be skipped)
    buf = b"\x00" * 8 + b"V\x00a\x00l\x00i\x00d\x00\x00\x00"
    strings = list(extract_unicode_strings(buf))
    assert len(strings) == 1
    assert strings[0] == String("Valid", 8)


def test_is_printable_str():
    assert is_printable_str("Hello World") is True
    assert is_printable_str("123!@#") is True
    assert is_printable_str("\t\n\r") is True  # whitespace is printable

    assert is_printable_str("\x00\x01\x02") is False
    assert is_printable_str("Hello\x07World") is False
    assert is_printable_str("\x1b[31m") is False  # ANSI escape codes

    assert is_printable_str("") is True  # empty string
    assert is_printable_str(" ") is True  # single space
    assert is_printable_str("\x7f") is False  # DEL character
