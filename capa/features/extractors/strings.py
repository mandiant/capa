# strings code from FLOSS, https://github.com/mandiant/flare-floss
#
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

import re
import string
import contextlib
from dataclasses import dataclass
from collections.abc import Iterator

ASCII_BYTE = r" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t".encode(
    "ascii"
)
ASCII_RE_4 = re.compile(b"([%s]{%d,})" % (ASCII_BYTE, 4))
UNICODE_RE_4 = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = {ord("A"), 0x00, 0xFE, 0xFF}
SLICE_SIZE = 4096
PRINTABLE_CHAR_SET = set(string.printable)


@dataclass
class String:
    s: str
    offset: int


def buf_filled_with(buf: bytes, character: int) -> bool:
    """Check if the given buffer is filled with the given character, repeatedly.

    Args:
        buf: The bytes buffer to check
        character: The byte value (0-255) to check for

    Returns:
        True if all bytes in the buffer match the character, False otherwise.
        The empty buffer contains no bytes, therefore always returns False.
    """
    if not buf:
        return False

    if not (0 <= character <= 255):
        raise ValueError(f"Character value {character} outside valid byte range (0-255)")

    if len(buf) < SLICE_SIZE:
        return all(b == character for b in buf)

    # single big allocation, re-used each loop
    dupe_chunk = bytes(character) * SLICE_SIZE

    for offset in range(0, len(buf), SLICE_SIZE):
        # bytes objects are immutable, so the slices share the underlying array,
        # and therefore this is cheap.
        current_chunk = buf[offset : offset + SLICE_SIZE]

        if len(current_chunk) == SLICE_SIZE:
            # chunk-aligned comparison

            if dupe_chunk != current_chunk:
                return False

        else:
            # last loop, final chunk size is not aligned
            if not all(b == character for b in current_chunk):
                return False

    return True


def extract_ascii_strings(buf: bytes, n: int = 4) -> Iterator[String]:
    """
    Extract ASCII strings from the given binary data.

    Params:
      buf: the bytes from which to extract strings
      n: minimum string length
    """

    if not buf:
        return

    if n < 1:
        raise ValueError("minimum string length must be positive")

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    r = None
    if n == 4:
        r = ASCII_RE_4
    else:
        reg = b"([%s]{%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())


def extract_unicode_strings(buf: bytes, n: int = 4) -> Iterator[String]:
    """
    Extract naive UTF-16 strings from the given binary data.

    Params:
      buf: the bytes from which to extract strings
      n: minimum string length
    """

    if not buf:
        return

    if n < 1:
        raise ValueError("minimum string length must be positive")

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    if n == 4:
        r = UNICODE_RE_4
    else:
        reg = b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
        r = re.compile(reg)
    for match in r.finditer(buf):
        with contextlib.suppress(UnicodeDecodeError):
            yield String(match.group().decode("utf-16"), match.start())


def is_printable_str(s: str) -> bool:
    return set(s).issubset(PRINTABLE_CHAR_SET)
