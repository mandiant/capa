# String extraction derived from FLOSS via capa.
# https://github.com/mandiant/flare-floss
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

from __future__ import annotations

import string

PRINTABLE_BYTES = set(string.printable.encode("ascii"))

MIN_STRING_LENGTH = 4

MAX_STRING_READ = 2048


def is_printable_ascii(s: str) -> bool:
    try:
        return all(b in PRINTABLE_BYTES for b in s.encode("ascii"))
    except UnicodeEncodeError:
        return False


def extract_ascii_from_buf(buf: bytes) -> str | None:
    """Extract a null-terminated printable ASCII string from the start of a buffer."""
    end = buf.find(b"\x00")
    if end == -1:
        end = len(buf)
    if end < MIN_STRING_LENGTH:
        return None
    candidate = buf[:end]
    if not all(b in PRINTABLE_BYTES for b in candidate):
        return None
    return candidate.decode("ascii")


def extract_utf16le_from_buf(buf: bytes) -> str | None:
    """Extract a null-terminated UTF-16 LE string from the start of a buffer."""
    if len(buf) < MIN_STRING_LENGTH * 2:
        return None
    if buf[1] != 0:
        return None
    chars: list[int] = []
    for i in range(0, len(buf) - 1, 2):
        lo, hi = buf[i], buf[i + 1]
        if lo == 0 and hi == 0:
            break
        if hi != 0 or lo not in PRINTABLE_BYTES:
            return None
        chars.append(lo)
    if len(chars) < MIN_STRING_LENGTH:
        return None
    return bytes(chars).decode("ascii")
