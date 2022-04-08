# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import struct
import builtins
from typing import Tuple, Iterator

MIN_STACKSTRING_LEN = 8


def xor_static(data: bytes, i: int) -> bytes:
    return bytes(c ^ i for c in data)


def is_aw_function(symbol: str) -> bool:
    """
    is the given function name an A/W function?
    these are variants of functions that, on Windows, accept either a narrow or wide string.
    """
    if len(symbol) < 2:
        return False

    # last character should be 'A' or 'W'
    if symbol[-1] not in ("A", "W"):
        return False

    return True


def is_ordinal(symbol: str) -> bool:
    """
    is the given symbol an ordinal that is prefixed by "#"?
    """
    if symbol:
        return symbol[0] == "#"
    return False


def generate_symbols(dll: str, symbol: str) -> Iterator[str]:
    """
    for a given dll and symbol name, generate variants.
    we over-generate features to make matching easier.
    these include:
      - kernel32.CreateFileA
      - kernel32.CreateFile
      - CreateFileA
      - CreateFile
    """
    # normalize dll name
    dll = dll.lower()

    # kernel32.CreateFileA
    yield "%s.%s" % (dll, symbol)

    if not is_ordinal(symbol):
        # CreateFileA
        yield symbol

    if is_aw_function(symbol):
        # kernel32.CreateFile
        yield "%s.%s" % (dll, symbol[:-1])

        if not is_ordinal(symbol):
            # CreateFile
            yield symbol[:-1]


def all_zeros(bytez: bytes) -> bool:
    return all(b == 0 for b in builtins.bytes(bytez))


def twos_complement(val: int, bits: int) -> int:
    """
    compute the 2's complement of int value val

    from: https://stackoverflow.com/a/9147327/87207
    """
    # if sign bit is set e.g., 8bit: 128-255
    if (val & (1 << (bits - 1))) != 0:
        # compute negative value
        return val - (1 << bits)
    else:
        # return positive value as is
        return val


def carve_pe(pbytes: bytes, offset: int = 0) -> Iterator[Tuple[int, int]]:
    """
    Generate (offset, key) tuples of embedded PEs

    Based on the version from vivisect:
      https://github.com/vivisect/vivisect/blob/7be4037b1cecc4551b397f840405a1fc606f9b53/PE/carve.py#L19
    And its IDA adaptation:
      capa/features/extractors/ida/file.py
    """
    mz_xor = [
        (
            xor_static(b"MZ", key),
            xor_static(b"PE", key),
            key,
        )
        for key in range(256)
    ]

    pblen = len(pbytes)
    todo = [(pbytes.find(mzx, offset), mzx, pex, key) for mzx, pex, key in mz_xor]
    todo = [(off, mzx, pex, key) for (off, mzx, pex, key) in todo if off != -1]

    while len(todo):

        off, mzx, pex, key = todo.pop()

        # The MZ header has one field we will check
        # e_lfanew is at 0x3c
        e_lfanew = off + 0x3C
        if pblen < (e_lfanew + 4):
            continue

        newoff = struct.unpack("<I", xor_static(pbytes[e_lfanew : e_lfanew + 4], key))[0]

        nextres = pbytes.find(mzx, off + 1)
        if nextres != -1:
            todo.append((nextres, mzx, pex, key))

        peoff = off + newoff
        if pblen < (peoff + 2):
            continue

        if pbytes[peoff : peoff + 2] == pex:
            yield (off, key)
