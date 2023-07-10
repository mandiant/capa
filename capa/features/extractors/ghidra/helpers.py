# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Any, Dict, Tuple, Iterator, Optional

import ghidra
from ghidra.program.model.symbol import SymbolType

currentProgram: ghidra.program.database.ProgramDB


def fix_byte(b: int) -> bytes:
    """Transform signed ints from Java into bytes for Python

    args:
        b: signed int returned from Java processing
    """
    return (b & 0xFF).to_bytes(1, "little")


def find_byte_sequence(seq: bytes) -> Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        seq: bytes to search e.g. b"\x01\x03"
    """
    seqstr = "".join([f"\\x{b:02x}" for b in seq])
    # .add(1) to avoid false positives on regular PE files
    ea = findBytes(currentProgram.getMinAddress().add(1), seqstr, 1, 1)  # type: ignore [name-defined]
    for e in ea:
        yield e


def get_bytes(addr: ghidra.program.model.address.Address, length: int) -> bytes:
    """yield length bytes at addr

    args:
        addr: Address to begin pull from
        length: length of bytes to pull
    """

    bytez = b""
    try:
        signed_ints = getBytes(addr, length)  # type: ignore [name-defined]
        for b in signed_ints:
            bytez = bytez + fix_byte(b)
        return bytez
    except RuntimeError:
        return bytez


def get_block_bytes(block: ghidra.program.model.mem.MemoryBlock) -> bytes:
    """yield all bytes in a given block

    args:
        block: MemoryBlock to pull from
    """

    bytez = b""
    try:
        signed_ints = getBytes(block.getStart(), block.getEnd().getOffset() - block.getStart().getOffset())  # type: ignore [name-defined]
        for b in signed_ints:
            bytez = bytez + fix_byte(b)
        return bytez
    except RuntimeError:
        return bytez


def get_function_symbols() -> Iterator[ghidra.program.database.function.FunctionDB]:
    """yield all non-external function symbols"""

    for f in currentProgram.getFunctionManager().getFunctionsNoStubs(True):
        yield f
