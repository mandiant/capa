# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Any, Dict, Iterator

import ghidra
from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import SourceType, SymbolType

import capa.features.extractors.helpers


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
    eas = findBytes(currentProgram.getMinAddress().add(1), seqstr, 1, 1)  # type: ignore [name-defined] # noqa: F821
    yield from eas


def get_bytes(addr: ghidra.program.model.address.Address, length: int) -> bytes:
    """yield length bytes at addr

    args:
        addr: Address to begin pull from
        length: length of bytes to pull
    """

    bytez = b""
    try:
        signed_ints = getBytes(addr, length)  # type: ignore [name-defined] # noqa: F821
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
        signed_ints = getBytes(block.getStart(), block.getEnd().getOffset() - block.getStart().getOffset())  # type: ignore [name-defined] # noqa: F821
        for b in signed_ints:
            bytez = bytez + fix_byte(b)
        return bytez
    except RuntimeError:
        return bytez


def get_function_symbols() -> Iterator[ghidra.program.database.function.FunctionDB]:
    """yield all non-external function symbols"""

    yield from currentProgram.getFunctionManager().getFunctionsNoStubs(True)  # type: ignore [name-defined] # noqa: F821


def get_file_imports() -> Dict[int, Any]:
    """get all import names & addrs"""

    addrs = []
    names = []

    for f in currentProgram.getFunctionManager().getExternalFunctions():  # type: ignore [name-defined] # noqa: F821
        for r in f.getSymbol().getReferences():
            if r.getReferenceType().isData():
                addr = r.getFromAddress().getOffset()  # gets pointer to fake external addr

        fstr = f.toString().split("::")  # format: MODULE.dll::import / MODULE::Ordinal_*
        if "Ordinal_" in fstr[1]:
            fstr[1] = f"#{fstr[1].split('_')[1]}"

        for name in capa.features.extractors.helpers.generate_symbols(fstr[0][:-4], fstr[1]):
            addrs.append(addr)
            names.append(name)

    return dict(zip(addrs, names))


def get_file_externs() -> Dict[int, Any]:
    addrs = []
    names = []

    for sym in currentProgram.getSymbolTable().getAllSymbols(True):  # type: ignore [name-defined] # noqa: F821
        # .isExternal() misses more than this config for the function symbols
        if sym.getSymbolType() == SymbolType.FUNCTION and sym.getSource() == SourceType.ANALYSIS and sym.isGlobal():
            name = sym.getName()  # starts to resolve names based on Ghidra's FidDB
            if name.startswith("FID_conflict:"):  # format: FID_conflict:<function-name>
                name = name[13:]
            addrs.append(sym.getAddress().getOffset())
            names.append(name)
            if name.startswith("_"):
                # some linkers may prefix linked routines with a `_` to avoid name collisions.
                # extract features for both the mangled and un-mangled representations.
                # e.g. `_fwrite` -> `fwrite`
                # see: https://stackoverflow.com/a/2628384/87207
                names.append(name[1:])

    return dict(zip(addrs, names))


def is_sp_modified(insn) -> bool:
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == OperandType.REGISTER:
            if "SP" in insn.getOpObjects(i)[0].toString():
                return True
    return False


def is_stack_referenced(insn) -> bool:
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == OperandType.REGISTER:
            reg = insn.getOpObjects(i)[0].toString()
            if "SP" in reg or "BP" in reg:
                return True
    return False


def is_zxor(insn) -> bool:
    # assume XOR insn
    # XOR's against the same operand zero out
    ops = []
    op_types = []
    for i in range(insn.getNumOperands()):
        op_types.append(insn.getOperandType(i))
        ops.append(insn.getOpObjects(i))

    return all(n == op_types[0] for n in op_types) and all(j == ops[0] for j in ops)
