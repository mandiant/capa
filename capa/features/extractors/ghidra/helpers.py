# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Dict, List, Iterator

import ghidra
from ghidra.program.model.lang import OperandType
from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.address import AddressSpace

import capa.features.extractors.helpers
from capa.features.address import AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle


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


def get_function_symbols() -> Iterator[FunctionHandle]:
    """yield all non-external function symbols"""

    for fhandle in currentProgram.getFunctionManager().getFunctionsNoStubs(True):  # type: ignore [name-defined] # noqa: F821
        yield FunctionHandle(address=AbsoluteVirtualAddress(fhandle.getEntryPoint().getOffset()), inner=fhandle)


def get_function_blocks(fh: FunctionHandle) -> Iterator[BBHandle]:
    """yield BBHandle for each bb in a given function"""

    func: ghidra.program.database.function.FunctionDB = fh.inner
    for bb in SimpleBlockIterator(BasicBlockModel(currentProgram), func.getBody(), monitor):  # type: ignore [name-defined] # noqa: F821
        yield BBHandle(address=AbsoluteVirtualAddress(bb.getMinAddress().getOffset()), inner=bb)


def get_insn_in_range(bbh: BBHandle) -> Iterator[InsnHandle]:
    """yield InshHandle for each insn in a given basicblock"""

    bb: ghidra.program.model.block.CodeBlock = bbh.inner
    for addr in bb.getAddresses(True):
        insn = getInstructionAt(addr)  # type: ignore [name-defined] # noqa: F821
        if insn:
            yield InsnHandle(address=AbsoluteVirtualAddress(insn.getAddress().getOffset()), inner=insn)


def get_file_imports() -> Dict[int, List[str]]:
    """get all import names & addrs"""

    import_dict: Dict[int, List[str]] = {}

    for f in currentProgram.getFunctionManager().getExternalFunctions():  # type: ignore [name-defined] # noqa: F821
        for r in f.getSymbol().getReferences():
            if r.getReferenceType().isData():
                addr = r.getFromAddress().getOffset()  # gets pointer to fake external addr

        fstr = f.toString().split("::")  # format: MODULE.dll::import / MODULE::Ordinal_*
        if "Ordinal_" in fstr[1]:
            fstr[1] = f"#{fstr[1].split('_')[1]}"

        for name in capa.features.extractors.helpers.generate_symbols(fstr[0][:-4], fstr[1]):
            import_dict.setdefault(addr, []).append(name)

    return import_dict


def get_file_externs() -> Dict[int, List[str]]:
    """
    Gets function names & addresses of statically-linked library functions

    Ghidra's external namespace is mostly reserved for dynamically-linked
    imports. Statically-linked functions are part of the global namespace.
    Filtering on the type, source, and namespace of the symbols yield more
    statically-linked library functions.

    Example: (PMA Lab 16-01.exe_) 7faafc7e4a5c736ebfee6abbbc812d80:0x407490
    - __aulldiv
    - Note: See Symbol Table labels
    """

    extern_dict: Dict[int, List[str]] = {}

    for sym in currentProgram.getSymbolTable().getAllSymbols(True):  # type: ignore [name-defined] # noqa: F821
        # .isExternal() misses more than this config for the function symbols
        if sym.getSymbolType() == SymbolType.FUNCTION and sym.getSource() == SourceType.ANALYSIS and sym.isGlobal():
            name = sym.getName()  # starts to resolve names based on Ghidra's FidDB
            if name.startswith("FID_conflict:"):  # format: FID_conflict:<function-name>
                name = name[13:]
            extern_dict.setdefault(sym.getAddress().getOffset(), []).append(name)
            if name.startswith("_"):
                # some linkers may prefix linked routines with a `_` to avoid name collisions.
                # extract features for both the mangled and un-mangled representations.
                # e.g. `_fwrite` -> `fwrite`
                # see: https://stackoverflow.com/a/2628384/87207
                extern_dict.setdefault(sym.getAddress().getOffset(), []).append(name[1:])

    return extern_dict


def map_fake_import_addrs() -> Dict[int, List[int]]:
    """
    Map ghidra's fake import entrypoints to their
    real addresses

    Helps as many Ghidra Scripting API calls end up returning
    these external (fake) addresses.

    Undocumented but intended Ghidra behavior:
     - Import entryPoint fields are stored in the 'EXTERNAL:' AddressSpace.
       'getEntryPoint()' returns the entryPoint field, which is an offset
       from the beginning of the assigned AddressSpace. In the case of externals,
       they start from 1 and increment.
    https://github.com/NationalSecurityAgency/ghidra/blob/26d4bd9104809747c21f2528cab8aba9aef9acd5/Ghidra/Features/Base/src/test.slow/java/ghidra/program/database/function/ExternalFunctionDBTest.java#L90

    Example: (mimikatz.exe_) 5f66b82558ca92e54e77f216ef4c066c:0x473090
    - 0x473090 -> PTR_CreateServiceW_00473090
    - 'EXTERNAL:00000025' -> External Address (ghidra.program.model.address.SpecialAddress)
    """
    fake_dict: Dict[int, List[int]] = {}

    for f in currentProgram.getFunctionManager().getExternalFunctions():  # type: ignore [name-defined] # noqa: F821
        for r in f.getSymbol().getReferences():
            if r.getReferenceType().isData():
                fake_dict.setdefault(f.getEntryPoint().getOffset(), []).append(r.getFromAddress().getOffset())

    return fake_dict


def get_external_locs() -> List[int]:
    """
     Helps to discern external offsets from regular bytes when extracting
     data.

    Ghidra behavior:
     - Offsets that point to specific sections of external programs
      i.e. library code.
     - Stored in data, and pointed to by an absolute address
     https://github.com/NationalSecurityAgency/ghidra/blob/26d4bd9104809747c21f2528cab8aba9aef9acd5/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/ExternalLocation.java#L25-30

    Example: (mimikatz.exe_) 5f66b82558ca92e54e77f216ef4c066c:0x473090
    - 0x473090 -> PTR_CreateServiceW_00473090
    - 0x000b34EC -> External Location
    """
    locs = []
    for fh in currentProgram.getFunctionManager().getExternalFunctions():  # type: ignore [name-defined] # noqa: F821
        external_loc = fh.getExternalLocation().getAddress()
        if external_loc:
            locs.append(external_loc)
    return locs


def check_addr_for_api(
    addr: ghidra.program.model.address.Address,
    fakes: Dict[int, List[int]],
    imports: Dict[int, List[str]],
    externs: Dict[int, List[str]],
    ex_locs: List[int],
) -> bool:
    offset = addr.getOffset()

    fake = fakes.get(offset)
    if fake:
        return True

    imp = imports.get(offset)
    if imp:
        return True

    extern = externs.get(offset)
    if extern:
        return True

    if addr in ex_locs:
        return True

    return False


def is_call_or_jmp(insn: ghidra.program.database.code.InstructionDB) -> bool:
    return any(mnem in insn.getMnemonicString() for mnem in ["CALL", "J"])  # JMP, JNE, JNZ, etc


def is_sp_modified(insn: ghidra.program.database.code.InstructionDB) -> bool:
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == OperandType.REGISTER:
            return "SP" in insn.getRegister(i).getName() and insn.getOperandRefType(i).isWrite()
    return False


def is_stack_referenced(insn: ghidra.program.database.code.InstructionDB) -> bool:
    """generic catch-all for stack references"""
    return any(ref.isStackReference() for ref in insn.getReferencesFrom())


def is_zxor(insn: ghidra.program.database.code.InstructionDB) -> bool:
    # assume XOR insn
    # XOR's against the same operand zero out
    ops = []
    operands = []
    for i in range(insn.getNumOperands()):
        ops.append(insn.getOpObjects(i))

    # Operands stored in a 2D array
    for j in range(len(ops)):
        for k in range(len(ops[j])):
            operands.append(ops[j][k])

    return all(n == operands[0] for n in operands)


def dereference_ptr(insn: ghidra.program.database.code.InstructionDB):
    to_deref = insn.getAddress(0)
    dat = getDataContaining(to_deref)  # type: ignore [name-defined] # noqa: F821
    if not dat:
        return to_deref
    if dat.isDefined() and dat.isPointer():
        addr = dat.getValue()
        # now we need to check the addr space to see if it is truly resolvable
        # ghidra sometimes likes to hand us direct RAM addrs, which typically point
        # to api calls that we can't actually resolve as such
        if addr.getAddressSpace().getType() == AddressSpace.TYPE_RAM:
            return to_deref
        else:
            return addr
    else:
        return to_deref
