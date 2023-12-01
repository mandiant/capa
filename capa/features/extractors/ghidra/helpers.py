# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Dict, List, Iterator

import ghidra
import java.lang
from ghidra.program.model.lang import OperandType
from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.address import AddressSpace

import capa.features.extractors.helpers
from capa.features.common import THUNK_CHAIN_DEPTH_DELTA
from capa.features.address import AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle


def ints_to_bytes(bytez: List[int]) -> bytes:
    """convert Java signed ints to Python bytes

    args:
        bytez: list of Java signed ints
    """
    return bytes([b & 0xFF for b in bytez])


def find_byte_sequence(addr: ghidra.program.model.address.Address, seq: bytes) -> Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        addr: start address
        seq: bytes to search e.g. b"\x01\x03"
    """
    seqstr = "".join([f"\\x{b:02x}" for b in seq])
    eas = findBytes(addr, seqstr, java.lang.Integer.MAX_VALUE, 1)  # type: ignore [name-defined] # noqa: F821

    yield from eas


def get_bytes(addr: ghidra.program.model.address.Address, length: int) -> bytes:
    """yield length bytes at addr

    args:
        addr: Address to begin pull from
        length: length of bytes to pull
    """
    try:
        return ints_to_bytes(getBytes(addr, length))  # type: ignore [name-defined] # noqa: F821
    except RuntimeError:
        return b""


def get_block_bytes(block: ghidra.program.model.mem.MemoryBlock) -> bytes:
    """yield all bytes in a given block

    args:
        block: MemoryBlock to pull from
    """
    return get_bytes(block.getStart(), block.getSize())


def get_function_symbols():
    """yield all non-external function symbols"""
    yield from currentProgram().getFunctionManager().getFunctionsNoStubs(True)  # type: ignore [name-defined] # noqa: F821


def get_function_blocks(fh: FunctionHandle) -> Iterator[BBHandle]:
    """yield BBHandle for each bb in a given function"""

    func: ghidra.program.database.function.FunctionDB = fh.inner
    for bb in SimpleBlockIterator(BasicBlockModel(currentProgram()), func.getBody(), monitor()):  # type: ignore [name-defined] # noqa: F821
        yield BBHandle(address=AbsoluteVirtualAddress(bb.getMinAddress().getOffset()), inner=bb)


def get_insn_in_range(bbh: BBHandle) -> Iterator[InsnHandle]:
    """yield InshHandle for each insn in a given basicblock"""
    for insn in currentProgram().getListing().getInstructions(bbh.inner, True):  # type: ignore [name-defined] # noqa: F821
        yield InsnHandle(address=AbsoluteVirtualAddress(insn.getAddress().getOffset()), inner=insn)


def get_file_imports() -> Dict[int, List[str]]:
    """get all import names & addrs"""

    import_dict: Dict[int, List[str]] = {}

    for f in currentProgram().getFunctionManager().getExternalFunctions():  # type: ignore [name-defined] # noqa: F821
        for r in f.getSymbol().getReferences():
            if r.getReferenceType().isData():
                addr = r.getFromAddress().getOffset()  # gets pointer to fake external addr

        ex_loc = f.getExternalLocation().getAddress()  # map external locations as well (offset into module files)

        fstr = f.toString().split("::")  # format: MODULE.dll::import / MODULE::Ordinal_* / <EXTERNAL>::import
        if "Ordinal_" in fstr[1]:
            fstr[1] = f"#{fstr[1].split('_')[1]}"

        # <EXTERNAL> mostly shows up in ELF files, otherwise, strip '.dll' w/ [:-4]
        fstr[0] = "*" if "<EXTERNAL>" in fstr[0] else fstr[0][:-4]

        for name in capa.features.extractors.helpers.generate_symbols(fstr[0], fstr[1]):
            import_dict.setdefault(addr, []).append(name)
            if ex_loc:
                import_dict.setdefault(ex_loc.getOffset(), []).append(name)

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

    for sym in currentProgram().getSymbolTable().getAllSymbols(True):  # type: ignore [name-defined] # noqa: F821
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

    for f in currentProgram().getFunctionManager().getExternalFunctions():  # type: ignore [name-defined] # noqa: F821
        for r in f.getSymbol().getReferences():
            if r.getReferenceType().isData():
                fake_dict.setdefault(f.getEntryPoint().getOffset(), []).append(r.getFromAddress().getOffset())

    return fake_dict


def check_addr_for_api(
    addr: ghidra.program.model.address.Address,
    fakes: Dict[int, List[int]],
    imports: Dict[int, List[str]],
    externs: Dict[int, List[str]],
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
    for i in range(insn.getNumOperands()):
        if insn.getOperandType(i) == OperandType.REGISTER:
            if "BP" in insn.getRegister(i).getName():
                return True
            else:
                continue

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


def handle_thunk(addr: ghidra.program.model.address.Address):
    """Follow thunk chains down to a reasonable depth"""
    ref = addr
    for _ in range(THUNK_CHAIN_DEPTH_DELTA):
        thunk_jmp = getInstructionAt(ref)  # type: ignore [name-defined] # noqa: F821
        if thunk_jmp and is_call_or_jmp(thunk_jmp):
            if OperandType.isAddress(thunk_jmp.getOperandType(0)):
                ref = thunk_jmp.getAddress(0)
        else:
            thunk_dat = getDataContaining(ref)  # type: ignore [name-defined] # noqa: F821
            if thunk_dat and thunk_dat.isDefined() and thunk_dat.isPointer():
                ref = thunk_dat.getValue()
                break  # end of thunk chain reached
    return ref


def dereference_ptr(insn: ghidra.program.database.code.InstructionDB):
    addr_code = OperandType.ADDRESS | OperandType.CODE
    to_deref = insn.getAddress(0)
    dat = getDataContaining(to_deref)  # type: ignore [name-defined] # noqa: F821

    if insn.getOperandType(0) == addr_code:
        thfunc = getFunctionContaining(to_deref)  # type: ignore [name-defined] # noqa: F821
        if thfunc and thfunc.isThunk():
            return handle_thunk(to_deref)
        else:
            # if it doesn't poin to a thunk, it's usually a jmp to a label
            return to_deref
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


def find_data_references_from_insn(insn, max_depth: int = 10):
    """yield data references from given instruction"""
    for reference in insn.getReferencesFrom():
        if not reference.getReferenceType().isData():
            # only care about data references
            continue

        to_addr = reference.getToAddress()

        for _ in range(max_depth - 1):
            data = getDataAt(to_addr)  # type: ignore [name-defined] # noqa: F821
            if data and data.isPointer():
                ptr_value = data.getValue()

                if ptr_value is None:
                    break

                to_addr = ptr_value
            else:
                break

        yield to_addr
