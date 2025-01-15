# Copyright 2023 Google LLC
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
import struct
from typing import Iterator

from ghidra.program.model.symbol import SourceType, SymbolType

import capa.features.extractors.common
import capa.features.extractors.helpers
import capa.features.extractors.strings
import capa.features.extractors.ghidra.helpers
from capa.features.file import Export, Import, Section, FunctionName
from capa.features.common import FORMAT_PE, FORMAT_ELF, Format, String, Feature, Characteristic
from capa.features.address import NO_ADDRESS, Address, FileOffsetAddress, AbsoluteVirtualAddress

MAX_OFFSET_PE_AFTER_MZ = 0x200


def find_embedded_pe(block_bytez: bytes, mz_xor: list[tuple[bytes, bytes, int]]) -> Iterator[tuple[int, int]]:
    """check segment for embedded PE

    adapted for Ghidra from:
    https://github.com/vivisect/vivisect/blob/91e8419a861f4977https://github.com/vivisect/vivisect/blob/91e8419a861f49779f18316f155311967e696836/PE/carve.py#L259f18316f155311967e696836/PE/carve.py#L25
    """
    todo = []

    for mzx, pex, i in mz_xor:
        for match in re.finditer(re.escape(mzx), block_bytez):
            todo.append((match.start(), mzx, pex, i))

    seg_max = len(block_bytez)  # noqa: F821
    while len(todo):
        off, mzx, pex, i = todo.pop()

        # MZ header has one field we will check e_lfanew is at 0x3c
        e_lfanew = off + 0x3C

        if seg_max < e_lfanew + 4:
            continue

        e_lfanew_bytes = block_bytez[e_lfanew : e_lfanew + 4]
        newoff = struct.unpack("<I", capa.features.extractors.helpers.xor_static(e_lfanew_bytes, i))[0]

        # assume XOR'd "PE" bytes exist within threshold
        if newoff > MAX_OFFSET_PE_AFTER_MZ:
            continue

        peoff = off + newoff
        if seg_max < peoff + 2:
            continue

        pe_bytes = block_bytez[peoff : peoff + 2]
        if pe_bytes == pex:
            yield off, i


def extract_file_embedded_pe() -> Iterator[tuple[Feature, Address]]:
    """extract embedded PE features"""

    # pre-compute XOR pairs
    mz_xor: list[tuple[bytes, bytes, int]] = [
        (
            capa.features.extractors.helpers.xor_static(b"MZ", i),
            capa.features.extractors.helpers.xor_static(b"PE", i),
            i,
        )
        for i in range(256)
    ]

    for block in currentProgram().getMemory().getBlocks():  # type: ignore [name-defined] # noqa: F821
        if not all((block.isLoaded(), block.isInitialized(), "Headers" not in block.getName())):
            continue

        for off, _ in find_embedded_pe(capa.features.extractors.ghidra.helpers.get_block_bytes(block), mz_xor):
            # add offset back to block start
            ea: int = block.getStart().add(off).getOffset()

            yield Characteristic("embedded pe"), FileOffsetAddress(ea)


def extract_file_export_names() -> Iterator[tuple[Feature, Address]]:
    """extract function exports"""
    st = currentProgram().getSymbolTable()  # type: ignore [name-defined] # noqa: F821
    for addr in st.getExternalEntryPointIterator():
        yield Export(st.getPrimarySymbol(addr).getName()), AbsoluteVirtualAddress(addr.getOffset())


def extract_file_import_names() -> Iterator[tuple[Feature, Address]]:
    """extract function imports

    1. imports by ordinal:
     - modulename.#ordinal

    2. imports by name, results in two features to support importname-only
       matching:
     - modulename.importname
     - importname
    """

    for f in currentProgram().getFunctionManager().getExternalFunctions():  # type: ignore [name-defined] # noqa: F821
        for r in f.getSymbol().getReferences():
            if r.getReferenceType().isData():
                addr = r.getFromAddress().getOffset()  # gets pointer to fake external addr

        fstr = f.toString().split("::")  # format: MODULE.dll::import / MODULE::Ordinal_*
        if "Ordinal_" in fstr[1]:
            fstr[1] = f"#{fstr[1].split('_')[1]}"

        for name in capa.features.extractors.helpers.generate_symbols(fstr[0][:-4], fstr[1], include_dll=True):
            yield Import(name), AbsoluteVirtualAddress(addr)


def extract_file_section_names() -> Iterator[tuple[Feature, Address]]:
    """extract section names"""

    for block in currentProgram().getMemory().getBlocks():  # type: ignore [name-defined] # noqa: F821
        yield Section(block.getName()), AbsoluteVirtualAddress(block.getStart().getOffset())


def extract_file_strings() -> Iterator[tuple[Feature, Address]]:
    """extract ASCII and UTF-16 LE strings"""

    for block in currentProgram().getMemory().getBlocks():  # type: ignore [name-defined] # noqa: F821
        if not block.isInitialized():
            continue

        p_bytes = capa.features.extractors.ghidra.helpers.get_block_bytes(block)

        for s in capa.features.extractors.strings.extract_ascii_strings(p_bytes):
            offset = block.getStart().getOffset() + s.offset
            yield String(s.s), FileOffsetAddress(offset)

        for s in capa.features.extractors.strings.extract_unicode_strings(p_bytes):
            offset = block.getStart().getOffset() + s.offset
            yield String(s.s), FileOffsetAddress(offset)


def extract_file_function_names() -> Iterator[tuple[Feature, Address]]:
    """
    extract the names of statically-linked library functions.
    """

    for sym in currentProgram().getSymbolTable().getAllSymbols(True):  # type: ignore [name-defined] # noqa: F821
        # .isExternal() misses more than this config for the function symbols
        if sym.getSymbolType() == SymbolType.FUNCTION and sym.getSource() == SourceType.ANALYSIS and sym.isGlobal():
            name = sym.getName()  # starts to resolve names based on Ghidra's FidDB
            if name.startswith("FID_conflict:"):  # format: FID_conflict:<function-name>
                name = name[13:]
            addr = AbsoluteVirtualAddress(sym.getAddress().getOffset())
            yield FunctionName(name), addr
            if name.startswith("_"):
                # some linkers may prefix linked routines with a `_` to avoid name collisions.
                # extract features for both the mangled and un-mangled representations.
                # e.g. `_fwrite` -> `fwrite`
                # see: https://stackoverflow.com/a/2628384/87207
                yield FunctionName(name[1:]), addr


def extract_file_format() -> Iterator[tuple[Feature, Address]]:
    ef = currentProgram().getExecutableFormat()  # type: ignore [name-defined] # noqa: F821
    if "PE" in ef:
        yield Format(FORMAT_PE), NO_ADDRESS
    elif "ELF" in ef:
        yield Format(FORMAT_ELF), NO_ADDRESS
    elif "Raw" in ef:
        # no file type to return when processing a binary file, but we want to continue processing
        return
    else:
        raise NotImplementedError(f"unexpected file format: {ef}")


def extract_features() -> Iterator[tuple[Feature, Address]]:
    """extract file features"""
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler():
            yield feature, addr


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    extract_file_function_names,
    extract_file_format,
)


def main():
    """ """
    import pprint

    pprint.pprint(list(extract_features()))  # noqa: T203


if __name__ == "__main__":
    main()
