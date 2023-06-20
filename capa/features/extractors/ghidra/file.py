# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import struct
from typing import Tuple, Iterator

from ghidra.program.model.symbol import SourceType

import capa.features.extractors.common
import capa.features.extractors.helpers
import capa.features.extractors.strings
import capa.features.extractors.ghidra.helpers
from capa.features.file import Export, Import, Section, FunctionName
from capa.features.common import FORMAT_PE, FORMAT_ELF, Format, String, Feature, Characteristic
from capa.features.address import NO_ADDRESS, Address, FileOffsetAddress, AbsoluteVirtualAddress

MAX_OFFSET_PE_AFTER_MZ = 0x200


def check_segment_for_pe() -> Iterator[Tuple[int, int]]:
    """check segment for embedded PE

    adapted for Ghidra from:
    https://github.com/vivisect/vivisect/blob/91e8419a861f4977https://github.com/vivisect/vivisect/blob/91e8419a861f49779f18316f155311967e696836/PE/carve.py#L259f18316f155311967e696836/PE/carve.py#L25
    """

    mz_xor = [
        (
            capa.features.extractors.helpers.xor_static(b"MZ", i),
            capa.features.extractors.helpers.xor_static(b"PE", i),
            i,
        )
        for i in range(256)
    ]
 
    todo = []
    for mzx, pex, i in mz_xor:
        # find all segment offsets containing XOR'd "MZ" bytes
        for off in capa.features.extractors.ghidra.helpers.find_byte_sequence(mzx):
            todo.append((off, mzx, pex, i))

    seg_max = currentProgram.getMaxAddress() 
    while len(todo):
        off, mzx, pex, i = todo.pop()

        # MZ header has one field we will check e_lfanew is at 0x3c
        e_lfanew = off.add(0x3C)

        if seg_max.getOffset() < (e_lfanew.getOffset() + 4):
            continue

        e_lfanew_bytes = b''
        e_lfanew_sbytes = getBytes(e_lfanew, 4) 
        for b in e_lfanew_sbytes:
            b = (b & 0xFF).to_bytes(1, 'little')
            e_lfanew_bytes = e_lfanew_bytes + b
        newoff = struct.unpack("<I", capa.features.extractors.helpers.xor_static(e_lfanew_bytes, i))[0]

        # assume XOR'd "PE" bytes exist within threshold
        if newoff > MAX_OFFSET_PE_AFTER_MZ:
            continue

        peoff = off.add(newoff)
        if seg_max.getOffset() < (peoff.getOffset() + 2):
            continue

        pe_bytes = b''
        pe_off_bytes = getBytes(peoff, 2)
        for b in pe_off_bytes:
            b = (b & 0xFF).to_bytes(1, 'little')
            pe_bytes = pe_bytes + b
        if pe_bytes == pex:
            yield off.getOffset(), i


def extract_file_embedded_pe() -> Iterator[Tuple[Feature, Address]]:
    """extract embedded PE features
    """

    for ea, _ in check_segment_for_pe():
        yield Characteristic("embedded pe"), FileOffsetAddress(ea)


def extract_file_export_names() -> Iterator[Tuple[Feature, Address]]:
    """extract function exports

    Exports in Ghidra:
        - namespace = Global
        - SourceType = IMPORTED
    """

    fm = currentProgram.getFunctionManager().getFunctions(True) # Only Global functions
    while fm.hasNext():
        f = fm.next().getSymbol()
        if (f.getSource() == SourceType.IMPORTED):
            yield Export(f.toString()), AbsoluteVirtualAddress(f.getAddress().getOffset())


def extract_file_import_names() -> Iterator[Tuple[Feature, Address]]:
    """extract function imports

    1. imports by ordinal:
     - modulename.#ordinal

    2. imports by name, results in two features to support importname-only
       matching:
     - modulename.importname
     - importname
    """

    fm = currentProgram.getFunctionManager().getExternalFunctions()
    while fm.hasNext():
        f = fm.next()
        addr = int(f.getEntryPoint().toString().split(':')[1], 16)  # format: EXTERNAL:<hex_addr>
        fstr = f.getName()  # format: 'importname' / 'Ordinal_*'
        if 'Ordinal_' in fstr:
            fstr = f"#{fstr.split('_')[1]}"
        yield Import(fstr), AbsoluteVirtualAddress(addr)


def extract_file_section_names() -> Iterator[Tuple[Feature, Address]]:
    """extract section names"""

    for block in currentProgram.getMemory().getBlocks():
        yield Section(block.getName()), AbsoluteVirtualAddress(block.getStart().getOffset())


def extract_file_strings() -> Iterator[Tuple[Feature, Address]]:
    """extract ASCII and UTF-16 LE strings"""

    dat = getFirstData()
    while (dat != None):
        if (dat.hasStringValue()):
            yield String(dat.getValue()), FileOffsetAddress(dat.getAddress().getOffset()) 
        dat = getDataAfter(dat)


def extract_file_function_names() -> Iterator[Tuple[Feature, Address]]:
    """
    extract the names of statically-linked library functions.
    """

    fm = currentProgram.getFunctionManager().getExternalFunctions()
    while fm.hasNext():
        f = fm.next()
        addr = int(f.getEntryPoint().toString().split(':')[1], 16)  # format: EXTERNAL:<hex_addr>
        name = f.getName()
        yield FunctionName(name), AbsoluteVirtualAddress(addr)
        if name.startswith("_"):
            # some linkers may prefix linked routines with a `_` to avoid name collisions.
            # extract features for both the mangled and un-mangled representations.
            # e.g. `_fwrite` -> `fwrite`
            # see: https://stackoverflow.com/a/2628384/87207
            yield FunctionName(name[1:]), AbsoluteVirtualAddress(addr)


def extract_file_format() -> Iterator[Tuple[Feature, Address]]:

    ef = currentProgram.getExecutableFormat()
    if 'PE' in ef:
        yield Format(FORMAT_PE), NO_ADDRESS
    elif 'ELF' in ef:
        yield Format(FORMAT_ELF), NO_ADDRESS
    elif 'Raw' in ef:
        # no file type to return when processing a binary file, but we want to continue processing
        return
    else:
        raise NotImplementedError(f"unexpected file format: {view_type}")


def extract_features() -> Iterator[Tuple[Feature, Address]]:
    """extract file features"""
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler():
            yield feature, addr


FILE_HANDLERS = (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_strings,
    extract_file_section_names,
    extract_file_embedded_pe,
    extract_file_function_names,
    extract_file_format,
)


def main():
    """ """
    import pprint

    pprint.pprint(list(extract_features()))


if __name__ == "__main__":
    main()

