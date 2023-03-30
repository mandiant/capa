# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import struct
from typing import Tuple, Iterator

from binaryninja import Symbol, Segment, BinaryView, SymbolType, SymbolBinding

import capa.features.extractors.common
import capa.features.extractors.helpers
import capa.features.extractors.strings
from capa.features.file import Export, Import, Section, FunctionName
from capa.features.common import FORMAT_PE, FORMAT_ELF, Format, String, Feature, Characteristic
from capa.features.address import NO_ADDRESS, Address, FileOffsetAddress, AbsoluteVirtualAddress
from capa.features.extractors.binja.helpers import unmangle_c_name


def check_segment_for_pe(bv: BinaryView, seg: Segment) -> Iterator[Tuple[int, int]]:
    """check segment for embedded PE

    adapted for binja from:
    https://github.com/vivisect/vivisect/blob/7be4037b1cecc4551b397f840405a1fc606f9b53/PE/carve.py#L19
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
    # If this is the first segment of the binary, skip the first bytes. Otherwise, there will always be a matched
    # PE at the start of the binaryview.
    start = seg.start
    if bv.view_type == "PE" and start == bv.start:
        start += 1

    for mzx, pex, i in mz_xor:
        for off, _ in bv.find_all_data(start, seg.end, mzx):
            todo.append((off, mzx, pex, i))

    while len(todo):
        off, mzx, pex, i = todo.pop()

        # The MZ header has one field we will check e_lfanew is at 0x3c
        e_lfanew = off + 0x3C

        if seg.end < (e_lfanew + 4):
            continue

        newoff = struct.unpack("<I", capa.features.extractors.helpers.xor_static(bv.read(e_lfanew, 4), i))[0]

        peoff = off + newoff
        if seg.end < (peoff + 2):
            continue

        if bv.read(peoff, 2) == pex:
            yield off, i


def extract_file_embedded_pe(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    """extract embedded PE features"""
    for seg in bv.segments:
        for ea, _ in check_segment_for_pe(bv, seg):
            yield Characteristic("embedded pe"), FileOffsetAddress(ea)


def extract_file_export_names(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    """extract function exports"""
    for sym in bv.get_symbols_of_type(SymbolType.FunctionSymbol):
        if sym.binding in [SymbolBinding.GlobalBinding, SymbolBinding.WeakBinding]:
            name = sym.short_name
            yield Export(name), AbsoluteVirtualAddress(sym.address)
            unmangled_name = unmangle_c_name(name)
            if name != unmangled_name:
                yield Export(unmangled_name), AbsoluteVirtualAddress(sym.address)


def extract_file_import_names(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    """extract function imports

    1. imports by ordinal:
     - modulename.#ordinal

    2. imports by name, results in two features to support importname-only
       matching:
     - modulename.importname
     - importname
    """
    for sym in bv.get_symbols_of_type(SymbolType.ImportAddressSymbol):
        lib_name = str(sym.namespace)
        addr = AbsoluteVirtualAddress(sym.address)
        for name in capa.features.extractors.helpers.generate_symbols(lib_name, sym.short_name):
            yield Import(name), addr

        ordinal = sym.ordinal
        if ordinal != 0 and (lib_name != ""):
            ordinal_name = f"#{ordinal}"
            for name in capa.features.extractors.helpers.generate_symbols(lib_name, ordinal_name):
                yield Import(name), addr


def extract_file_section_names(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    """extract section names"""
    for name, section in bv.sections.items():
        yield Section(name), AbsoluteVirtualAddress(section.start)


def extract_file_strings(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    """extract ASCII and UTF-16 LE strings"""
    for s in bv.strings:
        yield String(s.value), FileOffsetAddress(s.start)


def extract_file_function_names(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    """
    extract the names of statically-linked library functions.
    """
    for sym_name in bv.symbols:
        for sym in bv.symbols[sym_name]:
            if sym.type == SymbolType.LibraryFunctionSymbol:
                name = sym.short_name
                yield FunctionName(name), sym.address
                if name.startswith("_"):
                    # some linkers may prefix linked routines with a `_` to avoid name collisions.
                    # extract features for both the mangled and un-mangled representations.
                    # e.g. `_fwrite` -> `fwrite`
                    # see: https://stackoverflow.com/a/2628384/87207
                    yield FunctionName(name[1:]), sym.address


def extract_file_format(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    view_type = bv.view_type
    if view_type in ["PE", "COFF"]:
        yield Format(FORMAT_PE), NO_ADDRESS
    elif view_type == "ELF":
        yield Format(FORMAT_ELF), NO_ADDRESS
    elif view_type == "Raw":
        # no file type to return when processing a binary file, but we want to continue processing
        return
    else:
        raise NotImplementedError(f"unexpected file format: {view_type}")


def extract_features(bv: BinaryView) -> Iterator[Tuple[Feature, Address]]:
    """extract file features"""
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(bv):
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
    if len(sys.argv) < 2:
        return

    from binaryninja import BinaryViewType

    bv: BinaryView = BinaryViewType.get_view_of_file(sys.argv[1])
    if bv is None:
        return

    import pprint

    pprint.pprint(list(extract_features(bv)))


if __name__ == "__main__":
    main()
