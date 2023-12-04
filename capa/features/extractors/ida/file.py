# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import struct
from typing import Tuple, Iterator

import idc
import idaapi
import idautils
import ida_entry

import capa.features.extractors.common
import capa.features.extractors.helpers
import capa.features.extractors.strings
import capa.features.extractors.ida.helpers
from capa.features.file import Export, Import, Section, FunctionName
from capa.features.common import FORMAT_PE, FORMAT_ELF, Format, String, Feature, Characteristic
from capa.features.address import NO_ADDRESS, Address, FileOffsetAddress, AbsoluteVirtualAddress

MAX_OFFSET_PE_AFTER_MZ = 0x200


def check_segment_for_pe(seg: idaapi.segment_t) -> Iterator[Tuple[int, int]]:
    """check segment for embedded PE

    adapted for IDA from:
    https://github.com/vivisect/vivisect/blob/91e8419a861f49779f18316f155311967e696836/PE/carve.py#L25
    """
    seg_max = seg.end_ea
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
        for off in capa.features.extractors.ida.helpers.find_byte_sequence(seg.start_ea, seg.end_ea, mzx):
            todo.append((off, mzx, pex, i))

    while len(todo):
        off, mzx, pex, i = todo.pop()

        # MZ header has one field we will check e_lfanew is at 0x3c
        e_lfanew = off + 0x3C

        if seg_max < (e_lfanew + 4):
            continue

        newoff = struct.unpack("<I", capa.features.extractors.helpers.xor_static(idc.get_bytes(e_lfanew, 4), i))[0]

        # assume XOR'd "PE" bytes exist within threshold
        if newoff > MAX_OFFSET_PE_AFTER_MZ:
            continue

        peoff = off + newoff
        if seg_max < (peoff + 2):
            continue

        if idc.get_bytes(peoff, 2) == pex:
            yield off, i


def extract_file_embedded_pe() -> Iterator[Tuple[Feature, Address]]:
    """extract embedded PE features

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments(skip_header_segments=True):
        for ea, _ in check_segment_for_pe(seg):
            yield Characteristic("embedded pe"), FileOffsetAddress(ea)


def extract_file_export_names() -> Iterator[Tuple[Feature, Address]]:
    """extract function exports"""
    for _, ordinal, ea, name in idautils.Entries():
        forwarded_name = ida_entry.get_entry_forwarder(ordinal)
        if forwarded_name is None:
            yield Export(name), AbsoluteVirtualAddress(ea)
        else:
            forwarded_name = capa.features.extractors.helpers.reformat_forwarded_export_name(forwarded_name)
            yield Export(forwarded_name), AbsoluteVirtualAddress(ea)
            yield Characteristic("forwarded export"), AbsoluteVirtualAddress(ea)


def extract_file_import_names() -> Iterator[Tuple[Feature, Address]]:
    """extract function imports

    1. imports by ordinal:
     - modulename.#ordinal

    2. imports by name, results in two features to support importname-only
       matching:
     - modulename.importname
     - importname
    """
    for ea, info in capa.features.extractors.ida.helpers.get_file_imports().items():
        addr = AbsoluteVirtualAddress(ea)
        if info[1] and info[2]:
            # e.g. in mimikatz: ('cabinet', 'FCIAddFile', 11L)
            # extract by name here and by ordinal below
            for name in capa.features.extractors.helpers.generate_symbols(info[0], info[1], include_dll=True):
                yield Import(name), addr
            dll = info[0]
            symbol = f"#{info[2]}"
        elif info[1]:
            dll = info[0]
            symbol = info[1]
        elif info[2]:
            dll = info[0]
            symbol = f"#{info[2]}"
        else:
            continue

        for name in capa.features.extractors.helpers.generate_symbols(dll, symbol, include_dll=True):
            yield Import(name), addr

    for ea, info in capa.features.extractors.ida.helpers.get_file_externs().items():
        yield Import(info[1]), AbsoluteVirtualAddress(ea)


def extract_file_section_names() -> Iterator[Tuple[Feature, Address]]:
    """extract section names

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments(skip_header_segments=True):
        yield Section(idaapi.get_segm_name(seg)), AbsoluteVirtualAddress(seg.start_ea)


def extract_file_strings() -> Iterator[Tuple[Feature, Address]]:
    """extract ASCII and UTF-16 LE strings

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments():
        seg_buff = capa.features.extractors.ida.helpers.get_segment_buffer(seg)

        # differing to common string extractor factor in segment offset here
        for s in capa.features.extractors.strings.extract_ascii_strings(seg_buff):
            yield String(s.s), FileOffsetAddress(seg.start_ea + s.offset)

        for s in capa.features.extractors.strings.extract_unicode_strings(seg_buff):
            yield String(s.s), FileOffsetAddress(seg.start_ea + s.offset)


def extract_file_function_names() -> Iterator[Tuple[Feature, Address]]:
    """
    extract the names of statically-linked library functions.
    """
    for ea in idautils.Functions():
        addr = AbsoluteVirtualAddress(ea)
        if idaapi.get_func(ea).flags & idaapi.FUNC_LIB:
            name = idaapi.get_name(ea)
            yield FunctionName(name), addr
            if name.startswith("_"):
                # some linkers may prefix linked routines with a `_` to avoid name collisions.
                # extract features for both the mangled and un-mangled representations.
                # e.g. `_fwrite` -> `fwrite`
                # see: https://stackoverflow.com/a/2628384/87207
                yield FunctionName(name[1:]), addr


def extract_file_format() -> Iterator[Tuple[Feature, Address]]:
    file_info = idaapi.get_inf_structure()

    if file_info.filetype in (idaapi.f_PE, idaapi.f_COFF):
        yield Format(FORMAT_PE), NO_ADDRESS
    elif file_info.filetype == idaapi.f_ELF:
        yield Format(FORMAT_ELF), NO_ADDRESS
    elif file_info.filetype == idaapi.f_BIN:
        # no file type to return when processing a binary file, but we want to continue processing
        return
    else:
        raise NotImplementedError(f"unexpected file format: {file_info.filetype}")


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
