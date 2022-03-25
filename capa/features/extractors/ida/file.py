# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import struct

import idc
import idaapi
import idautils
import ida_loader

import capa.features.extractors.helpers
import capa.features.extractors.strings
import capa.features.extractors.ida.helpers
from capa.features.file import Export, Import, Section, FunctionName
from capa.features.common import OS, FORMAT_PE, FORMAT_ELF, OS_WINDOWS, Format, String, Characteristic


def check_segment_for_pe(seg):
    """check segment for embedded PE

    adapted for IDA from:
    https://github.com/vivisect/vivisect/blob/7be4037b1cecc4551b397f840405a1fc606f9b53/PE/carve.py#L19

    args:
        seg (IDA segment_t)
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
    for (mzx, pex, i) in mz_xor:
        for off in capa.features.extractors.ida.helpers.find_byte_sequence(seg.start_ea, seg.end_ea, mzx):
            todo.append((off, mzx, pex, i))

    while len(todo):
        off, mzx, pex, i = todo.pop()

        # The MZ header has one field we will check e_lfanew is at 0x3c
        e_lfanew = off + 0x3C

        if seg_max < (e_lfanew + 4):
            continue

        newoff = struct.unpack("<I", capa.features.extractors.helpers.xor_static(idc.get_bytes(e_lfanew, 4), i))[0]

        peoff = off + newoff
        if seg_max < (peoff + 2):
            continue

        if idc.get_bytes(peoff, 2) == pex:
            yield (off, i)

        for nextres in capa.features.extractors.ida.helpers.find_byte_sequence(off + 1, seg.end_ea, mzx):
            todo.append((nextres, mzx, pex, i))


def extract_file_embedded_pe():
    """extract embedded PE features

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments(skip_header_segments=True):
        for (ea, _) in check_segment_for_pe(seg):
            yield Characteristic("embedded pe"), ea


def extract_file_export_names():
    """extract function exports"""
    for (_, _, ea, name) in idautils.Entries():
        yield Export(name), ea


def extract_file_import_names():
    """extract function imports

    1. imports by ordinal:
     - modulename.#ordinal

    2. imports by name, results in two features to support importname-only
       matching:
     - modulename.importname
     - importname
    """
    for (ea, info) in capa.features.extractors.ida.helpers.get_file_imports().items():
        if info[1] and info[2]:
            # e.g. in mimikatz: ('cabinet', 'FCIAddFile', 11L)
            # extract by name here and by ordinal below
            for name in capa.features.extractors.helpers.generate_symbols(info[0], info[1]):
                yield Import(name), ea
            dll = info[0]
            symbol = "#%d" % (info[2])
        elif info[1]:
            dll = info[0]
            symbol = info[1]
        elif info[2]:
            dll = info[0]
            symbol = "#%d" % (info[2])
        else:
            continue

        for name in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield Import(name), ea


def extract_file_section_names():
    """extract section names

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments(skip_header_segments=True):
        yield Section(idaapi.get_segm_name(seg)), seg.start_ea


def extract_file_strings():
    """extract ASCII and UTF-16 LE strings

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments():
        seg_buff = capa.features.extractors.ida.helpers.get_segment_buffer(seg)

        for s in capa.features.extractors.strings.extract_ascii_strings(seg_buff):
            yield String(s.s), (seg.start_ea + s.offset)

        for s in capa.features.extractors.strings.extract_unicode_strings(seg_buff):
            yield String(s.s), (seg.start_ea + s.offset)


def extract_file_function_names():
    """
    extract the names of statically-linked library functions.
    """
    for ea in idautils.Functions():
        if idaapi.get_func(ea).flags & idaapi.FUNC_LIB:
            name = idaapi.get_name(ea)
            yield FunctionName(name), ea
            if name.startswith("_"):
                # some linkers may prefix linked routines with a `_` to avoid name collisions.
                # extract features for both the mangled and un-mangled representations.
                # e.g. `_fwrite` -> `fwrite`
                # see: https://stackoverflow.com/a/2628384/87207
                yield FunctionName(name[1:]), ea


def extract_file_format():
    file_info = idaapi.get_inf_structure()

    if file_info.filetype == idaapi.f_PE:
        yield Format(FORMAT_PE), 0x0
    elif file_info.filetype == idaapi.f_ELF:
        yield Format(FORMAT_ELF), 0x0
    elif file_info.filetype == idaapi.f_BIN:
        # no file type to return when processing a binary file, but we want to continue processing
        return
    else:
        raise NotImplementedError("file format: %d" % file_info.filetype)


def extract_features():
    """extract file features"""
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler():
            yield feature, va


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
