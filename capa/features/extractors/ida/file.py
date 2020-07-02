import struct
import pprint

import idautils
import idaapi
import idc

from capa.features import String
from capa.features import Characteristic
from capa.features.file import Section
from capa.features.file import Export
from capa.features.file import Import
import capa.features.extractors.strings
import capa.features.extractors.helpers
import capa.features.extractors.ida.helpers


def _ida_check_segment_for_pe(seg):
    """ check segment for embedded PE

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
    todo = [
        (capa.features.extractors.ida.helpers.find_byte_sequence(seg.start_ea, seg.end_ea, mzx), mzx, pex, i)
        for mzx, pex, i in mz_xor
    ]
    todo = [(off, mzx, pex, i) for (off, mzx, pex, i) in todo if off != idaapi.BADADDR]

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

        nextres = capa.features.extractors.ida.helpers.find_byte_sequence(off + 1, seg.end_ea, mzx)
        if nextres != -1:
            todo.append((nextres, mzx, pex, i))


def extract_file_embedded_pe():
    """ extract embedded PE features

        IDA must load resource sections for this to be complete
            - '-R' from console
            - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments():
        if seg.is_header_segm():
            # IDA may load header segments, skip if present
            continue

        for ea, _ in _ida_check_segment_for_pe(seg):
            yield Characteristic('embedded pe'), ea


def extract_file_export_names():
    """ extract function exports """
    for _, _, ea, name in idautils.Entries():
        yield Export(name), ea


def extract_file_import_names():
    """ extract function imports

        1. imports by ordinal:
         - modulename.#ordinal

        2. imports by name, results in two features to support importname-only
           matching:
         - modulename.importname
         - importname
    """
    for ea, imp_info in capa.features.extractors.ida.helpers.get_file_imports().items():
        dllname, name, ordi = imp_info

        if name:
            yield Import("%s.%s" % (dllname, name)), ea
            yield Import(name), ea

        if ordi:
            yield Import("%s.#%s" % (dllname, str(ordi))), ea


def extract_file_section_names():
    """ extract section names

        IDA must load resource sections for this to be complete
            - '-R' from console
            - Check 'Load resource sections' when opening binary in IDA manually
    """
    for seg in capa.features.extractors.ida.helpers.get_segments():
        if seg.is_header_segm():
            # IDA may load header segments, skip if present
            continue

        yield Section(idaapi.get_segm_name(seg)), seg.start_ea


def extract_file_strings():
    """ extract ASCII and UTF-16 LE strings

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


def extract_features():
    """ extract file features """
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler():
            yield feature, va


FILE_HANDLERS = (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_strings,
    extract_file_section_names,
    extract_file_embedded_pe,
)


def main():
    pprint.pprint(list(extract_features()))


if __name__ == "__main__":
    main()
