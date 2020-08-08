import pefile

import capa.features.extractors.strings
from capa.features import String, Characteristic
from capa.features.file import Export, Import, Section


def extract_file_embedded_pe(buf, pe):
    buf = buf[2:]

    total_offset = 2
    while True:
        try:
            offset = buf.index(b"MZ")
        except ValueError:
            return
        else:
            rest = buf[offset:]
            total_offset += offset

            try:
                _ = pefile.PE(data=rest)
            except:
                pass
            else:
                yield Characteristic("embedded pe"), total_offset

            buf = rest[2:]
            total_offset += 2


def extract_file_export_names(buf, pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return

    base_address = pe.OPTIONAL_HEADER.ImageBase
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        yield Export(exp.name.decode("ascii")), base_address + exp.address


def extract_file_import_names(buf, pe):
    base_address = pe.OPTIONAL_HEADER.ImageBase
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        libname = entry.dll.decode("ascii").lower().partition(".")[0]
        for imp in entry.imports:
            impaddr = base_address + imp.address
            if imp.ordinal:
                yield Import("%s.#%s" % (libname, imp.ordinal)), impaddr
            else:
                impname = imp.name.decode("ascii")
                yield Import("%s.%s" % (libname, impname)), impaddr
                yield Import("%s" % (impname)), impaddr


def extract_file_section_names(buf, pe):
    base_address = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        yield Section(section.Name.partition(b"\x00")[0].decode("ascii")), base_address + section.VirtualAddress


def extract_file_strings(buf, pe):
    for s in capa.features.extractors.strings.extract_ascii_strings(buf):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(buf):
        yield String(s.s), s.offset


def extract_file_features(buf):
    pe = pefile.PE(data=buf)
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(buf, pe):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
)
