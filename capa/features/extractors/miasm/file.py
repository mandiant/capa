# Copyright (C) 2020 FireEye, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: https://github.com/fireeye/capa/blob/master/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re

import miasm.analysis.binary

import capa.features.extractors.strings
from capa.features import String, Characteristic
from capa.features.file import Export, Import, Section


def extract_file_embedded_pe(extractor):
    """
    extract embedded PE features
    """
    buf = extractor.buf
    for match in re.finditer(b"MZ", buf):
        offset = match.start()
        subcontainer = miasm.analysis.binary.ContainerPE.from_string(buf[offset:], loc_db=extractor.loc_db)
        if isinstance(subcontainer, miasm.analysis.binary.ContainerPE):
            yield Characteristic("embedded pe"), offset


def extract_file_export_names(extractor):
    """
    extract file exports and their addresses
    """
    for symbol, va in miasm.jitter.loader.pe.get_export_name_addr_list(extractor.pe):
        # Only use func names and not ordinals
        if isinstance(symbol, str):
            yield Export(symbol), va


def extract_file_import_names(extractor):
    """
    extract imported function names and their addresses
    1. imports by ordinal:
     - modulename.#ordinal
    2. imports by name, results in two features to support importname-only matching:
     - modulename.importname
     - importname
    """
    for ((dll, symbol), va_set) in miasm.jitter.loader.pe.get_import_address_pe(extractor.pe).items():
        dll_name = dll[:-4]  # Remove .dll
        for va in va_set:
            if isinstance(symbol, int):
                yield Import("%s.#%s" % (dll_name, symbol)), va
            else:
                yield Import("%s.%s" % (dll_name, symbol)), va
                yield Import(symbol), va


def extract_file_section_names(extractor):
    """
    extract file sections and their addresses
    """
    for section in extractor.pe.SHList.shlist:
        name = section.name.partition(b"\x00")[0].decode("ascii")
        va = section.addr
        yield Section(name), va


def extract_file_strings(extractor):
    """
    extract ASCII and UTF-16 LE strings from file
    """
    for s in capa.features.extractors.strings.extract_ascii_strings(extractor.buf):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(extractor.buf):
        yield String(s.s), s.offset


def extract_file_features(extractor):
    """
    extract file features from given buffer and parsed binary

    args:
      buf (bytes): binary content
      container (miasm.analysis.binary.ContainerPE): parsed binary returned by miasm

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(extractor):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
)
