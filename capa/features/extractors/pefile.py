# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging

import pefile

import capa.features.extractors
import capa.features.extractors.helpers
import capa.features.extractors.strings
from capa.features.file import Export, Import, Section
from capa.features.common import String, Characteristic
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_embedded_pe(pe, file_path):
    with open(file_path, "rb") as f:
        fbytes = f.read()

    for offset, i in capa.features.extractors.helpers.carve_pe(fbytes, 1):
        yield Characteristic("embedded pe"), offset


def extract_file_export_names(pe, file_path):
    base_address = pe.OPTIONAL_HEADER.ImageBase

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                name = export.name.partition(b"\x00")[0].decode("ascii")
            except UnicodeDecodeError:
                continue
            va = base_address + export.address
            yield Export(name), va


def extract_file_import_names(pe, file_path):
    """
    extract imported function names
    1. imports by ordinal:
     - modulename.#ordinal
    2. imports by name, results in two features to support importname-only matching:
     - modulename.importname
     - importname
    """
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                modname = dll.dll.partition(b"\x00")[0].decode("ascii")
            except UnicodeDecodeError:
                continue

            # strip extension
            modname = modname.rpartition(".")[0].lower()

            for imp in dll.imports:
                if imp.import_by_ordinal:
                    impname = "#%s" % imp.ordinal
                else:
                    try:
                        impname = imp.name.partition(b"\x00")[0].decode("ascii")
                    except UnicodeDecodeError:
                        continue

                for name in capa.features.extractors.helpers.generate_symbols(modname, impname):
                    yield Import(name), imp.address


def extract_file_section_names(pe, file_path):
    base_address = pe.OPTIONAL_HEADER.ImageBase

    for section in pe.sections:
        try:
            name = section.Name.partition(b"\x00")[0].decode("ascii")
        except UnicodeDecodeError:
            continue

        yield Section(name), base_address + section.VirtualAddress


def extract_file_strings(pe, file_path):
    """
    extract ASCII and UTF-16 LE strings from file
    """
    with open(file_path, "rb") as f:
        b = f.read()

    for s in capa.features.extractors.strings.extract_ascii_strings(b):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(b):
        yield String(s.s), s.offset


def extract_file_function_names(pe, file_path):
    """
    extract the names of statically-linked library functions.
    """
    if False:
        # using a `yield` here to force this to be a generator, not function.
        yield NotImplementedError("pefile doesn't have library matching")
    return


def extract_file_features(pe, file_path):
    """
    extract file features from given workspace

    args:
      pe (pefile.PE): the parsed PE
      file_path: path to the input file

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """

    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(pe, file_path):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    extract_file_function_names,
)


class PefileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super(PefileFeatureExtractor, self).__init__()
        self.path = path
        self.pe = pefile.PE(path)

    def get_base_address(self):
        return self.pe.OPTIONAL_HEADER.ImageBase

    def extract_file_features(self):
        for feature, va in extract_file_features(self.pe, self.path):
            yield feature, va

    def get_functions(self):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")

    def extract_function_features(self, f):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")

    def get_basic_blocks(self, f):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")

    def extract_basic_block_features(self, f, bb):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")

    def get_instructions(self, f, bb):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")

    def extract_insn_features(self, f, bb, insn):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")

    def is_library_function(self, va):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")

    def get_function_name(self, va):
        raise NotImplementedError("PefileFeatureExtract can only be used to extract file features")
