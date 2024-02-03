# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from pathlib import Path

import pefile

import capa.features.common
import capa.features.extractors
import capa.features.extractors.common
import capa.features.extractors.helpers
import capa.features.extractors.strings
from capa.features.file import Export, Import, Section
from capa.features.common import OS, ARCH_I386, FORMAT_PE, ARCH_AMD64, OS_WINDOWS, Arch, Format, Characteristic
from capa.features.address import NO_ADDRESS, FileOffsetAddress, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import SampleHashes, StaticFeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_embedded_pe(buf, **kwargs):
    for offset, _ in capa.features.extractors.helpers.carve_pe(buf, 1):
        yield Characteristic("embedded pe"), FileOffsetAddress(offset)


def extract_file_export_names(pe, **kwargs):
    base_address = pe.OPTIONAL_HEADER.ImageBase

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not export.name:
                continue
            try:
                name = export.name.partition(b"\x00")[0].decode("ascii")
            except UnicodeDecodeError:
                continue

            if export.forwarder is None:
                va = base_address + export.address
                yield Export(name), AbsoluteVirtualAddress(va)

            else:
                try:
                    forwarded_name = export.forwarder.partition(b"\x00")[0].decode("ascii")
                except UnicodeDecodeError:
                    continue
                forwarded_name = capa.features.extractors.helpers.reformat_forwarded_export_name(forwarded_name)
                va = base_address + export.address
                yield Export(forwarded_name), AbsoluteVirtualAddress(va)
                yield Characteristic("forwarded export"), AbsoluteVirtualAddress(va)


def extract_file_import_names(pe, **kwargs):
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
                    impname = f"#{imp.ordinal}"
                else:
                    try:
                        impname = imp.name.partition(b"\x00")[0].decode("ascii")
                    except UnicodeDecodeError:
                        continue

                for name in capa.features.extractors.helpers.generate_symbols(modname, impname, include_dll=True):
                    yield Import(name), AbsoluteVirtualAddress(imp.address)


def extract_file_section_names(pe, **kwargs):
    base_address = pe.OPTIONAL_HEADER.ImageBase

    for section in pe.sections:
        try:
            name = section.Name.partition(b"\x00")[0].decode("ascii")
        except UnicodeDecodeError:
            continue

        yield Section(name), AbsoluteVirtualAddress(base_address + section.VirtualAddress)


def extract_file_strings(buf, **kwargs):
    yield from capa.features.extractors.common.extract_file_strings(buf)


def extract_file_function_names(**kwargs):
    """
    extract the names of statically-linked library functions.
    """
    if False:
        # using a `yield` here to force this to be a generator, not function.
        yield NotImplementedError("pefile doesn't have library matching")
    return


def extract_file_os(**kwargs):
    # assuming PE -> Windows
    # though i suppose they're also used by UEFI
    yield OS(OS_WINDOWS), NO_ADDRESS


def extract_file_format(**kwargs):
    yield Format(FORMAT_PE), NO_ADDRESS


def extract_file_arch(pe, **kwargs):
    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        yield Arch(ARCH_I386), NO_ADDRESS
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        yield Arch(ARCH_AMD64), NO_ADDRESS
    else:
        logger.warning("unsupported architecture: %s", pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine])


def extract_file_features(pe, buf):
    """
    extract file features from given workspace

    args:
      pe (pefile.PE): the parsed PE
      buf: the raw sample bytes

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """

    for file_handler in FILE_HANDLERS:
        # file_handler: type: (pe, bytes) -> Iterable[Tuple[Feature, Address]]
        for feature, va in file_handler(pe=pe, buf=buf):  # type: ignore
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    extract_file_function_names,
    extract_file_format,
)


def extract_global_features(pe, buf):
    """
    extract global features from given workspace

    args:
      pe (pefile.PE): the parsed PE
      buf: the raw sample bytes

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """
    for handler in GLOBAL_HANDLERS:
        # file_handler: type: (pe, bytes) -> Iterable[Tuple[Feature, Address]]
        for feature, va in handler(pe=pe, buf=buf):  # type: ignore
            yield feature, va


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


class PefileFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, path: Path):
        super().__init__(hashes=SampleHashes.from_bytes(path.read_bytes()))
        self.path: Path = path
        self.pe = pefile.PE(str(path))

    def get_base_address(self):
        return AbsoluteVirtualAddress(self.pe.OPTIONAL_HEADER.ImageBase)

    def extract_global_features(self):
        buf = Path(self.path).read_bytes()

        yield from extract_global_features(self.pe, buf)

    def extract_file_features(self):
        buf = Path(self.path).read_bytes()

        yield from extract_file_features(self.pe, buf)

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
