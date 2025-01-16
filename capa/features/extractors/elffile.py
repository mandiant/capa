# Copyright 2021 Google LLC
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

import io
import logging
from typing import Iterator
from pathlib import Path

from elftools.elf.elffile import ELFFile, DynamicSegment, SymbolTableSection

import capa.features.extractors.common
from capa.features.file import Export, Import, Section
from capa.features.common import OS, FORMAT_ELF, Arch, Format, Feature
from capa.features.address import NO_ADDRESS, FileOffsetAddress, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import SampleHashes, StaticFeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_export_names(elf: ELFFile, **kwargs):
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue

        if section["sh_entsize"] == 0:
            logger.debug("Symbol table '%s' has a sh_entsize of zero!", section.name)
            continue

        logger.debug("Symbol table '%s' contains %s entries:", section.name, section.num_symbols())

        for symbol in section.iter_symbols():
            # The following conditions are based on the following article
            # http://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
            if not symbol.name:
                continue
            if symbol.entry.st_info.type not in ["STT_FUNC", "STT_OBJECT", "STT_IFUNC"]:
                continue
            if symbol.entry.st_value == 0:
                continue
            if symbol.entry.st_shndx == "SHN_UNDEF":
                continue

            yield Export(symbol.name), AbsoluteVirtualAddress(symbol.entry.st_value)

    for segment in elf.iter_segments():
        if not isinstance(segment, DynamicSegment):
            continue

        tab_ptr, tab_offset = segment.get_table_offset("DT_SYMTAB")
        if tab_ptr is None or tab_offset is None:
            logger.debug("Dynamic segment doesn't contain DT_SYMTAB")
            continue

        logger.debug("Dynamic segment contains %s symbols: ", segment.num_symbols())

        for symbol in segment.iter_symbols():
            # The following conditions are based on the following article
            # http://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
            if not symbol.name:
                continue
            if symbol.entry.st_info.type not in ["STT_FUNC", "STT_OBJECT", "STT_IFUNC"]:
                continue
            if symbol.entry.st_value == 0:
                continue
            if symbol.entry.st_shndx == "SHN_UNDEF":
                continue

            yield Export(symbol.name), AbsoluteVirtualAddress(symbol.entry.st_value)


def extract_file_import_names(elf: ELFFile, **kwargs):
    symbol_name_by_index: dict[int, str] = {}

    # Extract symbol names and store them in the dictionary
    for segment in elf.iter_segments():
        if not isinstance(segment, DynamicSegment):
            continue

        tab_ptr, tab_offset = segment.get_table_offset("DT_SYMTAB")
        if tab_ptr is None or tab_offset is None:
            logger.debug("Dynamic segment doesn't contain DT_SYMTAB")
            continue

        for i, symbol in enumerate(segment.iter_symbols()):
            # The following conditions are based on the following article
            # http://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
            if not symbol.name:
                continue
            if symbol.entry.st_info.type not in ["STT_FUNC", "STT_OBJECT", "STT_IFUNC"]:
                continue
            if symbol.entry.st_value != 0:
                continue
            if symbol.entry.st_shndx != "SHN_UNDEF":
                continue
            if symbol.entry.st_name == 0:
                continue

            symbol_name_by_index[i] = symbol.name

    for segment in elf.iter_segments():
        if not isinstance(segment, DynamicSegment):
            continue

        relocation_tables = segment.get_relocation_tables()
        logger.debug("Dynamic Segment contains %s relocation tables:", len(relocation_tables))

        for relocation_table in relocation_tables.values():
            relocations = []
            for i in range(relocation_table.num_relocations()):
                try:
                    relocations.append(relocation_table.get_relocation(i))
                except TypeError:
                    # ELF is corrupt and the relocation table is invalid,
                    # so stop processing it.
                    break

            for relocation in relocations:
                if "r_info_sym" not in relocation.entry or "r_offset" not in relocation.entry:
                    continue

                symbol_address: int = relocation["r_offset"]
                symbol_index: int = relocation["r_info_sym"]

                if symbol_index not in symbol_name_by_index:
                    continue
                symbol_name = symbol_name_by_index[symbol_index]

                yield Import(symbol_name), FileOffsetAddress(symbol_address)


def extract_file_section_names(elf: ELFFile, **kwargs):
    for section in elf.iter_sections():
        if section.name:
            yield Section(section.name), AbsoluteVirtualAddress(section.header.sh_addr)
        elif section.is_null():
            yield Section("NULL"), AbsoluteVirtualAddress(section.header.sh_addr)


def extract_file_strings(buf, **kwargs):
    yield from capa.features.extractors.common.extract_file_strings(buf)


def extract_file_os(elf: ELFFile, buf, **kwargs):
    # our current approach does not always get an OS value, e.g. for packed samples
    # for file limitation purposes, we're more lax here
    try:
        os_tuple = next(capa.features.extractors.common.extract_os(buf))
        yield os_tuple
    except StopIteration:
        yield OS("unknown"), NO_ADDRESS


def extract_file_format(**kwargs):
    yield Format(FORMAT_ELF), NO_ADDRESS


def extract_file_arch(elf: ELFFile, **kwargs):
    arch = elf.get_machine_arch()
    if arch == "x86":
        yield Arch("i386"), NO_ADDRESS
    elif arch == "x64":
        yield Arch("amd64"), NO_ADDRESS
    elif arch == "ARM":
        yield Arch("arm"), NO_ADDRESS
    elif arch == "AArch64":
        yield Arch("aarch64"), NO_ADDRESS
    else:
        logger.warning("unsupported architecture: %s", arch)


def extract_file_features(elf: ELFFile, buf: bytes) -> Iterator[tuple[Feature, int]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(elf=elf, buf=buf):  # type: ignore
            yield feature, addr


FILE_HANDLERS = (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    # no library matching
    extract_file_format,
)


def extract_global_features(elf: ELFFile, buf: bytes) -> Iterator[tuple[Feature, int]]:
    for global_handler in GLOBAL_HANDLERS:
        for feature, addr in global_handler(elf=elf, buf=buf):  # type: ignore
            yield feature, addr


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


class ElfFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, path: Path):
        super().__init__(SampleHashes.from_bytes(path.read_bytes()))
        self.path: Path = path
        self.elf = ELFFile(io.BytesIO(path.read_bytes()))

    def get_base_address(self):
        # virtual address of the first segment with type LOAD
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                return AbsoluteVirtualAddress(segment.header.p_vaddr)

    def extract_global_features(self):
        buf = self.path.read_bytes()

        for feature, addr in extract_global_features(self.elf, buf):
            yield feature, addr

    def extract_file_features(self):
        buf = self.path.read_bytes()

        for feature, addr in extract_file_features(self.elf, buf):
            yield feature, addr

    def get_functions(self):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def extract_function_features(self, f):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def get_basic_blocks(self, f):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def extract_basic_block_features(self, f, bb):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def get_instructions(self, f, bb):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def extract_insn_features(self, f, bb, insn):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def is_library_function(self, addr):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")

    def get_function_name(self, addr):
        raise NotImplementedError("ElfFeatureExtractor can only be used to extract file features")
