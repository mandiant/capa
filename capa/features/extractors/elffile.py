# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import io
import logging
from typing import Tuple, Iterator

from elftools.elf.elffile import ELFFile, SymbolTableSection

import capa.features.extractors.common
from capa.features.file import Import, Section
from capa.features.common import OS, FORMAT_ELF, Arch, Format, Feature
from capa.features.address import NO_ADDRESS, FileOffsetAddress, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_import_names(elf, **kwargs):
    # see https://github.com/eliben/pyelftools/blob/0664de05ed2db3d39041e2d51d19622a8ef4fb0f/scripts/readelf.py#L372
    symbol_tables = [(idx, s) for idx, s in enumerate(elf.iter_sections()) if isinstance(s, SymbolTableSection)]

    for _, section in symbol_tables:
        if not isinstance(section, SymbolTableSection):
            continue

        if section["sh_entsize"] == 0:
            logger.debug("Symbol table '%s' has a sh_entsize of zero!", section.name)
            continue

        logger.debug("Symbol table '%s' contains %s entries:", section.name, section.num_symbols())

        for _, symbol in enumerate(section.iter_symbols()):
            if symbol.name and symbol.entry.st_info.type == "STT_FUNC":
                # TODO symbol address
                # TODO symbol version info?
                yield Import(symbol.name), FileOffsetAddress(0x0)


def extract_file_section_names(elf, **kwargs):
    for section in elf.iter_sections():
        if section.name:
            yield Section(section.name), AbsoluteVirtualAddress(section.header.sh_addr)
        elif section.is_null():
            yield Section("NULL"), AbsoluteVirtualAddress(section.header.sh_addr)


def extract_file_strings(buf, **kwargs):
    yield from capa.features.extractors.common.extract_file_strings(buf)


def extract_file_os(elf, buf, **kwargs):
    # our current approach does not always get an OS value, e.g. for packed samples
    # for file limitation purposes, we're more lax here
    try:
        os_tuple = next(capa.features.extractors.common.extract_os(buf))
        yield os_tuple
    except StopIteration:
        yield OS("unknown"), NO_ADDRESS


def extract_file_format(**kwargs):
    yield Format(FORMAT_ELF), NO_ADDRESS


def extract_file_arch(elf, **kwargs):
    # TODO merge with capa.features.extractors.elf.detect_elf_arch()
    arch = elf.get_machine_arch()
    if arch == "x86":
        yield Arch("i386"), NO_ADDRESS
    elif arch == "x64":
        yield Arch("amd64"), NO_ADDRESS
    else:
        logger.warning("unsupported architecture: %s", arch)


def extract_file_features(elf: ELFFile, buf: bytes) -> Iterator[Tuple[Feature, int]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(elf=elf, buf=buf):  # type: ignore
            yield feature, addr


FILE_HANDLERS = (
    # TODO extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    # no library matching
    extract_file_format,
)


def extract_global_features(elf: ELFFile, buf: bytes) -> Iterator[Tuple[Feature, int]]:
    for global_handler in GLOBAL_HANDLERS:
        for feature, addr in global_handler(elf=elf, buf=buf):  # type: ignore
            yield feature, addr


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


class ElfFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super().__init__()
        self.path = path
        with open(self.path, "rb") as f:
            self.elf = ELFFile(io.BytesIO(f.read()))

    def get_base_address(self):
        # virtual address of the first segment with type LOAD
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                return AbsoluteVirtualAddress(segment.header.p_vaddr)

    def extract_global_features(self):
        with open(self.path, "rb") as f:
            buf = f.read()

        for feature, addr in extract_global_features(self.elf, buf):
            yield feature, addr

    def extract_file_features(self):
        with open(self.path, "rb") as f:
            buf = f.read()

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
