# Copyright 2023 Google LLC
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

import pefile
from elftools.elf.elffile import ELFFile

import capa.features.common
import capa.features.extractors.common
import capa.features.extractors.pefile
import capa.features.extractors.elffile
from capa.features.common import Feature
from capa.features.address import Address
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def extract_file_export_names(_be2: BinExport2, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    if buf.startswith(capa.features.extractors.common.MATCH_PE):
        pe: pefile.PE = pefile.PE(data=buf)
        yield from capa.features.extractors.pefile.extract_file_export_names(pe)
    elif buf.startswith(capa.features.extractors.common.MATCH_ELF):
        elf: ELFFile = ELFFile(io.BytesIO(buf))
        yield from capa.features.extractors.elffile.extract_file_export_names(elf)
    else:
        logger.warning("unsupported format")


def extract_file_import_names(_be2: BinExport2, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    if buf.startswith(capa.features.extractors.common.MATCH_PE):
        pe: pefile.PE = pefile.PE(data=buf)
        yield from capa.features.extractors.pefile.extract_file_import_names(pe)
    elif buf.startswith(capa.features.extractors.common.MATCH_ELF):
        elf: ELFFile = ELFFile(io.BytesIO(buf))
        yield from capa.features.extractors.elffile.extract_file_import_names(elf)
    else:
        logger.warning("unsupported format")


def extract_file_section_names(_be2: BinExport2, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    if buf.startswith(capa.features.extractors.common.MATCH_PE):
        pe: pefile.PE = pefile.PE(data=buf)
        yield from capa.features.extractors.pefile.extract_file_section_names(pe)
    elif buf.startswith(capa.features.extractors.common.MATCH_ELF):
        elf: ELFFile = ELFFile(io.BytesIO(buf))
        yield from capa.features.extractors.elffile.extract_file_section_names(elf)
    else:
        logger.warning("unsupported format")


def extract_file_strings(_be2: BinExport2, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    yield from capa.features.extractors.common.extract_file_strings(buf)


def extract_file_format(_be2: BinExport2, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    yield from capa.features.extractors.common.extract_format(buf)


def extract_features(be2: BinExport2, buf: bytes) -> Iterator[tuple[Feature, Address]]:
    """extract file features"""
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(be2, buf):
            yield feature, addr


FILE_HANDLERS = (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_strings,
    extract_file_section_names,
    extract_file_format,
)
