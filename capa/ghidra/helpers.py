# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
import datetime
import contextlib
from typing import List
from pathlib import Path

import capa
import capa.version
import capa.features.common
import capa.features.freeze
import capa.render.result_document as rdoc
import capa.features.extractors.ghidra.helpers

logger = logging.getLogger("capa")

# file type as returned by Ghidra
SUPPORTED_FILE_TYPES = ("Executable and Linking Format (ELF)", "Portable Executable (PE)", "Raw Binary")


class GHIDRAIO:
    """
    An object that acts as a file-like object,
    using bytes from the current Ghidra listing.
    """

    def __init__(self):
        super().__init__()

        self.offset = 0
        self.bytes_ = self.get_bytes()

    def seek(self, offset, whence=0):
        assert whence == 0
        self.offset = offset

    def read(self, size):
        logger.debug("reading 0x%x bytes at 0x%x (ea: 0x%x)", size, self.offset, currentProgram().getImageBase().add(self.offset).getOffset())  # type: ignore [name-defined] # noqa: F821

        if size > len(self.bytes_) - self.offset:
            logger.debug("cannot read 0x%x bytes at 0x%x (ea: BADADDR)", size, self.offset)
            return b""
        else:
            return self.bytes_[self.offset : self.offset + size]

    def close(self):
        return

    def get_bytes(self):
        file_bytes = currentProgram().getMemory().getAllFileBytes()[0]  # type: ignore [name-defined] # noqa: F821

        # getOriginalByte() allows for raw file parsing on the Ghidra side
        # other functions will fail as Ghidra will think that it's reading uninitialized memory
        bytes_ = [file_bytes.getOriginalByte(i) for i in range(file_bytes.getSize())]

        return capa.features.extractors.ghidra.helpers.ints_to_bytes(bytes_)


def is_supported_ghidra_version():
    version = float(getGhidraVersion()[:4])  # type: ignore [name-defined] # noqa: F821
    if version < 10.2:
        warning_msg = "capa does not support this Ghidra version"
        logger.warning(warning_msg)
        logger.warning("Your Ghidra version is: %s. Supported versions are: Ghidra >= 10.2", version)
        return False
    return True


def is_running_headless():
    return isRunningHeadless()  # type: ignore [name-defined] # noqa: F821


def is_supported_file_type():
    file_info = currentProgram().getExecutableFormat()  # type: ignore [name-defined] # noqa: F821
    if file_info not in SUPPORTED_FILE_TYPES:
        logger.error("-" * 80)
        logger.error(" Input file does not appear to be a supported file type.")
        logger.error(" ")
        logger.error(
            " capa currently only supports analyzing PE, ELF, or binary files containing x86 (32- and 64-bit) shellcode."
        )
        logger.error(" If you don't know the input file type, you can try using the `file` utility to guess it.")
        logger.error("-" * 80)
        return False
    return True


def is_supported_arch_type():
    lang_id = str(currentProgram().getLanguageID()).lower()  # type: ignore [name-defined] # noqa: F821

    if not all((lang_id.startswith("x86"), any(arch in lang_id for arch in ("32", "64")))):
        logger.error("-" * 80)
        logger.error(" Input file does not appear to target a supported architecture.")
        logger.error(" ")
        logger.error(" capa currently only supports analyzing x86 (32- and 64-bit).")
        logger.error("-" * 80)
        return False
    return True


def get_file_md5():
    return currentProgram().getExecutableMD5()  # type: ignore [name-defined] # noqa: F821


def get_file_sha256():
    return currentProgram().getExecutableSHA256()  # type: ignore [name-defined] # noqa: F821


def collect_metadata(rules: List[Path]):
    md5 = get_file_md5()
    sha256 = get_file_sha256()

    info = currentProgram().getLanguageID().toString()  # type: ignore [name-defined] # noqa: F821
    if "x86" in info and "64" in info:
        arch = "x86_64"
    elif "x86" in info and "32" in info:
        arch = "x86"
    else:
        arch = "unknown arch"

    format_name: str = currentProgram().getExecutableFormat()  # type: ignore [name-defined] # noqa: F821
    if "PE" in format_name:
        os = "windows"
    elif "ELF" in format_name:
        with contextlib.closing(capa.ghidra.helpers.GHIDRAIO()) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)
    else:
        os = "unknown os"

    return rdoc.Metadata(
        timestamp=datetime.datetime.now(),
        version=capa.version.__version__,
        argv=(),
        sample=rdoc.Sample(
            md5=md5,
            sha1="",
            sha256=sha256,
            path=currentProgram().getExecutablePath(),  # type: ignore [name-defined] # noqa: F821
        ),
        flavor=rdoc.Flavor.STATIC,
        analysis=rdoc.StaticAnalysis(
            format=currentProgram().getExecutableFormat(),  # type: ignore [name-defined] # noqa: F821
            arch=arch,
            os=os,
            extractor="ghidra",
            rules=tuple(r.resolve().absolute().as_posix() for r in rules),
            base_address=capa.features.freeze.Address.from_capa(currentProgram().getImageBase().getOffset()),  # type: ignore [name-defined] # noqa: F821
            layout=rdoc.StaticLayout(
                functions=(),
            ),
            feature_counts=rdoc.StaticFeatureCounts(file=0, functions=()),
            library_functions=(),
        ),
    )
