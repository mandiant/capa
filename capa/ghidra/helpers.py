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

import logging
import datetime
import contextlib
from pathlib import Path

import capa
import capa.version
import capa.features.common
import capa.features.freeze
import capa.render.result_document as rdoc
import capa.features.extractors.ghidra.context as ghidra_context
import capa.features.extractors.ghidra.helpers
from capa.features.address import AbsoluteVirtualAddress

logger = logging.getLogger("capa")

# file type as returned by Ghidra
SUPPORTED_FILE_TYPES = ("Executable and Linking Format (ELF)", "Portable Executable (PE)", "Raw Binary")


def get_current_program():
    return ghidra_context.get_context().program


def get_flat_api():
    return ghidra_context.get_context().flat_api


def get_monitor():
    return ghidra_context.get_context().monitor


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
        logger.debug(
            "reading 0x%x bytes at 0x%x (ea: 0x%x)",
            size,
            self.offset,
            get_current_program().getImageBase().add(self.offset).getOffset(),
        )

        if size > len(self.bytes_) - self.offset:
            logger.debug("cannot read 0x%x bytes at 0x%x (ea: BADADDR)", size, self.offset)
            return b""
        else:
            return self.bytes_[self.offset : self.offset + size]

    def close(self):
        return

    def get_bytes(self):
        file_bytes = get_current_program().getMemory().getAllFileBytes()[0]

        # getOriginalByte() allows for raw file parsing on the Ghidra side
        # other functions will fail as Ghidra will think that it's reading uninitialized memory
        bytes_ = [file_bytes.getOriginalByte(i) for i in range(file_bytes.getSize())]

        return capa.features.extractors.ghidra.helpers.ints_to_bytes(bytes_)


def is_supported_ghidra_version():
    import ghidra.framework

    version = ghidra.framework.Application.getApplicationVersion()
    try:
        # version format example: "11.1.2" or "11.4"
        major, minor = map(int, version.split(".")[:2])
        if major < 12:
            logger.error("-" * 80)
            logger.error(" Ghidra version %s is not supported.", version)
            logger.error(" ")
            logger.error(" capa requires Ghidra 12.0 or higher.")
            logger.error("-" * 80)
            return False
    except ValueError:
        logger.warning("could not parse Ghidra version: %s", version)
        return False

    return True


def is_running_headless():
    return True  # PyGhidra is always headless in this context


def is_supported_file_type():
    file_info = get_current_program().getExecutableFormat()
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
    lang_id = str(get_current_program().getLanguageID()).lower()

    if not all((lang_id.startswith("x86"), any(arch in lang_id for arch in ("32", "64")))):
        logger.error("-" * 80)
        logger.error(" Input file does not appear to target a supported architecture.")
        logger.error(" ")
        logger.error(" capa currently only supports analyzing x86 (32- and 64-bit).")
        logger.error("-" * 80)
        return False
    return True


def get_file_md5():
    return get_current_program().getExecutableMD5()


def get_file_sha256():
    return get_current_program().getExecutableSHA256()


def collect_metadata(rules: list[Path]):
    md5 = get_file_md5()
    sha256 = get_file_sha256()

    info = get_current_program().getLanguageID().toString()
    if "x86" in info and "64" in info:
        arch = "x86_64"
    elif "x86" in info and "32" in info:
        arch = "x86"
    else:
        arch = "unknown arch"

    format_name: str = get_current_program().getExecutableFormat()
    if "PE" in format_name:
        os = "windows"
    elif "ELF" in format_name:
        with contextlib.closing(GHIDRAIO()) as f:
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
            path=get_current_program().getExecutablePath(),
        ),
        flavor=rdoc.Flavor.STATIC,
        analysis=rdoc.StaticAnalysis(
            format=get_current_program().getExecutableFormat(),
            arch=arch,
            os=os,
            extractor="ghidra",
            rules=tuple(r.resolve().absolute().as_posix() for r in rules),
            base_address=capa.features.freeze.Address.from_capa(
                AbsoluteVirtualAddress(get_current_program().getImageBase().getOffset())
            ),
            layout=rdoc.StaticLayout(
                functions=(),
            ),
            feature_counts=rdoc.StaticFeatureCounts(file=0, functions=()),
            library_functions=(),
        ),
    )
