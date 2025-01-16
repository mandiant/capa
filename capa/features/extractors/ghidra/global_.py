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
import contextlib
from typing import Iterator

import capa.ghidra.helpers
import capa.features.extractors.elf
import capa.features.extractors.ghidra.helpers
from capa.features.common import OS, ARCH_I386, ARCH_AMD64, OS_WINDOWS, Arch, Feature
from capa.features.address import NO_ADDRESS, Address

logger = logging.getLogger(__name__)


def extract_os() -> Iterator[tuple[Feature, Address]]:
    format_name: str = currentProgram().getExecutableFormat()  # type: ignore [name-defined] # noqa: F821

    if "PE" in format_name:
        yield OS(OS_WINDOWS), NO_ADDRESS

    elif "ELF" in format_name:
        with contextlib.closing(capa.ghidra.helpers.GHIDRAIO()) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)

        yield OS(os), NO_ADDRESS

    else:
        # we likely end up here:
        #  1. handling shellcode, or
        #  2. handling a new file format (e.g. macho)
        #
        # for (1) we can't do much - its shellcode and all bets are off.
        # we could maybe accept a further CLI argument to specify the OS,
        # but i think this would be rarely used.
        # rules that rely on OS conditions will fail to match on shellcode.
        #
        # for (2), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s, will not guess OS", format_name)
        return


def extract_arch() -> Iterator[tuple[Feature, Address]]:
    lang_id = currentProgram().getMetadata().get("Language ID")  # type: ignore [name-defined] # noqa: F821

    if "x86" in lang_id and "64" in lang_id:
        yield Arch(ARCH_AMD64), NO_ADDRESS

    elif "x86" in lang_id and "32" in lang_id:
        yield Arch(ARCH_I386), NO_ADDRESS

    elif "x86" not in lang_id:
        logger.debug("unsupported architecture: non-32-bit nor non-64-bit intel")
        return

    else:
        # we likely end up here:
        #  1. handling a new architecture (e.g. aarch64)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported architecture: %s", lang_id)
        return
