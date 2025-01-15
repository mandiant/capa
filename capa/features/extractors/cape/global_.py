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
from typing import Iterator

from capa.features.common import (
    OS,
    OS_ANY,
    OS_LINUX,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    FORMAT_ELF,
    OS_WINDOWS,
    Arch,
    Format,
    Feature,
)
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.cape.models import CapeReport

logger = logging.getLogger(__name__)


def extract_arch(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if "Intel 80386" in report.target.file.type:
        yield Arch(ARCH_I386), NO_ADDRESS
    elif "x86-64" in report.target.file.type:
        yield Arch(ARCH_AMD64), NO_ADDRESS
    else:
        logger.warning("unrecognized Architecture: %s", report.target.file.type)
        raise ValueError(
            f"unrecognized Architecture from the CAPE report; output of file command: {report.target.file.type}"
        )


def extract_format(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    if "PE" in report.target.file.type:
        yield Format(FORMAT_PE), NO_ADDRESS
    elif "ELF" in report.target.file.type:
        yield Format(FORMAT_ELF), NO_ADDRESS
    else:
        logger.warning("unknown file format, file command output: %s", report.target.file.type)
        raise ValueError(
            f"unrecognized file format from the CAPE report; output of file command: {report.target.file.type}"
        )


def extract_os(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    # this variable contains the output of the file command
    file_output = report.target.file.type

    if "windows" in file_output.lower():
        yield OS(OS_WINDOWS), NO_ADDRESS
    elif "elf" in file_output.lower():
        # operating systems recognized by the file command: https://github.com/file/file/blob/master/src/readelf.c#L609
        if "Linux" in file_output:
            yield OS(OS_LINUX), NO_ADDRESS
        elif "Hurd" in file_output:
            yield OS("hurd"), NO_ADDRESS
        elif "Solaris" in file_output:
            yield OS("solaris"), NO_ADDRESS
        elif "kFreeBSD" in file_output:
            yield OS("freebsd"), NO_ADDRESS
        elif "kNetBSD" in file_output:
            yield OS("netbsd"), NO_ADDRESS
        else:
            # if the operating system information is missing from the cape report, it's likely a bug
            logger.warning("unrecognized OS: %s", file_output)
            raise ValueError(f"unrecognized OS from the CAPE report; output of file command: {file_output}")
    else:
        # the sample is shellcode
        logger.debug("unsupported file format, file command output: %s", file_output)
        yield OS(OS_ANY), NO_ADDRESS


def extract_features(report: CapeReport) -> Iterator[tuple[Feature, Address]]:
    for global_handler in GLOBAL_HANDLER:
        for feature, addr in global_handler(report):
            yield feature, addr


GLOBAL_HANDLER = (
    extract_format,
    extract_os,
    extract_arch,
)
