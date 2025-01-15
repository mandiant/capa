# Copyright 2024 Google LLC
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
from capa.features.extractors.vmray import VMRayAnalysis

logger = logging.getLogger(__name__)


def extract_arch(analysis: VMRayAnalysis) -> Iterator[tuple[Feature, Address]]:
    file_type: str = analysis.file_type

    if "x86-32" in file_type:
        yield Arch(ARCH_I386), NO_ADDRESS
    elif "x86-64" in file_type:
        yield Arch(ARCH_AMD64), NO_ADDRESS
    else:
        raise ValueError("unrecognized arch from the VMRay report: %s" % file_type)


def extract_format(analysis: VMRayAnalysis) -> Iterator[tuple[Feature, Address]]:
    assert analysis.sample_file_static_data is not None
    if analysis.sample_file_static_data.pe:
        yield Format(FORMAT_PE), NO_ADDRESS
    elif analysis.sample_file_static_data.elf:
        yield Format(FORMAT_ELF), NO_ADDRESS
    else:
        raise ValueError("unrecognized file format from the VMRay report: %s" % analysis.file_type)


def extract_os(analysis: VMRayAnalysis) -> Iterator[tuple[Feature, Address]]:
    file_type: str = analysis.file_type

    if "windows" in file_type.lower():
        yield OS(OS_WINDOWS), NO_ADDRESS
    elif "linux" in file_type.lower():
        yield OS(OS_LINUX), NO_ADDRESS
    else:
        raise ValueError("unrecognized OS from the VMRay report: %s" % file_type)


def extract_features(analysis: VMRayAnalysis) -> Iterator[tuple[Feature, Address]]:
    for global_handler in GLOBAL_HANDLER:
        for feature, addr in global_handler(analysis):
            yield feature, addr


GLOBAL_HANDLER = (
    extract_format,
    extract_os,
    extract_arch,
)
