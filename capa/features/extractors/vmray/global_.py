# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Iterator, Tuple

from capa.features.address import NO_ADDRESS, Address
from capa.features.common import (
    ARCH_AMD64,
    ARCH_I386,
    FORMAT_PE,
    OS,
    OS_WINDOWS,
    Arch,
    Feature,
    Format,
)
from capa.features.extractors.vmray import VMRayAnalysis

logger = logging.getLogger(__name__)


def extract_arch(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    sample_type: str = analysis.sv2.analysis_metadata.sample_type

    if "x86-32" in sample_type:
        yield Arch(ARCH_I386), NO_ADDRESS
    elif "x86-64" in sample_type:
        yield Arch(ARCH_AMD64), NO_ADDRESS
    else:
        logger.warning("unrecognized arch: %s", sample_type)
        raise ValueError(f"unrecognized arch from the VMRay report: {sample_type}")


def extract_format(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    if analysis.sample_file_static_data.pe:
        yield Format(FORMAT_PE), NO_ADDRESS
    else:
        logger.warning(
            "unrecognized file format: %s", analysis.sv2.analysis_metadata.sample_type
        )
        raise ValueError(
            f"unrecognized file format from the VMRay report: {analysis.sv2.analysis_metadata.sample_type}"
        )


def extract_os(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    sample_type: str = analysis.sv2.analysis_metadata.sample_type

    if "windows" in sample_type.lower():
        yield OS(OS_WINDOWS), NO_ADDRESS
    else:
        logger.warning("unrecognized OS: %s", sample_type)
        raise ValueError(f"unrecognized OS from the VMRay report: {sample_type}")


def extract_features(analysis: VMRayAnalysis) -> Iterator[Tuple[Feature, Address]]:
    for global_handler in GLOBAL_HANDLER:
        for feature, addr in global_handler(analysis):
            yield feature, addr


GLOBAL_HANDLER = (
    extract_format,
    extract_os,
    extract_arch,
)
