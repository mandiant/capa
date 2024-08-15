# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Tuple, Iterator

from capa.features.common import OS, FORMAT_PE, ARCH_AMD64, OS_WINDOWS, Arch, Format, Feature
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.drakvuf.models import DrakvufReport

logger = logging.getLogger(__name__)


def extract_format(report: DrakvufReport) -> Iterator[Tuple[Feature, Address]]:
    # DRAKVUF sandbox currently supports only Windows as the guest: https://drakvuf-sandbox.readthedocs.io/en/latest/usage/getting_started.html
    yield Format(FORMAT_PE), NO_ADDRESS


def extract_os(report: DrakvufReport) -> Iterator[Tuple[Feature, Address]]:
    # DRAKVUF sandbox currently supports only PE files: https://drakvuf-sandbox.readthedocs.io/en/latest/usage/getting_started.html
    yield OS(OS_WINDOWS), NO_ADDRESS


def extract_arch(report: DrakvufReport) -> Iterator[Tuple[Feature, Address]]:
    # DRAKVUF sandbox currently supports only x64 Windows as the guest: https://drakvuf-sandbox.readthedocs.io/en/latest/usage/getting_started.html
    yield Arch(ARCH_AMD64), NO_ADDRESS


def extract_features(report: DrakvufReport) -> Iterator[Tuple[Feature, Address]]:
    for global_handler in GLOBAL_HANDLER:
        for feature, addr in global_handler(report):
            yield feature, addr


GLOBAL_HANDLER = (
    extract_format,
    extract_os,
    extract_arch,
)
