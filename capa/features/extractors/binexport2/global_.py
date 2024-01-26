# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Tuple, Iterator

from capa.features.common import ARCH_AARCH64, Arch, Feature
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def extract_os(be2: BinExport2) -> Iterator[Tuple[Feature, Address]]:
    # fetch from the buf.
    # TODO(wb): 1755
    yield from ()


def extract_arch(be2: BinExport2) -> Iterator[Tuple[Feature, Address]]:
    arch = be2.meta_information.architecture_name
    # TODO: where does this come from? is it from the BinExport extractor? is there any schema??
    if arch == "aarch64":
        yield Arch(ARCH_AARCH64), NO_ADDRESS
    # TODO: x86, etc.
    else:
        logger.debug("unsupported architecture: %s", arch)
        return
