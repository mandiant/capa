# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Tuple, Iterator

from capa.features.common import ARCH_I386, ARCH_AMD64, Arch, Feature
from capa.features.address import NO_ADDRESS, Address

logger = logging.getLogger(__name__)


def extract_arch(vw) -> Iterator[Tuple[Feature, Address]]:
    arch = vw.getMeta("Architecture")
    if arch == "amd64":
        yield Arch(ARCH_AMD64), NO_ADDRESS

    elif arch == "i386":
        yield Arch(ARCH_I386), NO_ADDRESS

    else:
        # we likely end up here:
        #  1. handling a new architecture (e.g. aarch64)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported architecture: %s", vw.arch.__class__.__name__)
        return
