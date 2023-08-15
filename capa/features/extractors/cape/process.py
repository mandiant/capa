# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Dict, List, Tuple, Iterator

import capa.features.extractors.cape.file
import capa.features.extractors.cape.thread
import capa.features.extractors.cape.global_
import capa.features.extractors.cape.process
from capa.features.common import String, Feature
from capa.features.address import Address, ThreadAddress
from capa.features.extractors.base_extractor import ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def get_threads(behavior: Dict, ph: ProcessHandle) -> Iterator[ThreadHandle]:
    """
    get the threads associated with a given process
    """

    process = capa.features.extractors.cape.helpers.find_process(behavior["processes"], ph)
    threads: List = process["threads"]

    for thread in threads:
        address: ThreadAddress = ThreadAddress(process=ph.address, tid=int(thread))
        yield ThreadHandle(address=address, inner={})


def extract_environ_strings(behavior: Dict, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    extract strings from a process' provided environment variables.
    """

    process = capa.features.extractors.cape.helpers.find_process(behavior["processes"], ph)
    environ: Dict[str, str] = process["environ"]

    if not environ:
        return

    for value in (value for value in environ.values() if value):
        yield String(value), ph.address


def extract_features(behavior: Dict, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in PROCESS_HANDLERS:
        for feature, addr in handler(behavior, ph):
            yield feature, addr


PROCESS_HANDLERS = (extract_environ_strings,)
