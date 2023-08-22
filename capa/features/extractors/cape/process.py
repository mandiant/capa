# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import List, Tuple, Iterator

from capa.features.common import String, Feature
from capa.features.address import Address, ThreadAddress
from capa.features.extractors.cape.models import Process
from capa.features.extractors.base_extractor import ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def get_threads(ph: ProcessHandle) -> Iterator[ThreadHandle]:
    """
    get the threads associated with a given process
    """
    process: Process = ph.inner
    threads: List[int] = process.threads

    for thread in threads:
        address: ThreadAddress = ThreadAddress(process=ph.address, tid=thread)
        yield ThreadHandle(address=address, inner={})


def extract_environ_strings(ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    extract strings from a process' provided environment variables.
    """
    process: Process = ph.inner

    for value in (value for value in process.environ.values() if value):
        yield String(value), ph.address


def extract_features(ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in PROCESS_HANDLERS:
        for feature, addr in handler(ph):
            yield feature, addr


PROCESS_HANDLERS = (extract_environ_strings,)
