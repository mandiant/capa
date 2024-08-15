# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Dict, List, Tuple, Iterator

from capa.features.common import String, Feature
from capa.features.address import Address, ThreadAddress, ProcessAddress
from capa.features.extractors.base_extractor import ThreadHandle, ProcessHandle
from capa.features.extractors.drakvuf.models import Call

logger = logging.getLogger(__name__)


def get_threads(
    calls: Dict[ProcessAddress, Dict[ThreadAddress, List[Call]]], ph: ProcessHandle
) -> Iterator[ThreadHandle]:
    """
    Get the threads associated with a given process.
    """
    for thread_addr in calls[ph.address]:
        yield ThreadHandle(address=thread_addr, inner={})


def extract_process_name(ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    yield String(ph.inner["process_name"]), ph.address


def extract_features(ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in PROCESS_HANDLERS:
        for feature, addr in handler(ph):
            yield feature, addr


PROCESS_HANDLERS = (extract_process_name,)
