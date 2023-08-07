# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Any, Dict, List, Tuple, Iterator

import capa.features.extractors.cape.helpers
from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address, DynamicCallAddress
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def get_calls(behavior: Dict, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
    process = capa.features.extractors.cape.helpers.find_process(behavior["processes"], ph)
    calls: List[Dict[str, Any]] = process["calls"]

    tid = str(th.address.tid)
    for call in calls:
        if call["thread_id"] != tid:
            continue

        addr = DynamicCallAddress(thread=th.address, id=call["id"])
        ch = CallHandle(address=addr, inner={})
        yield ch


def extract_thread_features(behavior: Dict, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
    yield from ((Feature(0), NO_ADDRESS),)


def extract_features(behavior: Dict, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in THREAD_HANDLERS:
        for feature, addr in handler(behavior, ph, th):
            yield feature, addr


THREAD_HANDLERS = (extract_thread_features,)
