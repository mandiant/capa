# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Dict, List, Iterator

from capa.features.address import ThreadAddress, ProcessAddress, DynamicCallAddress
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle
from capa.features.extractors.drakvuf.models import Call

logger = logging.getLogger(__name__)


def get_calls(
    sorted_calls: Dict[ProcessAddress, Dict[ThreadAddress, List[Call]]], ph: ProcessHandle, th: ThreadHandle
) -> Iterator[CallHandle]:
    for i, call in enumerate(sorted_calls[ph.address][th.address]):
        call_addr = DynamicCallAddress(thread=th.address, id=i)
        yield CallHandle(address=call_addr, inner=call)
