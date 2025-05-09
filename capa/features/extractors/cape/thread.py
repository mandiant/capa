# Copyright 2023 Google LLC
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

from capa.features.address import DynamicCallAddress
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.cape.models import Process
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def get_calls(ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
    process: Process = ph.inner

    tid = th.address.tid
    for call_index, call in enumerate(process.calls):
        if call.thread_id != tid:
            continue

        for symbol in generate_symbols("", call.api):
            call.api = symbol

            addr = DynamicCallAddress(thread=th.address, id=call_index)
            yield CallHandle(address=addr, inner=call)
