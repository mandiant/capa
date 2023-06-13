# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Any, Dict, List, Tuple, Iterator

import capa.features.extractors.cape.global_
import capa.features.extractors.cape.process
import capa.features.extractors.cape.file
import capa.features.extractors.cape.thread
from capa.features.common import Feature, String
from capa.features.insn import API, Number
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import ProcessHandle, ThreadHandle, DynamicExtractor


logger = logging.getLogger(__name__)


def extract_call_features(calls: List[Dict], th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
    tid = str(th.tid)
    for call in calls:
        if call["thead_id"] != tid:
            continue

        yield API(call["api"]), int(call["caller"], 16)
        yield Number(int(call["return"], 16)), int(call["caller"], 16)
        for arg in call["arguments"]:
            if arg["value"].isdecimal():
                yield Number(int(arg["value"])), int(call["caller"], 16)
                continue
            try:
                yield Number(int(arg["value"], 16)), int(call["caller"], 16)
            except:
                yield String{arg["value"]}, int(call["caller"], 16)


def extract_features(behavior: Dict, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
    processes: List = behavior["processes"]
    search_result = list(map(lambda proc: proc["process_id"] == ph.pid and proc["parent_id"] == ph.ppid, processes))
    process = processes[search_result.index(True)]

    for handler in THREAD_HANDLERS:
        handler(process["calls"])


THREAD_HANDLERS = (
    extract_call_features,
)