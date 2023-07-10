# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Any, Dict, List, Tuple, Iterator

import capa.features.extractors.cape.helpers
from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address, DynamicAddress, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def extract_call_features(behavior: Dict, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    this method goes through the specified thread's call trace, and extracts all possible
    features such as: API, Number (for arguments), String (for arguments).

    args:
      behavior: a dictionary of behavioral artifacts extracted by the sandbox
      ph: process handle (for defining the extraction scope)
      th: thread handle (for defining the extraction scope)

    yields:
      Feature, address; where Feature is either: API, Number, or String.
    """

    process = capa.features.extractors.cape.helpers.find_process(behavior["processes"], ph)
    calls: List[Dict[str, Any]] = process["calls"]

    tid = str(th.address.tid)
    for call in calls:
        if call["thread_id"] != tid:
            continue

        # TODO this address may vary from the PE header, may read actual base from procdump.pe.imagebase or similar
        caller = DynamicAddress(call["id"], int(call["caller"], 16))
        # list similar to disassembly: arguments right-to-left, call
        for arg in call["arguments"][::-1]:
            try:
                yield Number(int(arg["value"], 16), description=f"{arg['name']}"), caller
            except ValueError:
                yield String(arg["value"], description=f"{arg['name']}"), caller
        yield API(call["api"]), caller


def extract_features(behavior: Dict, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in THREAD_HANDLERS:
        for feature, addr in handler(behavior, ph, th):
            yield feature, addr


THREAD_HANDLERS = (extract_call_features,)
