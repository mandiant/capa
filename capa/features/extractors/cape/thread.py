# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Any, Dict, List, Tuple, Iterator

from capa.features.common import Feature, String
from capa.features.insn import API, Number
from capa.features.address import Address
from capa.features.extractors.base_extractor import ProcessHandle, ThreadHandle


logger = logging.getLogger(__name__)


def extract_call_features(behavior: Dict, ph:ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
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

    calls:List[Dict] = None
    for process in behavior["processes"]:
        if ph.pid == process["process_id"] and ph.inner["ppid"] == process["parent_id"]:
            calls:List[Dict] = process

    tid = str(th.tid)
    for call in calls:
        if call["thread_id"] != tid:
            continue
        yield Number(int(call["return"], 16)), int(call["caller"], 16)
        yield API(call["api"]), int(call["caller"], 16)
        for arg in call["arguments"]:
            if arg["value"].isdecimal():
                yield Number(int(arg["value"])), int(call["caller"], 16)
                continue
            try:
                # argument could be in hexadecimal
                yield Number(int(arg["value"], 16)), int(call["caller"], 16)
            except:
                if arg["value"]:
                    # argument is a non-empty string
                    yield String(arg["value"]), int(call["caller"], 16)


def extract_features(behavior: Dict, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in THREAD_HANDLERS:
        for feature, addr in handler(behavior, ph, th):
            yield feature, addr


THREAD_HANDLERS = (
    extract_call_features,
)