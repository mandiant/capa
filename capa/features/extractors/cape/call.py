# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Any, Dict, List, Tuple, Iterator

import capa.features.extractors.cape.file
import capa.features.extractors.cape.thread
import capa.features.extractors.cape.global_
import capa.features.extractors.cape.process
from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def extract_call_features(
    behavior: Dict, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
) -> Iterator[Tuple[Feature, Address]]:
    """
    this method extrcts the given call's features (api name and arguments),
    and returns them as API, Number, and String features.

    args:
      behavior: a dictionary of behavioral artifacts extracted by the sandbox
      ph: process handle (for defining the extraction scope)
      th: thread handle (for defining the extraction scope)
      ch: call handle (for defining the extraction scope)

    yields:
      Feature, address; where Feature is either: API, Number, or String.
    """
    # TODO(yelhamer): find correct base address used at runtime.
    # this address may vary from the PE header, may read actual base from procdump.pe.imagebase or similar.
    # https://github.com/mandiant/capa/issues/1618
    process = capa.features.extractors.cape.helpers.find_process(behavior["processes"], ph)
    calls: List[Dict[str, Any]] = process["calls"]
    call = calls[ch.address.id]
    assert call["thread_id"] == str(th.address.tid)
    # list similar to disassembly: arguments right-to-left, call
    for arg in call["arguments"][::-1]:
        try:
            yield Number(int(arg["value"], 16)), ch.address
        except ValueError:
            yield String(arg["value"]), ch.address
    yield API(call["api"]), ch.address


def extract_features(
    behavior: Dict, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
) -> Iterator[Tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(behavior, ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (extract_call_features,)
