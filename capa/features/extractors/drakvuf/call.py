# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Tuple, Iterator

from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle
from capa.features.extractors.drakvuf.models import Call

logger = logging.getLogger(__name__)


def extract_call_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    This method extracts the given call's features (such as API name and arguments),
    and returns them as API, Number, and String features.

    args:
      ph: process handle (for defining the extraction scope)
      th: thread handle (for defining the extraction scope)
      ch: call handle (for defining the extraction scope)

    yields:
      Feature, address; where Feature is either: API, Number, or String.
    """
    call: Call = ch.inner

    # list similar to disassembly: arguments right-to-left, call
    for arg_value in reversed(call.arguments.values()):
        try:
            yield Number(int(arg_value, 0)), ch.address
        except ValueError:
            # DRAKVUF automatically resolves the contents of memory addresses, (e.g. Arg1="0xc6f217efe0:\"ntdll.dll\"").
            # For those cases we yield the entire string as it, since yielding the address only would
            # likely not provide any matches, and yielding just the memory contentswould probably be misleading,
            # but yielding the entire string would be helpful for an analyst looking at the verbose output
            yield String(arg_value), ch.address

    yield API(call.name), ch.address


def extract_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (extract_call_features,)
