# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Tuple, Iterator

from capa.helpers import assert_never
from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.cape.models import Call
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def extract_call_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    this method extracts the given call's features (such as API name and arguments),
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
    for arg in reversed(call.arguments):
        value = arg.value
        if isinstance(value, list) and len(value) == 0:
            # unsure why CAPE captures arguments as empty lists?
            continue

        elif isinstance(value, str):
            yield String(value), ch.address

        elif isinstance(value, int):
            yield Number(value), ch.address

        else:
            assert_never(value)

    yield API(call.api), ch.address


def extract_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (extract_call_features,)
