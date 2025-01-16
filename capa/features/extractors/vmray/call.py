# Copyright 2024 Google LLC
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

import capa.features.extractors.helpers
from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.strings import is_printable_str
from capa.features.extractors.vmray.models import PARAM_TYPE_INT, PARAM_TYPE_STR, Param, FunctionCall, hexint
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def get_call_param_features(param: Param, ch: CallHandle) -> Iterator[tuple[Feature, Address]]:
    if param.deref is not None:
        # pointer types contain a special "deref" member that stores the deref'd value
        # so we check for this first and ignore Param.value as this always contains the
        # deref'd pointer value
        if param.deref.value is not None:
            if param.deref.type_ in PARAM_TYPE_INT:
                yield Number(hexint(param.deref.value)), ch.address
            elif param.deref.type_ in PARAM_TYPE_STR:
                if is_printable_str(param.deref.value):
                    # parsing the data up to here results in double-escaped backslashes, remove those here
                    yield String(param.deref.value.replace("\\\\", "\\")), ch.address
            else:
                logger.debug("skipping deref param type %s", param.deref.type_)
    elif param.value is not None:
        if param.type_ in PARAM_TYPE_INT:
            yield Number(hexint(param.value)), ch.address


def extract_call_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[tuple[Feature, Address]]:
    call: FunctionCall = ch.inner

    if call.params_in:
        for param in call.params_in.params:
            yield from get_call_param_features(param, ch)

    for name in capa.features.extractors.helpers.generate_symbols("", call.name):
        yield API(name), ch.address


def extract_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (extract_call_features,)
