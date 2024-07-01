# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing
# software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND
# , either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Tuple, Iterator

from capa.helpers import assert_never
from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.vmray.models import FunctionCall
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def extract_function_calls(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    This method extracts the given call's features (such as API name and
    arguments), and returns them as API, Number, and String features.

    Args:
        ph: process handle (for defining the extraction scope)
        th: thread handle (for defining the extraction scope)
        ch: call handle (for defining the extraction scope)

    Yields:
        Feature, address; where Feature is either: API, Number, or String.
    """

    # TODO(meh): update for new models
    # https://github.com/mandiant/capa/issues/2148

    call: FunctionCall = ch.inner

    # Extract arguments from <in>

    if call is not None:
        for param in call.in_:
            type = param.type
            value = param.value
            if type is not None:
                if type in [
                    "signed_8bit",
                    "unsigned_8bit",
                    "signed_16bit",
                    "unsigned_16bit",
                    "signed_32bit",
                    "unsigned_32bit",
                    "signed_64bit",
                    "unsigned_64bit",
                    "double",
                ]:
                    yield Number(value), ch.address
                elif type in [
                    "unknown",
                    "void",
                    "bool",
                    "void_ptr",
                    "ptr",
                    "str",
                    "array",
                    "container",
                    "bindata",
                    "undefined_type",
                ]:
                    yield String(value), ch.address
                else:
                    assert_never(value)

    # Extract return value from <out>
    if call is not None:
        for param in call.out_:
            type = param.type
            value = param.value
            if type is not None:
                if type in [
                    "signed_8bit",
                    "unsigned_8bit",
                    "signed_16bit",
                    "unsigned_16bit",
                    "signed_32bit",
                    "unsigned_32bit",
                    "signed_64bit",
                    "unsigned_64bit",
                    "double",
                ]:
                    yield Number(value), ch.address
                elif type in [
                    "unknown",
                    "void",
                    "bool",
                    "void_ptr",
                    "ptr",
                    "str",
                    "array",
                    "container",
                    "bindata",
                    "undefined_type",
                ]:
                    yield String(value), ch.address
                else:
                    assert_never(value)

    # Extract API name
    yield API(call.name), ch.address


def extract_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (extract_function_calls,)
