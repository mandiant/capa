# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Iterator, Tuple

from capa.features.address import Address
from capa.features.common import Feature, String
from capa.features.extractors.base_extractor import (
    CallHandle,
    ProcessHandle,
    ThreadHandle,
)
from capa.features.extractors.vmray.models import FunctionCall, Param
from capa.features.insn import API, Number
from capa.helpers import assert_never

logger = logging.getLogger(__name__)


def extract_function_calls(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    this method extracts the given call's features (such as API name and arguments),
    and returns them as API, Number, and String features.

    args:
      call: FunctionCall object representing the XML fncall element

      yields: Feature, address; where Feature is either: API, Number, or String.
    """

    # TODO (meh): update for new models https://github.com/mandiant/capa/issues/2148
    # print(ch)

    # Extract API name
    yield API(FunctionCall.fncall_id), Address(FunctionCall.addr)
    
    # Map str "type" values as int if they are in list
    datatype = [
        "unknown", 
        "void", 
        "bool", 
        "signed_8bit", 
        "unsigned_8bit", 
        "signed_16bit", 
        "unsigned_16bit", 
        "signed_32bit", 
        "unsigned_32bit", 
        "signed_64bit", 
        "unsigned_64bit", 
        "double", 
        "void_ptr", 
        "ptr", 
        "str", 
        "array", 
        "container", 
        "bindata", 
        "undefined_type"

        ]
    
    #Convert datatype value from str to int e.g. "value": "0x0" -> "value" : 0x0
    for i, param_data in enumerate(Param):
        param = Param #does an instance of Param need to be made? param = Param(**param_data)
        if Param.type in datatype:
            try:
                Param.value = int(Param.value)
                print(f"Converted value to int for Param {i+1}: {Param.value}")
            except ValueError:
                print(f"Could not convert value '{Param.value}' to int for Param {i+1}")
    print(Param)
    
    
    # Extract arguments from <in>
    if FunctionCall.in_ is not None:
        for param in FunctionCall.in_:
            value = param.value
            if value is not None:
                if isinstance(value, str):
                    yield String(value), Address(FunctionCall.address)
                elif isinstance(value, int):
                    yield Number(value), Address(FunctionCall.address)
                else:
                    assert_never(value)

    # Extract return value from <out>
    if FunctionCall.out_ is not None:
        for param in FunctionCall.out_:
            value = param.value
            if value is not None:
                if isinstance(value, str):
                    yield String(value), Address(FunctionCall.address)
                elif isinstance(value, int):
                    yield Number(value), Address(FunctionCall.address)
                else:
                    assert_never(value)

def extract_features(
    ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
) -> Iterator[Tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (
    extract_function_calls,
    extract_features,)
