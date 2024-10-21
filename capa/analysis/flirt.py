# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from pydantic import BaseModel

import capa.features.extractors.ida.idalib as idalib

if not idalib.has_idalib():
    raise RuntimeError("cannot find IDA idalib module.")

if not idalib.load_idalib():
    raise RuntimeError("failed to load IDA idalib module.")

import idaapi
import idautils


class FunctionId(BaseModel):
    va: int
    is_library: bool
    name: str


def get_flirt_matches(lib_only=True):
    for fva in idautils.Functions():
        f = idaapi.get_func(fva)
        is_lib = bool(f.flags & idaapi.FUNC_LIB)
        fname = idaapi.get_func_name(fva)

        if lib_only and not is_lib:
            continue

        yield FunctionId(va=fva, is_library=is_lib, name=fname)
