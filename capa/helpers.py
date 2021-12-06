# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
from typing import NoReturn

_hex = hex


def hex(i):
    return _hex(int(i))


def get_file_taste(sample_path: str) -> bytes:
    if not os.path.exists(sample_path):
        raise IOError("sample path %s does not exist or cannot be accessed" % sample_path)
    with open(sample_path, "rb") as f:
        taste = f.read(8)
    return taste


def is_runtime_ida():
    try:
        import idc
    except ImportError:
        return False
    else:
        return True


def assert_never(value: NoReturn) -> NoReturn:
    assert False, f"Unhandled value: {value} ({type(value).__name__})"
