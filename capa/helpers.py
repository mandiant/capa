# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
from typing import NoReturn

from pefile import PE

import capa.features

EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")


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


def is_dotnet_file(pe: PE) -> bool:
    image_directory_entry_com_descriptor = 14
    com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[image_directory_entry_com_descriptor]
    return not (com_dir.Size == 0 and com_dir.VirtualAddress == 0)


def use_pe_format(format_: str, taste: bytes):
    return format_ == "pe" or (format_ == "auto" and taste.startswith(b"MZ"))


def use_freeze_format(format_: str, taste: bytes):
    return (format_ == "freeze") or (format_ == "auto" and capa.features.freeze.is_freeze(taste))


def get_format_via_file_extension(sample: str, format_: str) -> str:
    if sample.endswith(EXTENSIONS_SHELLCODE_32):
        return "sc32"
    elif sample.endswith(EXTENSIONS_SHELLCODE_64):
        return "sc64"
    else:
        return format_
