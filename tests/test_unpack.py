# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys

import pefile
import pytest
from fixtures import *

import capa.unpack


@pytest.mark.xfail(sys.version_info <= (3, 5), reason="auto-unpack only works on py3.6+")
def test_aspack_is_packed(aspack_extractor):
    path = aspack_extractor.path

    with open(path, "rb") as f:
        buf = f.read()

    assert capa.unpack.is_packed(buf) is True


@pytest.mark.xfail(sys.version_info <= (3, 5), reason="auto-unpack only works on py3.6+")
def test_aspack_detect(aspack_extractor):
    path = aspack_extractor.path

    with open(path, "rb") as f:
        buf = f.read()

    assert capa.unpack.detect_packer(buf) == "aspack"


@pytest.mark.xfail(sys.version_info <= (3, 5), reason="auto-unpack only works on py3.6+")
def test_aspack_unpack(aspack_extractor):
    with open(aspack_extractor.path, "rb") as f:
        buf = f.read()

    unpacked = capa.unpack.unpack_pe("aspack", buf)

    pe = pefile.PE(data=unpacked)
    assert pe.OPTIONAL_HEADER.ImageBase == 0x4AD00000
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x1A610
    assert b"This program cannot be run in DOS mode" in unpacked
    assert "(C) Copyright 1985-2000 Microsoft Corp.".encode("utf-16le") in unpacked
    assert "CMD.EXE has halted. %0".encode("utf-16le") in unpacked

    dlls = set([])
    syms = set([])
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dlls.add(entry.dll.decode("ascii").lower().partition(".")[0])
        for imp in entry.imports:
            syms.add(imp.name.decode("ascii"))

    assert dlls == {"advapi32", "kernel32", "msvcrt", "user32"}
    assert "RegQueryValueExW" in syms
    assert "WriteConsoleW" in syms
    assert "realloc" in syms
    assert "GetProcessWindowStation" in syms
