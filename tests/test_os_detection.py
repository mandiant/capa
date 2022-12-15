# -*- coding: utf-8 -*-

# Copyright (C) 2022 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import pytest
from fixtures import *

import capa.features.extractors.elf


def test_elf_sh_notes():
    # guess: osabi: None
    # guess: ph notes: None
    # guess: sh notes: OS.LINUX
    # guess: linker: None
    # guess: ABI versions needed: None
    # guess: needed dependencies: None
    path = get_data_path_by_name("2f7f5f")
    with open(path, "rb") as f:
        assert capa.features.extractors.elf.detect_elf_os(f) == "linux"


def test_elf_pt_notes():
    # guess: osabi: None
    # guess: ph notes: None
    # guess: sh notes: OS.LINUX
    # guess: linker: OS.LINUX
    # guess: ABI versions needed: OS.LINUX
    # guess: needed dependencies: None
    path = get_data_path_by_name("7351f.elf")
    with open(path, "rb") as f:
        assert capa.features.extractors.elf.detect_elf_os(f) == "linux"


def test_elf_so_needed():
    # guess: osabi: None
    # guess: ph notes: None
    # guess: sh notes: OS.HURD
    # guess: linker: None
    # guess: ABI versions needed: OS.HURD
    # guess: needed dependencies: OS.HURD
    path = get_data_path_by_name("b5f052")
    with open(path, "rb") as f:
        assert capa.features.extractors.elf.detect_elf_os(f) == "hurd"


def test_elf_abi_version_hurd():
    # guess: osabi: None
    # guess: ph notes: None
    # guess: sh notes: OS.HURD
    # guess: linker: None
    # guess: ABI versions needed: OS.HURD
    # guess: needed dependencies: None
    path = get_data_path_by_name("bf7a9c")
    with open(path, "rb") as f:
        assert capa.features.extractors.elf.detect_elf_os(f) == "hurd"
