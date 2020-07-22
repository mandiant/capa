# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import os.path
import collections

import pytest
import viv_utils

CD = os.path.dirname(__file__)


Sample = collections.namedtuple("Sample", ["vw", "path"])


@pytest.fixture
def mimikatz():
    path = os.path.join(CD, "data", "mimikatz.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_a933a1a402775cfa94b6bee0963f4b46():
    path = os.path.join(CD, "data", "a933a1a402775cfa94b6bee0963f4b46.dll_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def kernel32():
    path = os.path.join(CD, "data", "kernel32.dll_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_a198216798ca38f280dc413f8c57f2c2():
    path = os.path.join(CD, "data", "a198216798ca38f280dc413f8c57f2c2.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_9324d1a8ae37a36ae560c37448c9705a():
    path = os.path.join(CD, "data", "9324d1a8ae37a36ae560c37448c9705a.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def pma_lab_12_04():
    path = os.path.join(CD, "data", "Practical Malware Analysis Lab 12-04.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_bfb9b5391a13d0afd787e87ab90f14f5():
    path = os.path.join(CD, "data", "bfb9b5391a13d0afd787e87ab90f14f5.dll_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_lab21_01():
    path = os.path.join(CD, "data", "Practical Malware Analysis Lab 21-01.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_c91887d861d9bd4a5872249b641bc9f9():
    path = os.path.join(CD, "data", "c91887d861d9bd4a5872249b641bc9f9.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41():
    path = os.path.join(CD, "data", "39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.dll_",)
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_499c2a85f6e8142c3f48d4251c9c7cd6_raw32():
    path = os.path.join(CD, "data", "499c2a85f6e8142c3f48d4251c9c7cd6.raw32")
    return Sample(viv_utils.getShellcodeWorkspace(path), path)
