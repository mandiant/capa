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


import fixtures

import capa.main
import capa.features.file
import capa.features.insn
import capa.features.common

DYNAMIC_VMRAY_FEATURE_PRESENCE_TESTS = sorted(
    [
        ("93b2d1-vmray", "file", capa.features.common.String("api.%x%x.%s"), True),
        ("93b2d1-vmray", "file", capa.features.common.String("\\Program Files\\WindowsApps\\does_not_exist"), False),
        # file/imports
        ("93b2d1-vmray", "file", capa.features.file.Import("GetAddrInfoW"), True),
        ("93b2d1-vmray", "file", capa.features.file.Import("GetAddrInfo"), True),
        # thread/api calls
        ("93b2d1-vmray", "process=(2176:0),thread=2180", capa.features.insn.API("LoadLibraryExA"), True),
        ("93b2d1-vmray", "process=(2176:0),thread=2180", capa.features.insn.API("LoadLibraryEx"), True),
        ("93b2d1-vmray", "process=(2176:0),thread=2420", capa.features.insn.API("GetAddrInfoW"), True),
        ("93b2d1-vmray", "process=(2176:0),thread=2420", capa.features.insn.API("GetAddrInfo"), True),
        ("93b2d1-vmray", "process=(2176:0),thread=2420", capa.features.insn.API("DoesNotExist"), False),
        # call/api
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=2361", capa.features.insn.API("GetAddrInfoW"), True),
        # call/string argument
        (
            "93b2d1-vmray",
            "process=(2176:0),thread=2420,call=10323",
            capa.features.common.String("raw.githubusercontent.com"),
            True,
        ),
        # backslashes in paths; see #2428
        (
            "93b2d1-vmray",
            "process=(2176:0),thread=2180,call=267",
            capa.features.common.String("C:\\Users\\WhuOXYsD\\Desktop\\filename.exe"),
            True,
        ),
        (
            "93b2d1-vmray",
            "process=(2176:0),thread=2180,call=267",
            capa.features.common.String("C:\\\\Users\\\\WhuOXYsD\\\\Desktop\\\\filename.exe"),
            False,
        ),
        (
            "93b2d1-vmray",
            "process=(2176:0),thread=2204,call=2395",
            capa.features.common.String("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
            True,
        ),
        (
            "93b2d1-vmray",
            "process=(2176:0),thread=2204,call=2395",
            capa.features.common.String("Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System"),
            False,
        ),
        # call/number argument
        # VirtualAlloc(4096, 4)
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=2358", capa.features.insn.Number(4096), True),
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=2358", capa.features.insn.Number(4), True),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)

DYNAMIC_VMRAY_FEATURE_COUNT_TESTS = sorted(
    [
        # file/imports
        ("93b2d1-vmray", "file", capa.features.file.Import("GetAddrInfoW"), 1),
        # thread/api calls
        ("93b2d1-vmray", "process=(2176:0),thread=2420", capa.features.insn.API("free"), 1),
        ("93b2d1-vmray", "process=(2176:0),thread=2420", capa.features.insn.API("GetAddrInfoW"), 5),
        # call/api
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=2345", capa.features.insn.API("free"), 1),
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=2345", capa.features.insn.API("GetAddrInfoW"), 0),
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=2361", capa.features.insn.API("GetAddrInfoW"), 1),
        # call/string argument
        (
            "93b2d1-vmray",
            "process=(2176:0),thread=2420,call=10323",
            capa.features.common.String("raw.githubusercontent.com"),
            1,
        ),
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=10323", capa.features.common.String("non_existant"), 0),
        # call/number argument
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=10315", capa.features.insn.Number(4096), 1),
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=10315", capa.features.insn.Number(4), 1),
        ("93b2d1-vmray", "process=(2176:0),thread=2420,call=10315", capa.features.insn.Number(404), 0),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    DYNAMIC_VMRAY_FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_vmray_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_vmray_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    DYNAMIC_VMRAY_FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_vmray_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_vmray_extractor, sample, scope, feature, expected)


def test_vmray_processes():
    # see #2394
    path = fixtures.get_data_path_by_name("2f8a79-vmray")
    vmre = fixtures.get_vmray_extractor(path)
    assert len(vmre.analysis.monitor_processes) == 9
