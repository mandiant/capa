# Copyright 2023 Google LLC
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
import capa.features.basicblock

DYNAMIC_CAPE_FEATURE_PRESENCE_TESTS = sorted(
    [
        # file/string
        ("0000a657", "file", capa.features.common.String("T_Ba?.BcRJa"), True),
        ("0000a657", "file", capa.features.common.String("GetNamedPipeClientSessionId"), True),
        ("0000a657", "file", capa.features.common.String("nope"), False),
        # file/sections
        ("0000a657", "file", capa.features.file.Section(".rdata"), True),
        ("0000a657", "file", capa.features.file.Section(".nope"), False),
        # file/imports
        ("0000a657", "file", capa.features.file.Import("NdrSimpleTypeUnmarshall"), True),
        ("0000a657", "file", capa.features.file.Import("Nope"), False),
        # file/exports
        ("0000a657", "file", capa.features.file.Export("Nope"), False),
        # process/environment variables
        (
            "0000a657",
            "process=(1180:3052)",
            capa.features.common.String("C:\\Users\\comp\\AppData\\Roaming\\Microsoft\\Jxoqwnx\\jxoqwn.exe"),
            True,
        ),
        ("0000a657", "process=(1180:3052)", capa.features.common.String("nope"), False),
        # thread/api calls
        ("0000a657", "process=(2900:2852),thread=2904", capa.features.insn.API("RegQueryValueExA"), True),
        ("0000a657", "process=(2900:2852),thread=2904", capa.features.insn.API("RegQueryValueEx"), True),
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.API("NtQueryValueKey"), True),
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.API("GetActiveWindow"), False),
        # thread/number call argument
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.Number(0x000000EC), True),
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.Number(110173), False),
        # thread/string call argument
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.common.String("SetThreadUILanguage"), True),
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.common.String("nope"), False),
        ("0000a657", "process=(2852:3052),thread=2804,call=56", capa.features.insn.API("NtQueryValueKey"), True),
        ("0000a657", "process=(2852:3052),thread=2804,call=1958", capa.features.insn.API("nope"), False),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)

DYNAMIC_CAPE_FEATURE_COUNT_TESTS = sorted(
    # TODO(yelhamer): use the same sample for testing CAPE and DRAKVUF extractors
    # https://github.com/mandiant/capa/issues/2180
    [
        # file/string
        ("0000a657", "file", capa.features.common.String("T_Ba?.BcRJa"), 1),
        ("0000a657", "file", capa.features.common.String("GetNamedPipeClientSessionId"), 1),
        ("0000a657", "file", capa.features.common.String("nope"), 0),
        # file/sections
        ("0000a657", "file", capa.features.file.Section(".rdata"), 1),
        ("0000a657", "file", capa.features.file.Section(".nope"), 0),
        # file/imports
        ("0000a657", "file", capa.features.file.Import("NdrSimpleTypeUnmarshall"), 1),
        ("0000a657", "file", capa.features.file.Import("Nope"), 0),
        # file/exports
        ("0000a657", "file", capa.features.file.Export("Nope"), 0),
        # process/environment variables
        (
            "0000a657",
            "process=(1180:3052)",
            capa.features.common.String("C:\\Users\\comp\\AppData\\Roaming\\Microsoft\\Jxoqwnx\\jxoqwn.exe"),
            2,
        ),
        ("0000a657", "process=(1180:3052)", capa.features.common.String("nope"), 0),
        # thread/api calls
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.API("NtQueryValueKey"), 7),
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.API("GetActiveWindow"), 0),
        # thread/number call argument
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.Number(0x000000EC), 1),
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.insn.Number(110173), 0),
        # thread/string call argument
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.common.String("SetThreadUILanguage"), 1),
        ("0000a657", "process=(2852:3052),thread=2804", capa.features.common.String("nope"), 0),
        ("0000a657", "process=(2852:3052),thread=2804,call=56", capa.features.insn.API("NtQueryValueKey"), 1),
        ("0000a657", "process=(2852:3052),thread=2804,call=1958", capa.features.insn.API("nope"), 0),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    DYNAMIC_CAPE_FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_cape_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_cape_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    DYNAMIC_CAPE_FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_cape_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_cape_extractor, sample, scope, feature, expected)
