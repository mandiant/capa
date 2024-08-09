# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import fixtures

import capa.main
import capa.features.file
import capa.features.insn
import capa.features.common

DYNAMIC_DRAKVUF_FEATURE_PRESENCE_TESTS = sorted(
    [
        ("93b2d1-drakvuf", "file", capa.features.common.String("\\Program Files\\WindowsApps\\does_not_exist"), False),
        # file/imports
        ("93b2d1-drakvuf", "file", capa.features.file.Import("SetUnhandledExceptionFilter"), True),
        # thread/api calls
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592", capa.features.insn.API("LdrLoadDll"), True),
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592", capa.features.insn.API("DoesNotExist"), False),
        # call/api
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.API("LdrLoadDll"), True),
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.API("DoesNotExist"), False),
        # call/string argument
        (
            "93b2d1-drakvuf",
            "process=(3564:4852),thread=6592,call=1",
            capa.features.common.String('0x667e2beb40:"api-ms-win-core-fibers-l1-1-1"'),
            True,
        ),
        (
            "93b2d1-drakvuf",
            "process=(3564:4852),thread=6592,call=1",
            capa.features.common.String("non_existant"),
            False,
        ),
        # call/number argument
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.Number(0x801), True),
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.Number(0x010101010101), False),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)

DYNAMIC_DRAKVUF_FEATURE_COUNT_TESTS = sorted(
    [
        ("93b2d1-drakvuf", "file", capa.features.common.String("\\Program Files\\WindowsApps\\does_not_exist"), False),
        # file/imports
        ("93b2d1-drakvuf", "file", capa.features.file.Import("SetUnhandledExceptionFilter"), 1),
        # thread/api calls
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592", capa.features.insn.API("LdrLoadDll"), 9),
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592", capa.features.insn.API("DoesNotExist"), False),
        # call/api
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.API("LdrLoadDll"), 1),
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.API("DoesNotExist"), 0),
        # call/string argument
        (
            "93b2d1-drakvuf",
            "process=(3564:4852),thread=6592,call=1",
            capa.features.common.String('0x667e2beb40:"api-ms-win-core-fibers-l1-1-1"'),
            1,
        ),
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.common.String("non_existant"), 0),
        # call/number argument
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.Number(0x801), 1),
        ("93b2d1-drakvuf", "process=(3564:4852),thread=6592,call=1", capa.features.insn.Number(0x010101010101), 0),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    DYNAMIC_DRAKVUF_FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_drakvuf_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_drakvuf_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    DYNAMIC_DRAKVUF_FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_drakvuf_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_drakvuf_extractor, sample, scope, feature, expected)
