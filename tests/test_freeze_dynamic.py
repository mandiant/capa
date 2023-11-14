# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import textwrap
from typing import List
from pathlib import Path

import fixtures

import capa.main
import capa.rules
import capa.helpers
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.freeze
import capa.features.basicblock
import capa.features.extractors.null
import capa.features.extractors.base_extractor
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import (
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    ThreadAddress,
    ProcessAddress,
    DynamicCallAddress,
    DynamicFeatureExtractor,
)

EXTRACTOR = capa.features.extractors.null.NullDynamicFeatureExtractor(
    base_address=AbsoluteVirtualAddress(0x401000),
    sample_hashes=SampleHashes(
        md5="6eb7ee7babf913d75df3f86c229df9e7",
        sha1="2a082494519acd5130d5120fa48786df7275fdd7",
        sha256="0c7d1a34eb9fd55bedbf37ba16e3d5dd8c1dd1d002479cc4af27ef0f82bb4792",
    ),
    global_features=[],
    file_features=[
        (AbsoluteVirtualAddress(0x402345), capa.features.common.Characteristic("embedded pe")),
    ],
    processes={
        ProcessAddress(pid=1): capa.features.extractors.null.ProcessFeatures(
            name="explorer.exe",
            features=[],
            threads={
                ThreadAddress(ProcessAddress(pid=1), tid=1): capa.features.extractors.null.ThreadFeatures(
                    features=[],
                    calls={
                        DynamicCallAddress(
                            thread=ThreadAddress(ProcessAddress(pid=1), tid=1), id=1
                        ): capa.features.extractors.null.CallFeatures(
                            name="CreateFile(12)",
                            features=[
                                (
                                    DynamicCallAddress(thread=ThreadAddress(ProcessAddress(pid=1), tid=1), id=1),
                                    capa.features.insn.API("CreateFile"),
                                ),
                                (
                                    DynamicCallAddress(thread=ThreadAddress(ProcessAddress(pid=1), tid=1), id=1),
                                    capa.features.insn.Number(12),
                                ),
                            ],
                        ),
                        DynamicCallAddress(
                            thread=ThreadAddress(ProcessAddress(pid=1), tid=1), id=2
                        ): capa.features.extractors.null.CallFeatures(
                            name="WriteFile()",
                            features=[
                                (
                                    DynamicCallAddress(thread=ThreadAddress(ProcessAddress(pid=1), tid=1), id=2),
                                    capa.features.insn.API("WriteFile"),
                                ),
                            ],
                        ),
                    },
                ),
            },
        ),
    },
)


def addresses(s) -> List[Address]:
    return sorted(i.address for i in s)


def test_null_feature_extractor():
    ph = ProcessHandle(ProcessAddress(pid=1), None)
    th = ThreadHandle(ThreadAddress(ProcessAddress(pid=1), tid=1), None)

    assert addresses(EXTRACTOR.get_processes()) == [ProcessAddress(pid=1)]
    assert addresses(EXTRACTOR.get_threads(ph)) == [ThreadAddress(ProcessAddress(pid=1), tid=1)]
    assert addresses(EXTRACTOR.get_calls(ph, th)) == [
        DynamicCallAddress(thread=ThreadAddress(ProcessAddress(pid=1), tid=1), id=1),
        DynamicCallAddress(thread=ThreadAddress(ProcessAddress(pid=1), tid=1), id=2),
    ]

    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: create file
                            scopes:
                                static: basic block
                                dynamic: call
                        features:
                            - and:
                                - api: CreateFile
                    """
                )
            ),
        ]
    )
    capabilities, _ = capa.main.find_capabilities(rules, EXTRACTOR)
    assert "create file" in capabilities


def compare_extractors(a: DynamicFeatureExtractor, b: DynamicFeatureExtractor):
    assert list(a.extract_file_features()) == list(b.extract_file_features())

    assert addresses(a.get_processes()) == addresses(b.get_processes())
    for p in a.get_processes():
        assert addresses(a.get_threads(p)) == addresses(b.get_threads(p))
        assert sorted(set(a.extract_process_features(p))) == sorted(set(b.extract_process_features(p)))

        for t in a.get_threads(p):
            assert addresses(a.get_calls(p, t)) == addresses(b.get_calls(p, t))
            assert sorted(set(a.extract_thread_features(p, t))) == sorted(set(b.extract_thread_features(p, t)))

            for c in a.get_calls(p, t):
                assert sorted(set(a.extract_call_features(p, t, c))) == sorted(set(b.extract_call_features(p, t, c)))


def test_freeze_str_roundtrip():
    load = capa.features.freeze.loads
    dump = capa.features.freeze.dumps
    reanimated = load(dump(EXTRACTOR))
    compare_extractors(EXTRACTOR, reanimated)


def test_freeze_bytes_roundtrip():
    load = capa.features.freeze.load
    dump = capa.features.freeze.dump
    reanimated = load(dump(EXTRACTOR))
    compare_extractors(EXTRACTOR, reanimated)


def test_freeze_load_sample(tmpdir):
    o = tmpdir.mkdir("capa").join("test.frz")

    extractor = fixtures.get_cape_extractor(fixtures.get_data_path_by_name("d46900"))

    Path(o.strpath).write_bytes(capa.features.freeze.dump(extractor))

    null_extractor = capa.features.freeze.load(Path(o.strpath).read_bytes())

    compare_extractors(extractor, null_extractor)
