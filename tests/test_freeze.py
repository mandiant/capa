# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import textwrap
from typing import List

from fixtures import *

import capa.main
import capa.rules
import capa.helpers
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.freeze
import capa.features.basicblock
import capa.features.extractors.base_extractor
from capa.features.address import AbsoluteVirtualAddress

EXTRACTOR = capa.features.extractors.base_extractor.NullFeatureExtractor(
    {
        "base address": AbsoluteVirtualAddress(0x401000),
        "file features": [
            (AbsoluteVirtualAddress(0x402345), capa.features.common.Characteristic("embedded pe")),
        ],
        "functions": {
            AbsoluteVirtualAddress(0x401000): {
                "features": [
                    (AbsoluteVirtualAddress(0x401000), capa.features.common.Characteristic("indirect call")),
                ],
                "basic blocks": {
                    AbsoluteVirtualAddress(0x401000): {
                        "features": [
                            (AbsoluteVirtualAddress(0x401000), capa.features.common.Characteristic("tight loop")),
                        ],
                        "instructions": {
                            AbsoluteVirtualAddress(0x401000): {
                                "features": [
                                    (AbsoluteVirtualAddress(0x401000), capa.features.insn.Mnemonic("xor")),
                                    (AbsoluteVirtualAddress(0x401000), capa.features.common.Characteristic("nzxor")),
                                ],
                            },
                            AbsoluteVirtualAddress(0x401002): {
                                "features": [
                                    (AbsoluteVirtualAddress(0x401002), capa.features.insn.Mnemonic("mov")),
                                ],
                            },
                        },
                    },
                },
            },
        },
    }
)


def addresses(s) -> List[Address]:
    return list(sorted(map(lambda i: i.address, s)))


def test_null_feature_extractor():
    fh = FunctionHandle(AbsoluteVirtualAddress(0x401000), None)
    bbh = BBHandle(AbsoluteVirtualAddress(0x401000), None)

    assert addresses(EXTRACTOR.get_functions()) == [AbsoluteVirtualAddress(0x401000)]
    assert addresses(EXTRACTOR.get_basic_blocks(fh)) == [AbsoluteVirtualAddress(0x401000)]
    assert addresses(EXTRACTOR.get_instructions(fh, bbh)) == [AbsoluteVirtualAddress(0x401000), AbsoluteVirtualAddress(0x401002)]

    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: xor loop
                            scope: basic block
                        features:
                            - and:
                                - characteristic: tight loop
                                - mnemonic: xor
                                - characteristic: nzxor
                    """
                )
            ),
        ]
    )
    capabilities, meta = capa.main.find_capabilities(rules, EXTRACTOR)
    assert "xor loop" in capabilities


def compare_extractors(a, b):
    """
    args:
      a (capa.features.extractors.NullFeatureExtractor)
      b (capa.features.extractors.NullFeatureExtractor)
    """
    assert list(a.extract_file_features()) == list(b.extract_file_features())

    assert addresses(a.get_functions()) == addresses(b.get_functions())
    for f in a.get_functions():
        assert addresses(a.get_basic_blocks(f)) == addresses(b.get_basic_blocks(f))
        assert list(a.extract_function_features(f)) == list(b.extract_function_features(f))

        for bb in a.get_basic_blocks(f):
            assert addresses(a.get_instructions(f, bb)) == addresses(b.get_instructions(f, bb))
            assert list(a.extract_basic_block_features(f, bb)) == list(b.extract_basic_block_features(f, bb))

            for insn in a.get_instructions(f, bb):
                assert list(a.extract_insn_features(f, bb, insn)) == list(b.extract_insn_features(f, bb, insn))


def test_freeze_s_roundtrip():
    load = capa.features.freeze.loads
    dump = capa.features.freeze.dumps
    reanimated = load(dump(EXTRACTOR))
    compare_extractors(EXTRACTOR, reanimated)


def test_freeze_b_roundtrip():
    load = capa.features.freeze.load
    dump = capa.features.freeze.dump
    reanimated = load(dump(EXTRACTOR))
    compare_extractors(EXTRACTOR, reanimated)


def roundtrip_feature(feature):
    serialize = capa.features.freeze.serialize_feature
    deserialize = capa.features.freeze.deserialize_feature
    assert feature == deserialize(serialize(feature))


def test_serialize_features():
    roundtrip_feature(capa.features.insn.API("advapi32.CryptAcquireContextW"))
    roundtrip_feature(capa.features.common.String("SCardControl"))
    roundtrip_feature(capa.features.insn.Number(0xFF))
    roundtrip_feature(capa.features.insn.Offset(0x0))
    roundtrip_feature(capa.features.insn.Mnemonic("push"))
    roundtrip_feature(capa.features.file.Section(".rsrc"))
    roundtrip_feature(capa.features.common.Characteristic("tight loop"))
    roundtrip_feature(capa.features.basicblock.BasicBlock())
    roundtrip_feature(capa.features.file.Export("BaseThreadInitThunk"))
    roundtrip_feature(capa.features.file.Import("kernel32.IsWow64Process"))
    roundtrip_feature(capa.features.file.Import("#11"))


def test_freeze_sample(tmpdir, z9324d_extractor):
    # tmpdir fixture handles cleanup
    o = tmpdir.mkdir("capa").join("test.frz").strpath
    path = z9324d_extractor.path
    assert capa.features.freeze.main([path, o, "-v"]) == 0


def test_freeze_load_sample(tmpdir, z9324d_extractor):
    o = tmpdir.mkdir("capa").join("test.frz")

    with open(o.strpath, "wb") as f:
        f.write(capa.features.freeze.dump(z9324d_extractor))

    with open(o.strpath, "rb") as f:
        null_extractor = capa.features.freeze.load(f.read())

    compare_extractors(z9324d_extractor, null_extractor)
