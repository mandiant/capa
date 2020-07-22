# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import textwrap

from fixtures import *

import capa.main
import capa.helpers
import capa.features
import capa.features.insn
import capa.features.freeze
import capa.features.extractors

EXTRACTOR = capa.features.extractors.NullFeatureExtractor(
    {
        "base address": 0x401000,
        "file features": [(0x402345, capa.features.Characteristic("embedded pe")),],
        "functions": {
            0x401000: {
                "features": [(0x401000, capa.features.Characteristic("switch")),],
                "basic blocks": {
                    0x401000: {
                        "features": [(0x401000, capa.features.Characteristic("tight loop")),],
                        "instructions": {
                            0x401000: {
                                "features": [
                                    (0x401000, capa.features.insn.Mnemonic("xor")),
                                    (0x401000, capa.features.Characteristic("nzxor")),
                                ],
                            },
                            0x401002: {"features": [(0x401002, capa.features.insn.Mnemonic("mov")),],},
                        },
                    },
                },
            },
        },
    }
)


def test_null_feature_extractor():
    assert list(EXTRACTOR.get_functions()) == [0x401000]
    assert list(EXTRACTOR.get_basic_blocks(0x401000)) == [0x401000]
    assert list(EXTRACTOR.get_instructions(0x401000, 0x0401000)) == [0x401000, 0x401002]

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

    # TODO: ordering of these things probably doesn't work yet

    assert list(a.extract_file_features()) == list(b.extract_file_features())
    assert list(a.get_functions()) == list(b.get_functions())
    for f in a.get_functions():
        assert list(a.get_basic_blocks(f)) == list(b.get_basic_blocks(f))
        assert list(a.extract_function_features(f)) == list(b.extract_function_features(f))

        for bb in a.get_basic_blocks(f):
            assert list(a.get_instructions(f, bb)) == list(b.get_instructions(f, bb))
            assert list(a.extract_basic_block_features(f, bb)) == list(b.extract_basic_block_features(f, bb))

            for insn in a.get_instructions(f, bb):
                assert list(a.extract_insn_features(f, bb, insn)) == list(b.extract_insn_features(f, bb, insn))


def compare_extractors_viv_null(viv_ext, null_ext):
    """
    almost identical to compare_extractors but adds casts to ints since the VivisectFeatureExtractor returns objects
    and NullFeatureExtractor returns ints

    args:
      viv_ext (capa.features.extractors.viv.VivisectFeatureExtractor)
      null_ext (capa.features.extractors.NullFeatureExtractor)
    """

    # TODO: ordering of these things probably doesn't work yet

    assert list(viv_ext.extract_file_features()) == list(null_ext.extract_file_features())
    assert to_int(list(viv_ext.get_functions())) == list(null_ext.get_functions())
    for f in viv_ext.get_functions():
        assert to_int(list(viv_ext.get_basic_blocks(f))) == list(null_ext.get_basic_blocks(to_int(f)))
        assert list(viv_ext.extract_function_features(f)) == list(null_ext.extract_function_features(to_int(f)))

        for bb in viv_ext.get_basic_blocks(f):
            assert to_int(list(viv_ext.get_instructions(f, bb))) == list(
                null_ext.get_instructions(to_int(f), to_int(bb))
            )
            assert list(viv_ext.extract_basic_block_features(f, bb)) == list(
                null_ext.extract_basic_block_features(to_int(f), to_int(bb))
            )

            for insn in viv_ext.get_instructions(f, bb):
                assert list(viv_ext.extract_insn_features(f, bb, insn)) == list(
                    null_ext.extract_insn_features(to_int(f), to_int(bb), to_int(insn))
                )


def to_int(o):
    """helper to get int value of extractor items"""
    if isinstance(o, list):
        return map(lambda x: capa.helpers.oint(x), o)
    else:
        return capa.helpers.oint(o)


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
    roundtrip_feature(capa.features.String("SCardControl"))
    roundtrip_feature(capa.features.insn.Number(0xFF))
    roundtrip_feature(capa.features.insn.Offset(0x0))
    roundtrip_feature(capa.features.insn.Mnemonic("push"))
    roundtrip_feature(capa.features.file.Section(".rsrc"))
    roundtrip_feature(capa.features.Characteristic("tight loop"))
    roundtrip_feature(capa.features.basicblock.BasicBlock())
    roundtrip_feature(capa.features.file.Export("BaseThreadInitThunk"))
    roundtrip_feature(capa.features.file.Import("kernel32.IsWow64Process"))
    roundtrip_feature(capa.features.file.Import("#11"))


def test_freeze_sample(tmpdir, sample_9324d1a8ae37a36ae560c37448c9705a):
    # tmpdir fixture handles cleanup
    o = tmpdir.mkdir("capa").join("test.frz").strpath
    assert capa.features.freeze.main([sample_9324d1a8ae37a36ae560c37448c9705a.path, o, "-v"]) == 0


def test_freeze_load_sample(tmpdir, sample_9324d1a8ae37a36ae560c37448c9705a):
    o = tmpdir.mkdir("capa").join("test.frz")
    viv_extractor = capa.features.extractors.viv.VivisectFeatureExtractor(
        sample_9324d1a8ae37a36ae560c37448c9705a.vw, sample_9324d1a8ae37a36ae560c37448c9705a.path,
    )
    with open(o.strpath, "wb") as f:
        f.write(capa.features.freeze.dump(viv_extractor))
    null_extractor = capa.features.freeze.load(o.open("rb").read())
    compare_extractors_viv_null(viv_extractor, null_extractor)
