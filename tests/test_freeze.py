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
import capa.features.extractors.null
import capa.features.extractors.base_extractor
from capa.features.address import AbsoluteVirtualAddress

EXTRACTOR = capa.features.extractors.null.NullFeatureExtractor(
    base_address=AbsoluteVirtualAddress(0x401000),
    global_features=[],
    file_features=[
        (AbsoluteVirtualAddress(0x402345), capa.features.common.Characteristic("embedded pe")),
    ],
    functions={
        AbsoluteVirtualAddress(0x401000): capa.features.extractors.null.FunctionFeatures(
            features=[
                (AbsoluteVirtualAddress(0x401000), capa.features.common.Characteristic("indirect call")),
            ],
            basic_blocks={
                AbsoluteVirtualAddress(0x401000): capa.features.extractors.null.BasicBlockFeatures(
                    features=[
                        (AbsoluteVirtualAddress(0x401000), capa.features.common.Characteristic("tight loop")),
                    ],
                    instructions={
                        AbsoluteVirtualAddress(0x401000): capa.features.extractors.null.InstructionFeatures(
                            features=[
                                (AbsoluteVirtualAddress(0x401000), capa.features.insn.Mnemonic("xor")),
                                (AbsoluteVirtualAddress(0x401000), capa.features.common.Characteristic("nzxor")),
                            ],
                        ),
                        AbsoluteVirtualAddress(0x401002): capa.features.extractors.null.InstructionFeatures(
                            features=[
                                (AbsoluteVirtualAddress(0x401002), capa.features.insn.Mnemonic("mov")),
                            ],
                        ),
                    },
                ),
            },
        ),
    },
)


def addresses(s) -> List[Address]:
    return list(sorted(map(lambda i: i.address, s)))


def test_null_feature_extractor():
    fh = FunctionHandle(AbsoluteVirtualAddress(0x401000), None)
    bbh = BBHandle(AbsoluteVirtualAddress(0x401000), None)

    assert addresses(EXTRACTOR.get_functions()) == [AbsoluteVirtualAddress(0x401000)]
    assert addresses(EXTRACTOR.get_basic_blocks(fh)) == [AbsoluteVirtualAddress(0x401000)]
    assert addresses(EXTRACTOR.get_instructions(fh, bbh)) == [
        AbsoluteVirtualAddress(0x401000),
        AbsoluteVirtualAddress(0x401002),
    ]

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
    assert list(a.extract_file_features()) == list(b.extract_file_features())

    assert addresses(a.get_functions()) == addresses(b.get_functions())
    for f in a.get_functions():
        assert addresses(a.get_basic_blocks(f)) == addresses(b.get_basic_blocks(f))
        assert list(sorted(set(a.extract_function_features(f)))) == list(sorted(set(b.extract_function_features(f))))

        for bb in a.get_basic_blocks(f):
            assert addresses(a.get_instructions(f, bb)) == addresses(b.get_instructions(f, bb))
            assert list(sorted(set(a.extract_basic_block_features(f, bb)))) == list(
                sorted(set(b.extract_basic_block_features(f, bb)))
            )

            for insn in a.get_instructions(f, bb):
                assert list(sorted(set(a.extract_insn_features(f, bb, insn)))) == list(
                    sorted(set(b.extract_insn_features(f, bb, insn)))
                )


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


def roundtrip_feature(feature):
    assert feature == capa.features.freeze.feature_from_capa(feature).to_capa()


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
    roundtrip_feature(capa.features.insn.OperandOffset(0, 0x8))
    roundtrip_feature(
        capa.features.insn.Property("System.IO.FileInfo::Length", access=capa.features.common.FeatureAccess.READ)
    )
    roundtrip_feature(capa.features.insn.Property("System.IO.FileInfo::Length"))


def test_freeze_sample(tmpdir, z9324d_extractor):
    # tmpdir fixture handles cleanup
    o = tmpdir.mkdir("capa").join("test.frz").strpath
    path = z9324d_extractor.path
    assert capa.features.freeze.main([path, o, "-v"]) == 0


@pytest.mark.parametrize(
    "extractor",
    [
        pytest.param("z9324d_extractor"),
    ],
)
def test_freeze_load_sample(tmpdir, request, extractor):
    o = tmpdir.mkdir("capa").join("test.frz")

    extractor = request.getfixturevalue(extractor)

    with open(o.strpath, "wb") as f:
        f.write(capa.features.freeze.dump(extractor))

    with open(o.strpath, "rb") as f:
        null_extractor = capa.features.freeze.load(f.read())

    compare_extractors(extractor, null_extractor)
