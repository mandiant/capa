# Copyright 2026 Google LLC
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

import textwrap

import capa.rules
from capa.features.insn import API
from capa.features.address import AbsoluteVirtualAddress
from capa.features.extractors.null import (
    FunctionFeatures,
    BasicBlockFeatures,
    InstructionFeatures,
    NullStaticFeatureExtractor,
)
from capa.features.extractors.base_extractor import BBHandle, SampleHashes
from capa.capabilities.common import find_capabilities


class GraphNullStaticExtractor(NullStaticFeatureExtractor):
    def __init__(self, *args, edges=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._edges = edges or {}

    def get_cfg_edges(self, f, bb):
        for succ in self._edges.get(int(f.address), {}).get(int(bb.address), []):
            yield BBHandle(AbsoluteVirtualAddress(succ), None)


def make_graph_extractor():
    fva = AbsoluteVirtualAddress(0x401000)
    b0 = AbsoluteVirtualAddress(0x401000)
    b1 = AbsoluteVirtualAddress(0x401100)
    b2 = AbsoluteVirtualAddress(0x401200)
    b3 = AbsoluteVirtualAddress(0x401300)
    b4 = AbsoluteVirtualAddress(0x401400)
    b5 = AbsoluteVirtualAddress(0x401500)

    return GraphNullStaticExtractor(
        base_address=AbsoluteVirtualAddress(0x400000),
        sample_hashes=SampleHashes(md5="", sha1="", sha256=""),
        global_features=[],
        file_features=[],
        functions={
            fva: FunctionFeatures(
                features=[],
                basic_blocks={
                    b0: BasicBlockFeatures(
                        features=[],
                        instructions={
                            AbsoluteVirtualAddress(0x401001): InstructionFeatures(
                                features=[(AbsoluteVirtualAddress(0x401001), API("CreateFileA"))]
                            )
                        },
                    ),
                    b1: BasicBlockFeatures(features=[], instructions={}),
                    b2: BasicBlockFeatures(
                        features=[],
                        instructions={
                            AbsoluteVirtualAddress(0x401201): InstructionFeatures(
                                features=[(AbsoluteVirtualAddress(0x401201), API("WriteFile"))]
                            )
                        },
                    ),
                    b3: BasicBlockFeatures(
                        features=[],
                        instructions={},
                    ),
                    b4: BasicBlockFeatures(
                        features=[],
                        instructions={},
                    ),
                    b5: BasicBlockFeatures(
                        features=[],
                        instructions={
                            AbsoluteVirtualAddress(0x401501): InstructionFeatures(
                                features=[(AbsoluteVirtualAddress(0x401501), API("CloseHandle"))]
                            )
                        },
                    ),
                },
            )
        },
        edges={
            int(fva): {
                int(b0): [int(b1)],
                int(b1): [int(b2)],
                int(b2): [int(b3)],
                int(b3): [int(b4)],
                int(b4): [int(b5)],
            }
        },
    )


def test_connected_blocks_depth2_match():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: connected blocks depth2
                            scopes:
                                static: function
                                dynamic: process
                        features:
                            - and:
                                - connected blocks:
                                    - and:
                                        - api: CreateFileA
                                        - api: WriteFile
                    """
                )
            ),
        ]
    )
    capabilities = find_capabilities(rules, make_graph_extractor())
    assert "connected blocks depth2" in capabilities.matches
    assert AbsoluteVirtualAddress(0x401000) in {m[0] for m in capabilities.matches["connected blocks depth2"]}


def test_connected_blocks_too_far_no_match():
    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: connected blocks too far
                            scopes:
                                static: function
                                dynamic: process
                        features:
                            - and:
                                - connected blocks:
                                    - and:
                                        - api: CreateFileA
                                        - api: CloseHandle
                    """
                )
            ),
        ]
    )
    capabilities = find_capabilities(rules, make_graph_extractor())
    assert "connected blocks too far" not in capabilities.matches
