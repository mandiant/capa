# Copyright 2025 Google LLC
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

import capa.main
import capa.rules
import capa.loader
import capa.features.common
import capa.features.basicblock
import capa.features.extractors.null
from capa.features.address import AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import BBHandle, SampleHashes, FunctionHandle


def test_compute_static_layout_with_missing_basic_block():
    """
    Test that compute_static_layout handles the case where a matched
    basic block address is no longer present when re-enumerating BBs.

    This can happen with extractors like Binary Ninja where the analysis
    state may change between feature extraction and layout computation,
    causing basic block boundaries to shift.

    See #2734.
    """
    # Create an extractor with two basic blocks at 0x401000 and 0x401010
    extractor = capa.features.extractors.null.NullStaticFeatureExtractor(
        base_address=AbsoluteVirtualAddress(0x401000),
        sample_hashes=SampleHashes(
            md5="6eb7ee7babf913d75df3f86c229df9e7",
            sha1="2a082494519acd5130d5120fa48786df7275fdd7",
            sha256="0c7d1a34eb9fd55bedbf37ba16e3d5dd8c1dd1d002479cc4af27ef0f82bb4792",
        ),
        global_features=[],
        file_features=[],
        functions={
            AbsoluteVirtualAddress(0x401000): capa.features.extractors.null.FunctionFeatures(
                features=[],
                basic_blocks={
                    AbsoluteVirtualAddress(0x401000): capa.features.extractors.null.BasicBlockFeatures(
                        features=[
                            (AbsoluteVirtualAddress(0x401000), capa.features.common.Characteristic("tight loop")),
                        ],
                        instructions={},
                    ),
                },
            ),
        },
    )

    rules = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                        meta:
                            name: test rule
                            scopes:
                                static: basic block
                                dynamic: process
                        features:
                            - characteristic: tight loop
                    """
                )
            ),
        ]
    )

    # Find capabilities — the rule matches at BB 0x401000
    capabilities = capa.main.find_capabilities(rules, extractor)
    assert "test rule" in capabilities.matches

    # Now simulate the regression: remove the matched BB from the extractor
    # so that when compute_static_layout re-enumerates BBs, it won't find it.
    # This simulates what happens with Binary Ninja when IL recomputation
    # changes basic block boundaries between the two passes.
    del extractor.functions[AbsoluteVirtualAddress(0x401000)].basic_blocks[AbsoluteVirtualAddress(0x401000)]

    # Before the fix, this would raise AssertionError.
    # After the fix, it should complete gracefully with a warning.
    layout = capa.loader.compute_static_layout(rules, extractor, capabilities.matches)

    # The layout should be valid but empty (the only matched BB was removed)
    assert len(layout.functions) == 0
