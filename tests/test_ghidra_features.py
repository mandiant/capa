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
import importlib.util
import os

import pytest
import fixtures

import capa.features.common

ghidra_present = importlib.util.find_spec("pyghidra") is not None and "GHIDRA_INSTALL_DIR" in os.environ


@pytest.mark.skipif(ghidra_present is False, reason="PyGhidra not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected",
    [
        t
        for t in fixtures.FEATURE_PRESENCE_TESTS
        # this test case is specific to Vivisect and its basic blocks do not align with Ghidra's analysis
        if t[0] != "294b8d..." or t[2] != capa.features.common.String("\r\n\x00:ht")
    ],
    indirect=["sample", "scope"],
)
def test_ghidra_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_ghidra_extractor, sample, scope, feature, expected)


@pytest.mark.skipif(ghidra_present is False, reason="PyGhidra not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected", fixtures.FEATURE_COUNT_TESTS_GHIDRA, indirect=["sample", "scope"]
)
def test_ghidra_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_ghidra_extractor, sample, scope, feature, expected)
