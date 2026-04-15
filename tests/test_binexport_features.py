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

from typing import cast

import fixtures
import pytest

import capa.features.common

BACKEND = fixtures.BackendFeaturePolicy(
    name="binexport",
    get_extractor=fixtures.get_binexport_extractor,
    include_tags={"binexport"},
)


@fixtures.parametrize_backend_feature_fixtures(BACKEND)
def test_binexport_features_elf_aarch64(feature_fixture):
    fixtures.run_feature_fixture(BACKEND, feature_fixture)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_binexport_features_pe_x86(sample, scope, feature, expected):
    if "mimikatz.exe_" not in sample.name:
        pytest.skip("for now only testing mimikatz.exe_ Ghidra BinExport file")

    if isinstance(
        feature, capa.features.common.Characteristic
    ) and "stack string" in cast(str, feature.value):
        pytest.skip("for now only testing basic features")

    sample = sample.parent / "binexport2" / (sample.name + ".ghidra.BinExport")
    assert sample.exists()
    fixtures.do_test_feature_presence(
        fixtures.get_binexport_extractor, sample, scope, feature, expected
    )


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS_GHIDRA,
    indirect=["sample", "scope"],
)
def test_binexport_feature_counts_ghidra(sample, scope, feature, expected):
    if "mimikatz.exe_" not in sample.name:
        pytest.skip("for now only testing mimikatz.exe_ Ghidra BinExport file")
    sample = sample.parent / "binexport2" / (sample.name + ".ghidra.BinExport")
    assert sample.exists()
    fixtures.do_test_feature_count(
        fixtures.get_binexport_extractor, sample, scope, feature, expected
    )
