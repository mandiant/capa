# Copyright 2021 Google LLC
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

import pytest
import fixtures

import capa.features.file


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_pefile_features(sample, scope, feature, expected):
    if scope.__name__ != "file":
        pytest.xfail("pefile only extracts file scope features")

    if isinstance(feature, capa.features.file.FunctionName):
        pytest.xfail("pefile doesn't extract function names")

    if ".elf" in sample.name:
        pytest.xfail("pefile doesn't handle ELF files")
    fixtures.do_test_feature_presence(fixtures.get_pefile_extractor, sample, scope, feature, expected)
