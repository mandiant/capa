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

import fixtures

import capa.features.file


@fixtures.parametrize(
    "sample,scope,feature,expected",
    [
        ("mimikatz", "function=0x401000", capa.features.file.Section(".text"), True),
        ("mimikatz", "function=0x401000", capa.features.file.Section(".nope"), False),
    ],
    indirect=["sample", "scope"],
)
def test_function_section_features_viv(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_viv_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    [
        ("687e79.ghidra.be2", "function=0x1056c0", capa.features.file.Section(".text"), True),
        ("687e79.ghidra.be2", "function=0x1056c0", capa.features.file.Section(".nope"), False),
    ],
    indirect=["sample", "scope"],
)
def test_function_section_features_binexport2(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_binexport_extractor, sample, scope, feature, expected)
