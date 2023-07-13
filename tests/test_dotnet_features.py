# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import fixtures


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS_DOTNET,
    indirect=["sample", "scope"],
)
def test_dnfile_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_dnfile_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "extractor,function,expected",
    [
        ("b9f5b_dotnetfile_extractor", "is_dotnet_file", True),
        ("b9f5b_dotnetfile_extractor", "is_mixed_mode", False),
        ("mixed_mode_64_dotnetfile_extractor", "is_mixed_mode", True),
        ("b9f5b_dotnetfile_extractor", "get_entry_point", 0x6000007),
        ("b9f5b_dotnetfile_extractor", "get_runtime_version", (2, 5)),
        ("b9f5b_dotnetfile_extractor", "get_meta_version_string", "v2.0.50727"),
    ],
)
def test_dnfile_extractor(request, extractor, function, expected):
    extractor_function = getattr(request.getfixturevalue(extractor), function)
    assert extractor_function() == expected
