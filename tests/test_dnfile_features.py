# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import pytest
import fixtures
from fixtures import *
from fixtures import parametrize


@parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS_DOTNET,
    indirect=["sample", "scope"],
)
def test_dnfile_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_dnfile_extractor, sample, scope, feature, expected)


@parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS_DOTNET,
    indirect=["sample", "scope"],
)
def test_dnfile_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_dnfile_extractor, sample, scope, feature, expected)
