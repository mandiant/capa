# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys

from fixtures import *


@parametrize(
    "sample,scope,feature,expected",
    FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_viv_features(sample, scope, feature, expected):
    with xfail(sys.version_info >= (3, 0), reason="vivsect only works on py2"):
        do_test_feature_presence(get_viv_extractor, sample, scope, feature, expected)


@parametrize(
    "sample,scope,feature,expected",
    FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_viv_feature_counts(sample, scope, feature, expected):
    with xfail(sys.version_info >= (3, 0), reason="vivsect only works on py2"):
        do_test_feature_count(get_viv_extractor, sample, scope, feature, expected)
