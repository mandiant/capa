# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys

import pytest
from fixtures import *
from fixtures import parametrize

import capa.features.file


@parametrize(
    "sample,scope,feature,expected",
    FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_pefile_features(sample, scope, feature, expected):
    if scope.__name__ != "file":
        pytest.xfail("pefile only extract file scope features")

    if isinstance(feature, capa.features.file.FunctionName):
        pytest.xfail("pefile only doesn't extract function names")

    do_test_feature_presence(get_pefile_extractor, sample, scope, feature, expected)
