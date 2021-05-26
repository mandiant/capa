# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import pytest
from fixtures import *
from fixtures import parametrize

import capa.features.file


def smda_parametrize(params, valuess, **kwargs):
    """
    fixup pytest parametrization to mark a subset of tests as xfail.

    xfail SMDA tests that rely on function id.
    """
    ret = []
    for values in valuess:
        (_, scope, feature, expected) = values
        if scope == "file" and isinstance(feature, capa.features.file.FunctionName) and expected is True:
            # pytest.param behaves like a list, but carries along associated marks, like xfail.
            #
            # https://stackoverflow.com/a/30575822/87207
            ret.append(pytest.param(*values, marks=pytest.mark.xfail(reason="SMDA has no function ID")))
        else:
            ret.append(values)
    return parametrize(params, ret, **kwargs)


@smda_parametrize(
    "sample,scope,feature,expected",
    FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_smda_features(sample, scope, feature, expected):
    do_test_feature_presence(get_smda_extractor, sample, scope, feature, expected)


@smda_parametrize(
    "sample,scope,feature,expected",
    FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_smda_feature_counts(sample, scope, feature, expected):
    do_test_feature_count(get_smda_extractor, sample, scope, feature, expected)
