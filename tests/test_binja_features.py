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

import logging
from pathlib import Path

import pytest
import fixtures

import capa.main
import capa.features.file
import capa.features.common

logger = logging.getLogger(__file__)


# We need to skip the binja test if we cannot import binaryninja, e.g., in GitHub CI.
binja_present: bool = False
try:
    import binaryninja

    try:
        binaryninja.load(source=b"\x90")
    except RuntimeError:
        logger.warning("Binary Ninja license is not valid, provide via $BN_LICENSE or license.dat")
    else:
        binja_present = True
except ImportError:
    pass


@pytest.mark.skipif(binja_present is False, reason="Skip binja tests if the binaryninja Python API is not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS + fixtures.FEATURE_SYMTAB_FUNC_TESTS + fixtures.FEATURE_BINJA_DATABASE_TESTS,
    indirect=["sample", "scope"],
)
def test_binja_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_binja_extractor, sample, scope, feature, expected)


@pytest.mark.skipif(binja_present is False, reason="Skip binja tests if the binaryninja Python API is not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_binja_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_binja_extractor, sample, scope, feature, expected)


@pytest.mark.skipif(binja_present is False, reason="Skip binja tests if the binaryninja Python API is not installed")
def test_standalone_binja_backend():
    CD = Path(__file__).resolve().parent
    test_path = CD / ".." / "tests" / "data" / "Practical Malware Analysis Lab 01-01.exe_"
    assert capa.main.main([str(test_path), "-b", capa.main.BACKEND_BINJA]) == 0


@pytest.mark.skipif(binja_present is False, reason="Skip binja tests if the binaryninja Python API is not installed")
def test_binja_version():
    version = binaryninja.core_version_info()
    assert version.major == 4 and version.minor == 2
