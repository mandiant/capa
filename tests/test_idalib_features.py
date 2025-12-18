# Copyright 2020 Google LLC
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

import pytest
import fixtures

import capa.features.extractors.ida.idalib

logger = logging.getLogger(__name__)

idalib_present = capa.features.extractors.ida.idalib.has_idalib()
if idalib_present:
    try:
        import idapro  # noqa: F401 [imported but unused]
    except ImportError:
        idalib_present = False


@pytest.mark.skipif(idalib_present is False, reason="Skip idalib tests if the idalib Python API is not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS + fixtures.FEATURE_SYMTAB_FUNC_TESTS,
    indirect=["sample", "scope"],
)
def test_idalib_features(sample, scope, feature, expected):
    try:
        fixtures.do_test_feature_presence(fixtures.get_idalib_extractor, sample, scope, feature, expected)
    finally:
        logger.debug("closing database...")
        import idapro

        idapro.close_database(save=False)
        logger.debug("closed database.")


@pytest.mark.skipif(idalib_present is False, reason="Skip idalib tests if the idalib Python API is not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_idalib_feature_counts(sample, scope, feature, expected):
    try:
        fixtures.do_test_feature_count(fixtures.get_idalib_extractor, sample, scope, feature, expected)
    finally:
        logger.debug("closing database...")
        import idapro

        idapro.close_database(save=False)
        logger.debug("closed database.")
