# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
Must invoke this script from within the Ghidra Runtime Enviornment
"""
import sys
import logging

import pytest
import fixtures

logger = logging.getLogger("test_ghidra_features")

ghidra_present: bool = False
try:
    import ghidra.program.flatapi  # noqa: F401

    ghidra_present = True
except ImportError:
    pass


def check_input_file(wanted):
    import capa.ghidra.helpers as ghidra_helpers

    found = ghidra_helpers.get_file_md5()
    if not wanted.startswith(found):
        raise RuntimeError(f"please run the tests against sample with MD5: `{wanted}`")


def get_ghidra_extractor(_path):
    import capa.features.extractors.ghidra.extractor

    return capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()


@pytest.mark.skipif(ghidra_present is False, reason="Ghidra tests must be ran within Ghidra")
@fixtures.parametrize("sample,scope,feature,expected", fixtures.FEATURE_PRESENCE_TESTS, indirect=["sample", "scope"])
def test_ghidra_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(get_ghidra_extractor, sample, scope, feature, expected)


@pytest.mark.skipif(ghidra_present is False, reason="Ghidra tests must be ran within Ghidra")
@fixtures.parametrize("sample,scope,feature,expected", fixtures.FEATURE_COUNT_TESTS, indirect=["sample", "scope"])
def test_ghidra_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(get_ghidra_extractor, sample, scope, feature, expected)


if __name__ == "__main__":
    sys.exit(pytest.main(["--pyargs", "test_ghidra_features"]))
