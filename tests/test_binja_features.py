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

import fixtures
import pytest

import capa.features.common
import capa.main

logger = logging.getLogger(__file__)


# We need to skip the binja test if we cannot import binaryninja, e.g., in GitHub CI.
binja_present: bool = False
try:
    import binaryninja

    try:
        binaryninja.load(source=b"\x90")
    except RuntimeError:
        logger.warning(
            "Binary Ninja license is not valid, provide via $BN_LICENSE or license.dat"
        )
    else:
        binja_present = True
except ImportError:
    pass


BACKEND = fixtures.BackendFeaturePolicy(
    name="binja",
    # binja also loads .bndb database files natively, so include `binja-db`
    # alongside the regular static-binary fixtures.
    get_extractor=fixtures.get_binja_extractor,
    include_tags={"static", "binja-db"},
    exclude_tags={"dotnet", "ghidra"},
)


@pytest.mark.skipif(
    binja_present is False,
    reason="Skip binja tests if the binaryninja Python API is not installed",
)
@fixtures.parametrize_backend_feature_fixtures(BACKEND)
def test_binja_features(feature_fixture):
    fixtures.run_feature_fixture(BACKEND, feature_fixture)


@pytest.mark.skipif(
    binja_present is False,
    reason="Skip binja tests if the binaryninja Python API is not installed",
)
def test_standalone_binja_backend():
    CD = Path(__file__).resolve().parent
    test_path = (
        CD / ".." / "tests" / "data" / "Practical Malware Analysis Lab 01-01.exe_"
    )
    assert capa.main.main([str(test_path), "-b", capa.main.BACKEND_BINJA]) == 0


@pytest.mark.skipif(
    binja_present is False,
    reason="Skip binja tests if the binaryninja Python API is not installed",
)
def test_binja_version():
    version = binaryninja.core_version_info()  # type: ignore[possibly-undefined]  # guarded by skipif binja_present
    assert (version.major, version.minor) >= (5, 3)
