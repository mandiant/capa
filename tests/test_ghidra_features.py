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
import importlib.util
import os

import fixtures
import pytest

ghidra_present = (
    importlib.util.find_spec("pyghidra") is not None
    and "GHIDRA_INSTALL_DIR" in os.environ
)


BACKEND = fixtures.BackendFeaturePolicy(
    name="ghidra",
    get_extractor=fixtures.get_ghidra_extractor,
    include_tags={"static"},
    exclude_tags={"dotnet"},
)


@pytest.mark.skipif(ghidra_present is False, reason="PyGhidra not installed")
@fixtures.parametrize_backend_feature_fixtures(BACKEND)
def test_ghidra_features(feature_fixture):
    fixtures.run_feature_fixture(BACKEND, feature_fixture)
