# Copyright 2022 Google LLC
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

import fixtures


@fixtures.parametrize_backend_feature_fixtures(
    fixtures.BackendFeaturePolicy(
        name="dotnetfile",
        include_tags={"dotnet"},
        exclude_tags={
            # dotnetfile is a file-scope extractor; drop non-file scopes
            "function",
            "basic-block",
            "instruction",
            # and drop feature types dotnetfile doesn't produce
            "function-name",
        },
    )
)
def test_dotnetfile_features(feature_fixture):
    extractor = fixtures.get_dotnetfile_extractor(feature_fixture.sample_path)
    fixtures.run_feature_fixture(extractor, feature_fixture)


def test_dotnetfile_extractor_is_dotnet_file():
    extractor = fixtures.get_dotnetfile_extractor(fixtures.CD / "data" / "b9f5bd514485fb06da39beff051b9fdc.exe_")
    assert extractor.is_dotnet_file() is True


def test_dotnetfile_extractor_is_not_mixed_mode():
    extractor = fixtures.get_dotnetfile_extractor(fixtures.CD / "data" / "b9f5bd514485fb06da39beff051b9fdc.exe_")
    assert extractor.is_mixed_mode() is False


def test_dotnetfile_extractor_mixed_mode_64_is_mixed_mode():
    extractor = fixtures.get_dotnetfile_extractor(
        fixtures.DNFILE_TESTFILES / "mixed-mode" / "ModuleCode" / "bin" / "ModuleCode_amd64.exe"
    )
    assert extractor.is_mixed_mode() is True


def test_dotnetfile_extractor_get_entry_point():
    extractor = fixtures.get_dotnetfile_extractor(fixtures.CD / "data" / "b9f5bd514485fb06da39beff051b9fdc.exe_")
    assert extractor.get_entry_point() == 0x6000007


def test_dotnetfile_extractor_get_runtime_version():
    extractor = fixtures.get_dotnetfile_extractor(fixtures.CD / "data" / "b9f5bd514485fb06da39beff051b9fdc.exe_")
    assert extractor.get_runtime_version() == (2, 5)


def test_dotnetfile_extractor_get_meta_version_string():
    extractor = fixtures.get_dotnetfile_extractor(fixtures.CD / "data" / "b9f5bd514485fb06da39beff051b9fdc.exe_")
    assert extractor.get_meta_version_string() == "v2.0.50727"
