# Copyright 2021 Google LLC
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
from pathlib import Path

import fixtures

import capa.features.extractors.pefile
from capa.features.file import Import


@fixtures.parametrize_backend_feature_fixtures(
    fixtures.BackendFeaturePolicy(
        name="pefile",
        include_tags={"static"},
        exclude_tags={
            "dotnet",
            "elf",
            # pefile is a file-scope extractor; drop non-file scopes
            "function",
            "basic block",
            "instruction",
            # and drop feature types pefile doesn't produce
            "function-name",
        },
    )
)
def test_pefile_features(feature_fixture):
    extractor = fixtures.get_pefile_extractor(feature_fixture.sample_path)
    fixtures.run_feature_fixture(extractor, feature_fixture)


def test_pefile_extensionless_import_names():
    sample = Path(__file__).resolve().parent / "data" / "9ff8e68343cc29c1036650fc153e69f7.exe_"
    extractor = capa.features.extractors.pefile.PefileFeatureExtractor(sample)
    features = {f for f, _ in extractor.extract_file_features() if isinstance(f, Import)}

    # 9ff8e68343cc29c1036650fc153e69f7.exe_ imports NtUnmapViewOfSection from "ntdll" (without .dll extension)
    assert Import("ntdll.NtUnmapViewOfSection") in features
    assert Import("NtUnmapViewOfSection") in features
    assert Import(".NtUnmapViewOfSection") not in features

    # standard imports with .dll extension in the same sample should still have their extension stripped
    assert Import("kernel32.Sleep") in features
    assert Import("advapi32.RegQueryValueExA") in features
