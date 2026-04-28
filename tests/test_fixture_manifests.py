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

from fixtures import get_fixture_files


def test_no_orphaned_file_entries():
    for manifest_path, data in get_fixture_files():
        feature_refs = {feat["file"] for feat in data.get("features", [])}
        for entry in data["files"]:
            assert entry["key"] in feature_refs, (
                f"file entry {entry['key']!r} in {manifest_path.name} is not referenced by any feature"
            )
