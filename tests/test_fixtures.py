# Copyright 2025 Google LLC
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

import pytest
import fixtures


@pytest.mark.parametrize(
    "md5, name",
    [
        ("5f66b82558ca92e54e77f216ef4c066c", "mimikatz"),
        ("e80758cf485db142fca1ee03a34ead05", "kernel32"),
        ("a8565440629ac87f6fef7d588fe3ff0f", "kernel32-64"),
        ("db648cd247281954344f1d810c6fd590", "al-khaser x86"),
        ("3cb21ae76ff3da4b7e02d77ff76e82be", "al-khaser x64"),
    ],
)
def test_get_sample_short_name_by_md5(md5, name):
    """Test that get_sample_short_name_by_md5 correctly returns sample names"""
    assert fixtures.get_sample_short_name_by_md5(md5) == name


def test_get_sample_short_name_by_md5_unknown():
    """Test that get_sample_short_name_by_md5 raises ValueError for an unknown MD5"""
    with pytest.raises(ValueError, match="unexpected sample MD5"):
        fixtures.get_sample_short_name_by_md5("0000000000000000000000000000000")


@pytest.mark.parametrize(
    "name",
    [
        "mimikatz",
        "kernel32",
        "kernel32-64",
        "pma12-04",
        "pma16-01",
        "pma01-01",
        "pma21-01",
    ],
)
def test_md5_name_lookup_roundtrip_simple_names(name):
    """Test that get_sample_md5_by_name and get_sample_short_name_by_md5 are inverses for simple names."""
    md5 = fixtures.get_sample_md5_by_name(name)
    assert fixtures.get_sample_short_name_by_md5(md5) == name


@pytest.mark.parametrize(
    "name",
    [
        "499c2a85f6e8142c3f48d4251c9c7cd6",
        "9324d1a8ae37a36ae560c37448c9705a",
        "64d9f7d96b99467f36e22fada623c3bb",
    ],
)
def test_md5_name_lookup_roundtrip_hash_names(name):
    """Test that get_sample_md5_by_name and get_sample_short_name_by_md5 are inverses for hash-based names."""
    assert fixtures.get_sample_short_name_by_md5(fixtures.get_sample_md5_by_name(name)) == name
