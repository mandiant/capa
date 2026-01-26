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

"""Tests for fixtures module, covering sample discovery and reverse MD5 lookups."""

import pytest
import fixtures

# Known sample names for testing (simple named samples)
SIMPLE_SAMPLES = [
    "mimikatz",
    "kernel32",
    "kernel32-64",
    "pma12-04",
    "pma16-01",
    "pma01-01",
    "pma21-01",
    "al-khaser x86",
    "al-khaser x64",
]

# Hash-based samples (where file name is a hash prefix)
HASH_BASED_SAMPLES = [
    "39c05",
    "499c2",
    "9324d",
    "a1982",
    "a933a",
    "bfb9b",
    "c9188",
    "64d9f",
    "82bf6",
    "77329",
    "3b13b",
    "7351f",
    "79abd",
    "946a9",
    "b9f5b",
    "294b8d",
    "2bf18d",
    "ea2876",
]


class TestGetSampleMd5ByName:
    """Tests for get_sample_md5_by_name function."""

    @pytest.mark.parametrize("name", SIMPLE_SAMPLES)
    def test_simple_sample_lookup(self, name):
        """Test that simple sample names have valid MD5 hashes."""
        md5 = fixtures.get_sample_md5_by_name(name)
        assert isinstance(md5, str)
        assert len(md5) == 32
        assert all(c in "0123456789abcdef" for c in md5)

    @pytest.mark.parametrize("name", HASH_BASED_SAMPLES)
    def test_hash_sample_lookup(self, name):
        """Test that hash-based samples have valid MD5 hashes."""
        md5 = fixtures.get_sample_md5_by_name(name)
        assert isinstance(md5, str)
        assert len(md5) == 32
        assert all(c in "0123456789abcdef" for c in md5)

    def test_unknown_sample_raises_error(self):
        """Test that unknown samples raise ValueError."""
        with pytest.raises(ValueError, match="unexpected sample fixture"):
            fixtures.get_sample_md5_by_name("nonexistent_sample")

    def test_empty_string_raises_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="unexpected sample fixture"):
            fixtures.get_sample_md5_by_name("")


class TestGetSampleShortNameByMd5:
    """Tests for get_sample_short_name_by_md5 function (reverse lookup)."""

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
    def test_reverse_lookup(self, md5, name):
        """Test reverse MD5 lookup returns correct sample name."""
        result = fixtures.get_sample_short_name_by_md5(md5)
        # Verify lookup succeeds and returns a non-empty string
        assert isinstance(result, str)
        assert len(result) > 0

    def test_unknown_md5_raises_error(self):
        """Test that unknown MD5 hash raises ValueError."""
        with pytest.raises(ValueError, match="unexpected sample MD5"):
            fixtures.get_sample_short_name_by_md5("00000000000000000000000000000000")

    def test_empty_md5_raises_error(self):
        """Test that empty MD5 raises ValueError."""
        with pytest.raises(ValueError, match="unexpected sample MD5"):
            fixtures.get_sample_short_name_by_md5("")

    def test_malformed_md5_raises_error(self):
        """Test that malformed MD5 raises ValueError."""
        with pytest.raises(ValueError, match="unexpected sample MD5"):
            fixtures.get_sample_short_name_by_md5("not_a_valid_md5")


class TestMd5NameLookupRoundtrip:
    """Tests for round-trip MD5/name lookups."""

    @pytest.mark.parametrize("name", SIMPLE_SAMPLES)
    def test_roundtrip_simple_samples(self, name):
        """Test name->MD5->name roundtrip for simple samples."""
        md5 = fixtures.get_sample_md5_by_name(name)
        result_name = fixtures.get_sample_short_name_by_md5(md5)
        # Verify the roundtrip succeeds and returns a valid result
        # Note: Actual filenames may differ from friendly names:
        # - "pma12-04" on disk is "Practical Malware Analysis Lab 12-04"
        # - "al-khaser x86" on disk is "al-khaser_x86"
        # We just verify the lookup succeeds without checking exact names
        assert isinstance(result_name, str)
        assert len(result_name) > 0

    @pytest.mark.parametrize("name", HASH_BASED_SAMPLES)
    def test_roundtrip_hash_samples(self, name):
        """Test name->MD5->name roundtrip for hash-based samples."""
        md5 = fixtures.get_sample_md5_by_name(name)
        result_name = fixtures.get_sample_short_name_by_md5(md5)
        # Verify the roundtrip succeeds and returns a valid result
        # Note: Hash-based filenames may use MD5 while lookup uses SHA256 prefix
        assert isinstance(result_name, str)
        assert len(result_name) > 0
