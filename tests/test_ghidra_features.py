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

"""
Must invoke this script from within the Ghidra Runtime Environment
"""
import sys
import logging
from pathlib import Path

import pytest

try:
    sys.path.append(str(Path(__file__).parent))
    import fixtures
finally:
    sys.path.pop()


logger = logging.getLogger("test_ghidra_features")

ghidra_present: bool = False
try:
    import ghidra  # noqa: F401

    ghidra_present = True
except ImportError:
    pass


def standardize_posix_str(psx_str):
    """fixture test passes the PosixPath to the test data

    params: psx_str - PosixPath() to the test data
    return: string that matches test-id sample name
    """

    if "Practical Malware Analysis Lab" in str(psx_str):
        # <PosixPath>/'Practical Malware Analysis Lab 16-01.exe_' -> 'pma16-01'
        wanted_str = "pma" + str(psx_str).split("/")[-1][len("Practical Malware Analysis Lab ") : -5]
    else:
        # <PosixPath>/mimikatz.exe_ -> mimikatz
        wanted_str = str(psx_str).split("/")[-1][:-5]

    if "_" in wanted_str:
        # al-khaser_x86 -> al-khaser x86
        wanted_str = wanted_str.replace("_", " ")

    return wanted_str


def check_input_file(wanted):
    """check that test is running on the loaded sample

    params: wanted - PosixPath() passed from test arg
    """

    import capa.ghidra.helpers as ghidra_helpers

    found = ghidra_helpers.get_file_md5()
    sample_name = standardize_posix_str(wanted)

    if not found.startswith(fixtures.get_sample_md5_by_name(sample_name)):
        raise RuntimeError(f"please run the tests against sample with MD5: `{found}`")


@pytest.mark.skipif(ghidra_present is False, reason="Ghidra tests must be ran within Ghidra")
@fixtures.parametrize("sample,scope,feature,expected", fixtures.FEATURE_PRESENCE_TESTS, indirect=["sample", "scope"])
def test_ghidra_features(sample, scope, feature, expected):
    try:
        check_input_file(sample)
    except RuntimeError:
        pytest.skip(reason="Test must be ran against sample loaded in Ghidra")

    fixtures.do_test_feature_presence(fixtures.get_ghidra_extractor, sample, scope, feature, expected)


@pytest.mark.skipif(ghidra_present is False, reason="Ghidra tests must be ran within Ghidra")
@fixtures.parametrize(
    "sample,scope,feature,expected", fixtures.FEATURE_COUNT_TESTS_GHIDRA, indirect=["sample", "scope"]
)
def test_ghidra_feature_counts(sample, scope, feature, expected):
    try:
        check_input_file(sample)
    except RuntimeError:
        pytest.skip(reason="Test must be ran against sample loaded in Ghidra")

    fixtures.do_test_feature_count(fixtures.get_ghidra_extractor, sample, scope, feature, expected)


if __name__ == "__main__":
    # No support for faulthandler module in Ghidrathon, see:
    # https://github.com/mandiant/Ghidrathon/issues/70
    sys.exit(pytest.main(["--pyargs", "-p no:faulthandler", "test_ghidra_features"]))
