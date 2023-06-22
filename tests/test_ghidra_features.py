import sys
import logging
import os.path
import binascii
import traceback

import pytest

try:
    sys.path.append(os.path.dirname(__file__))
    import fixtures
    from fixtures import *
finally:
    sys.path.pop()


logger = logging.getLogger("test_ghidra_features")


# We need to skip the ghidra test if we cannot import ghidra modules, e.g., in GitHub CI.
ghidra_present: bool = False
try:
    import ghidra.program.flatapi as flatapi

    ghidraapi = flatapi.FlatProgramAPI(currentProgram)

    try:
        current_program_test = ghidraapi.getCurrentProgram()
    except RuntimeError as e:
        logger.warning("Ghidra runtime not detected")
    else:
        ghidra_present = True
except ImportError:
    pass


@pytest.mark.skipif(ghidra_present is False, reason="Skip ghidra tests if the ghidra Python API is not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_ghidra_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_ghidra_extractor, sample, scope, feature, expected)


@pytest.mark.skipif(ghidra_present is False, reason="Skip ghidra tests if the ghidra Python API is not installed")
@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS,
    indirect=["sample", "scope"],
)
def test_ghidra_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_ghidra_extractor, sample, scope, feature, expected)
