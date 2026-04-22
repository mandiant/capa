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

from pathlib import Path

import dnfile
import pytest
from dncil.clr.token import Token

import fixtures
from capa.features.common import Format
from capa.features.extractors.dnfile.helpers import calculate_dotnet_token_value
from capa.features.extractors.dnfile.extractor import (
    DnFileFeatureExtractorCache,
    DnfileFeatureExtractor,
)
from capa.features.extractors.dnfile.insn import get_callee

CD = Path(__file__).resolve().parent


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS_DOTNET,
    indirect=["sample", "scope"],
)
def test_dnfile_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(
        fixtures.get_dnfile_extractor, sample, scope, feature, expected
    )


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS_DOTNET,
    indirect=["sample", "scope"],
)
def test_dnfile_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(
        fixtures.get_dnfile_extractor, sample, scope, feature, expected
    )


def test_no_duplicate_format_feature_in_dnfile_extractor():
    path = fixtures.DNFILE_TESTFILES / "hello-world" / "hello-world.exe"
    if not path.exists():
        pytest.skip("test data not available")

    extractor = DnfileFeatureExtractor(path)

    format_values = [
        f.value
        for f, _ in list(extractor.extract_file_features())
        + list(extractor.extract_global_features())
        if isinstance(f, Format)
    ]

    assert len(format_values) == len(set(format_values)), (
        f"duplicate Format features: {format_values}"
    )


def test_get_callee_invalid_methodspec_token_returns_none():
    path = (
        CD
        / "data"
        / "2dae11cc5f86f5399b560b8837c26274b7e09431deed669b0844fef44e917915.exe_"
    )
    if not path.exists():
        pytest.skip("test data not available")

    pe = dnfile.dnPE(str(path))
    cache = DnFileFeatureExtractorCache(pe)

    ms_table = pe.net.mdtables.tables.get(dnfile.mdtable.MethodSpec.number)
    assert ms_table is not None and len(ms_table.rows) > 0

    out_of_range_rid = len(ms_table.rows) + 999
    token_value = calculate_dotnet_token_value(
        dnfile.mdtable.MethodSpec.number, out_of_range_rid
    )
    token = Token(token_value)

    result = get_callee(pe, cache, token)
    assert result is None
