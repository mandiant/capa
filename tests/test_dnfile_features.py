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
import fixtures
from dncil.clr.token import Token

from capa.features.common import Format
from capa.features.extractors.dnfile.insn import get_callee
from capa.features.extractors.dnfile.helpers import get_dotnet_table_row, calculate_dotnet_token_value
from capa.features.extractors.dnfile.extractor import (
    DnfileFeatureExtractor,
    DnFileFeatureExtractorCache,
)

CD = Path(__file__).resolve().parent

DOTNET_DIR = Path(__file__).resolve().parent / "data" / "dotnet"


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS_DOTNET,
    indirect=["sample", "scope"],
)
def test_dnfile_features(sample, scope, feature, expected):
    fixtures.do_test_feature_presence(fixtures.get_dnfile_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS_DOTNET,
    indirect=["sample", "scope"],
)
def test_dnfile_feature_counts(sample, scope, feature, expected):
    fixtures.do_test_feature_count(fixtures.get_dnfile_extractor, sample, scope, feature, expected)


def test_get_dotnet_table_row_first_row():
    """row_index=1 is the first valid .NET metadata row; it must not be rejected."""
    pe = dnfile.dnPE(DOTNET_DIR / "dd9098ff91717f4906afe9dafdfa2f52.exe_")
    row = get_dotnet_table_row(pe, dnfile.mdtable.TypeDef.number, 1)
    assert row is not None
    assert str(row.TypeName) == "<Module>"


def test_get_dotnet_table_row_invalid_zero():
    """row_index=0 is the null token; the function must return None."""
    pe = dnfile.dnPE(DOTNET_DIR / "dd9098ff91717f4906afe9dafdfa2f52.exe_")
    assert get_dotnet_table_row(pe, dnfile.mdtable.TypeDef.number, 0) is None


def test_get_dotnet_table_row_valid_rows():
    """All valid row indices 1..N return a row from the real PE."""
    pe = dnfile.dnPE(DOTNET_DIR / "dd9098ff91717f4906afe9dafdfa2f52.exe_")
    assert pe.net is not None
    assert pe.net.mdtables is not None
    table = pe.net.mdtables.tables.get(dnfile.mdtable.TypeDef.number)
    assert table is not None
    for row_index in range(1, len(table.rows) + 1):
        assert get_dotnet_table_row(pe, dnfile.mdtable.TypeDef.number, row_index) is not None


def test_get_dotnet_table_row_out_of_bounds():
    """row_index beyond the table size returns None."""
    pe = dnfile.dnPE(DOTNET_DIR / "dd9098ff91717f4906afe9dafdfa2f52.exe_")
    assert pe.net is not None
    assert pe.net.mdtables is not None
    table = pe.net.mdtables.tables.get(dnfile.mdtable.TypeDef.number)
    assert table is not None
    assert get_dotnet_table_row(pe, dnfile.mdtable.TypeDef.number, len(table.rows) + 1) is None


def test_no_duplicate_format_feature_in_dnfile_extractor():
    path = fixtures.DNFILE_TESTFILES / "hello-world" / "hello-world.exe"
    if not path.exists():
        pytest.skip("test data not available")

    extractor = DnfileFeatureExtractor(path)

    format_values = [
        f.value
        for f, _ in list(extractor.extract_file_features()) + list(extractor.extract_global_features())
        if isinstance(f, Format)
    ]

    assert len(format_values) == len(set(format_values)), f"duplicate Format features: {format_values}"


def test_get_callee_invalid_methodspec_token_returns_none():
    path = CD / "data" / "2dae11cc5f86f5399b560b8837c26274b7e09431deed669b0844fef44e917915.exe_"
    pe = dnfile.dnPE(str(path))
    cache = DnFileFeatureExtractorCache(pe)

    assert pe.net is not None
    assert pe.net.mdtables is not None
    ms_table = pe.net.mdtables.tables.get(dnfile.mdtable.MethodSpec.number)
    assert ms_table is not None and len(ms_table.rows) > 0

    out_of_range_rid = len(ms_table.rows) + 999
    token_value = calculate_dotnet_token_value(dnfile.mdtable.MethodSpec.number, out_of_range_rid)
    token = Token(token_value)

    result = get_callee(pe, cache, token)
    assert result is None
