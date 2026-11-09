# Copyright 2026 Google LLC
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# https://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io

import pytest

import capa.render.vverbose
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.render.utils import Console


@pytest.mark.parametrize(
    "feature, expected",
    [
        (frzf.NumberFeature(number=1), "number(0x1)"),
        (frzf.NumberFeature(number=0), "number(0x0)"),
        (frzf.NumberFeature(number=-16), "number(-0x10)"),
        (frzf.NumberFeature(number=1.5), "number(1.5)"),
        (frzf.OffsetFeature(offset=16), "offset(0x10)"),
        (frzf.OffsetFeature(offset=0), "offset(0x0)"),
        (frzf.OperandNumberFeature(index=0, **{"operand number": 16}), "operand number(0x10)"),
        (frzf.OperandOffsetFeature(index=0, **{"operand offset": -16}), "operand offset(-0x10)"),
        (frzf.StringFeature(string="hello"), 'string("hello")'),
        (frzf.StringFeature(string=""), 'string("")'),
        (frzf.BasicBlockFeature(), "basic block"),
    ],
)
def test_vverbose_range_feature_values(feature, expected):
    output = io.StringIO()
    console = Console(file=output, color_system=None, width=200, highlight=False)
    statement = rd.RangeStatement(min=2, max=2, child=feature)
    match = rd.Match(
        success=True,
        node=rd.StatementNode(statement=statement),
        children=(),
        locations=(),
        captures={},
    )
    capa.render.vverbose.render_statement(console, rd.StaticLayout(functions=()), match, statement, 0)
    assert output.getvalue() == f"count({expected}): 2\n"
