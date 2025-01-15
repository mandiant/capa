# Copyright 2024 Google LLC
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

from typing import Optional
from dataclasses import dataclass

from capa.features.extractors.binexport2.helpers import get_operand_expressions
from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

# security cookie checks may perform non-zeroing XORs, these are expected within a certain
# byte range within the first and returning basic blocks, this helps to reduce FP features
SECURITY_COOKIE_BYTES_DELTA: int = 0x40


@dataclass
class OperandPhraseInfo:
    scale: Optional[BinExport2.Expression] = None
    index: Optional[BinExport2.Expression] = None
    base: Optional[BinExport2.Expression] = None
    displacement: Optional[BinExport2.Expression] = None


def get_operand_phrase_info(be2: BinExport2, operand: BinExport2.Operand) -> Optional[OperandPhraseInfo]:
    # assume the following (see https://blog.yossarian.net/2020/06/13/How-x86_64-addresses-memory):
    #
    # Scale: A 2-bit constant factor
    # Index: Any general purpose register
    # Base: Any general purpose register
    # Displacement: An integral offset

    expressions: list[BinExport2.Expression] = get_operand_expressions(be2, operand)

    # skip expression up to and including BinExport2.Expression.DEREFERENCE, assume caller
    # has checked for BinExport2.Expression.DEREFERENCE
    for i, expression in enumerate(expressions):
        if expression.type == BinExport2.Expression.DEREFERENCE:
            expressions = expressions[i + 1 :]
            break

    expression0: BinExport2.Expression
    expression1: BinExport2.Expression
    expression2: BinExport2.Expression
    expression3: BinExport2.Expression
    expression4: BinExport2.Expression

    if len(expressions) == 1:
        expression0 = expressions[0]

        assert (
            expression0.type == BinExport2.Expression.IMMEDIATE_INT
            or expression0.type == BinExport2.Expression.REGISTER
        )

        if expression0.type == BinExport2.Expression.IMMEDIATE_INT:
            # Displacement
            return OperandPhraseInfo(displacement=expression0)
        elif expression0.type == BinExport2.Expression.REGISTER:
            # Base
            return OperandPhraseInfo(base=expression0)

    elif len(expressions) == 3:
        expression0 = expressions[0]
        expression1 = expressions[1]
        expression2 = expressions[2]

        assert expression0.type == BinExport2.Expression.REGISTER
        assert expression1.type == BinExport2.Expression.OPERATOR
        assert (
            expression2.type == BinExport2.Expression.IMMEDIATE_INT
            or expression2.type == BinExport2.Expression.REGISTER
        )

        if expression2.type == BinExport2.Expression.REGISTER:
            # Base + Index
            return OperandPhraseInfo(base=expression0, index=expression2)
        elif expression2.type == BinExport2.Expression.IMMEDIATE_INT:
            # Base + Displacement
            return OperandPhraseInfo(base=expression0, displacement=expression2)

    elif len(expressions) == 5:
        expression0 = expressions[0]
        expression1 = expressions[1]
        expression2 = expressions[2]
        expression3 = expressions[3]
        expression4 = expressions[4]

        assert expression0.type == BinExport2.Expression.REGISTER
        assert expression1.type == BinExport2.Expression.OPERATOR
        assert (
            expression2.type == BinExport2.Expression.REGISTER
            or expression2.type == BinExport2.Expression.IMMEDIATE_INT
        )
        assert expression3.type == BinExport2.Expression.OPERATOR
        assert expression4.type == BinExport2.Expression.IMMEDIATE_INT

        if expression1.symbol == "+" and expression3.symbol == "+":
            # Base + Index + Displacement
            return OperandPhraseInfo(base=expression0, index=expression2, displacement=expression4)
        elif expression1.symbol == "+" and expression3.symbol == "*":
            # Base + (Index * Scale)
            return OperandPhraseInfo(base=expression0, index=expression2, scale=expression3)
        elif expression1.symbol == "*" and expression3.symbol == "+":
            # (Index * Scale) + Displacement
            return OperandPhraseInfo(index=expression0, scale=expression2, displacement=expression3)
        else:
            raise NotImplementedError(expression1.symbol, expression3.symbol)

    elif len(expressions) == 7:
        expression0 = expressions[0]
        expression1 = expressions[1]
        expression2 = expressions[2]
        expression3 = expressions[3]
        expression4 = expressions[4]
        expression5 = expressions[5]
        expression6 = expressions[6]

        assert expression0.type == BinExport2.Expression.REGISTER
        assert expression1.type == BinExport2.Expression.OPERATOR
        assert expression2.type == BinExport2.Expression.REGISTER
        assert expression3.type == BinExport2.Expression.OPERATOR
        assert expression4.type == BinExport2.Expression.IMMEDIATE_INT
        assert expression5.type == BinExport2.Expression.OPERATOR
        assert expression6.type == BinExport2.Expression.IMMEDIATE_INT

        # Base + (Index * Scale) + Displacement
        return OperandPhraseInfo(base=expression0, index=expression2, scale=expression4, displacement=expression6)

    else:
        raise NotImplementedError(len(expressions))

    return None
