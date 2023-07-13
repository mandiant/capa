# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import capa.features.address
from capa.engine import Or, And, Not, Some, Range
from capa.features.insn import Number

ADDR1 = capa.features.address.AbsoluteVirtualAddress(0x401001)
ADDR2 = capa.features.address.AbsoluteVirtualAddress(0x401002)
ADDR3 = capa.features.address.AbsoluteVirtualAddress(0x401003)
ADDR4 = capa.features.address.AbsoluteVirtualAddress(0x401004)


def test_number():
    assert bool(Number(1).evaluate({Number(0): {ADDR1}})) is False
    assert bool(Number(1).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Number(1).evaluate({Number(2): {ADDR1, ADDR2}})) is False


def test_and():
    assert bool(And([Number(1)]).evaluate({Number(0): {ADDR1}})) is False
    assert bool(And([Number(1)]).evaluate({Number(1): {ADDR1}})) is True
    assert bool(And([Number(1), Number(2)]).evaluate({Number(0): {ADDR1}})) is False
    assert bool(And([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}})) is False
    assert bool(And([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}})) is False
    assert bool(And([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}})) is True


def test_or():
    assert bool(Or([Number(1)]).evaluate({Number(0): {ADDR1}})) is False
    assert bool(Or([Number(1)]).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Or([Number(1), Number(2)]).evaluate({Number(0): {ADDR1}})) is False
    assert bool(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}})) is True
    assert bool(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}})) is True


def test_not():
    assert bool(Not(Number(1)).evaluate({Number(0): {ADDR1}})) is True
    assert bool(Not(Number(1)).evaluate({Number(1): {ADDR1}})) is False


def test_some():
    assert bool(Some(0, [Number(1)]).evaluate({Number(0): {ADDR1}})) is True
    assert bool(Some(1, [Number(1)]).evaluate({Number(0): {ADDR1}})) is False

    assert bool(Some(2, [Number(1), Number(2), Number(3)]).evaluate({Number(0): {ADDR1}})) is False
    assert bool(Some(2, [Number(1), Number(2), Number(3)]).evaluate({Number(0): {ADDR1}, Number(1): {ADDR1}})) is False
    assert (
        bool(
            Some(2, [Number(1), Number(2), Number(3)]).evaluate(
                {Number(0): {ADDR1}, Number(1): {ADDR1}, Number(2): {ADDR1}}
            )
        )
        is True
    )
    assert (
        bool(
            Some(2, [Number(1), Number(2), Number(3)]).evaluate(
                {Number(0): {ADDR1}, Number(1): {ADDR1}, Number(2): {ADDR1}, Number(3): {ADDR1}}
            )
        )
        is True
    )
    assert (
        bool(
            Some(2, [Number(1), Number(2), Number(3)]).evaluate(
                {Number(0): {ADDR1}, Number(1): {ADDR1}, Number(2): {ADDR1}, Number(3): {ADDR1}, Number(4): {ADDR1}}
            )
        )
        is True
    )


def test_complex():
    assert True is bool(
        Or([And([Number(1), Number(2)]), Or([Number(3), Some(2, [Number(4), Number(5), Number(6)])])]).evaluate(
            {Number(5): {ADDR1}, Number(6): {ADDR1}, Number(7): {ADDR1}, Number(8): {ADDR1}}
        )
    )

    assert False is bool(
        Or([And([Number(1), Number(2)]), Or([Number(3), Some(2, [Number(4), Number(5)])])]).evaluate(
            {Number(5): {ADDR1}, Number(6): {ADDR1}, Number(7): {ADDR1}, Number(8): {ADDR1}}
        )
    )


def test_range():
    # unbounded range, but no matching feature
    # since the lower bound is zero, and there are zero matches, ok
    assert bool(Range(Number(1)).evaluate({Number(2): {}})) is True

    # unbounded range with matching feature should always match
    assert bool(Range(Number(1)).evaluate({Number(1): {}})) is True
    assert bool(Range(Number(1)).evaluate({Number(1): {ADDR1}})) is True

    # unbounded max
    assert bool(Range(Number(1), min=1).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Range(Number(1), min=2).evaluate({Number(1): {ADDR1}})) is False
    assert bool(Range(Number(1), min=2).evaluate({Number(1): {ADDR1, ADDR2}})) is True

    # unbounded min
    assert bool(Range(Number(1), max=0).evaluate({Number(1): {ADDR1}})) is False
    assert bool(Range(Number(1), max=1).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Range(Number(1), max=2).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Range(Number(1), max=2).evaluate({Number(1): {ADDR1, ADDR2}})) is True
    assert bool(Range(Number(1), max=2).evaluate({Number(1): {ADDR1, ADDR2, ADDR3}})) is False

    # we can do an exact match by setting min==max
    assert bool(Range(Number(1), min=1, max=1).evaluate({Number(1): {}})) is False
    assert bool(Range(Number(1), min=1, max=1).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Range(Number(1), min=1, max=1).evaluate({Number(1): {ADDR1, ADDR2}})) is False

    # bounded range
    assert bool(Range(Number(1), min=1, max=3).evaluate({Number(1): {}})) is False
    assert bool(Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1, ADDR2}})) is True
    assert bool(Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1, ADDR2, ADDR3}})) is True
    assert bool(Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1, ADDR2, ADDR3, ADDR4}})) is False


def test_short_circuit():
    assert bool(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}})) is True

    # with short circuiting, only the children up until the first satisfied child are captured.
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}, short_circuit=True).children) == 1
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}, short_circuit=False).children) == 2


def test_eval_order():
    # base cases.
    assert bool(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}})) is True

    # with short circuiting, only the children up until the first satisfied child are captured.
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}).children) == 1
    assert len(Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}).children) == 2
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR1}}).children) == 1

    # and its guaranteed that children are evaluated in order.
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}).children[0].statement == Number(1)
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}).children[0].statement != Number(2)

    assert Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}).children[1].statement == Number(2)
    assert Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}).children[1].statement != Number(1)
