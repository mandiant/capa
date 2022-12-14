# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import capa.features.address
from capa.engine import *
from capa.features import *
from capa.features.insn import *

ADDR1 = capa.features.address.AbsoluteVirtualAddress(0x401001)
ADDR2 = capa.features.address.AbsoluteVirtualAddress(0x401002)
ADDR3 = capa.features.address.AbsoluteVirtualAddress(0x401003)
ADDR4 = capa.features.address.AbsoluteVirtualAddress(0x401004)


def test_number():
    assert Number(1).evaluate({Number(0): {ADDR1}}) == False
    assert Number(1).evaluate({Number(1): {ADDR1}}) == True
    assert Number(1).evaluate({Number(2): {ADDR1, ADDR2}}) == False


def test_and():
    assert And([Number(1)]).evaluate({Number(0): {ADDR1}}) == False
    assert And([Number(1)]).evaluate({Number(1): {ADDR1}}) == True
    assert And([Number(1), Number(2)]).evaluate({Number(0): {ADDR1}}) == False
    assert And([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}) == False
    assert And([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}) == False
    assert And([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}}) == True


def test_or():
    assert Or([Number(1)]).evaluate({Number(0): {ADDR1}}) == False
    assert Or([Number(1)]).evaluate({Number(1): {ADDR1}}) == True
    assert Or([Number(1), Number(2)]).evaluate({Number(0): {ADDR1}}) == False
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}) == True
    assert Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}) == True
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}}) == True


def test_not():
    assert Not(Number(1)).evaluate({Number(0): {ADDR1}}) == True
    assert Not(Number(1)).evaluate({Number(1): {ADDR1}}) == False


def test_some():
    assert Some(0, [Number(1)]).evaluate({Number(0): {ADDR1}}) == True
    assert Some(1, [Number(1)]).evaluate({Number(0): {ADDR1}}) == False

    assert Some(2, [Number(1), Number(2), Number(3)]).evaluate({Number(0): {ADDR1}}) == False
    assert Some(2, [Number(1), Number(2), Number(3)]).evaluate({Number(0): {ADDR1}, Number(1): {ADDR1}}) == False
    assert (
        Some(2, [Number(1), Number(2), Number(3)]).evaluate(
            {Number(0): {ADDR1}, Number(1): {ADDR1}, Number(2): {ADDR1}}
        )
        == True
    )
    assert (
        Some(2, [Number(1), Number(2), Number(3)]).evaluate(
            {Number(0): {ADDR1}, Number(1): {ADDR1}, Number(2): {ADDR1}, Number(3): {ADDR1}}
        )
        == True
    )
    assert (
        Some(2, [Number(1), Number(2), Number(3)]).evaluate(
            {
                Number(0): {ADDR1},
                Number(1): {ADDR1},
                Number(2): {ADDR1},
                Number(3): {ADDR1},
                Number(4): {ADDR1},
            }
        )
        == True
    )


def test_complex():
    assert True == Or(
        [And([Number(1), Number(2)]), Or([Number(3), Some(2, [Number(4), Number(5), Number(6)])])]
    ).evaluate({Number(5): {ADDR1}, Number(6): {ADDR1}, Number(7): {ADDR1}, Number(8): {ADDR1}})

    assert False == Or([And([Number(1), Number(2)]), Or([Number(3), Some(2, [Number(4), Number(5)])])]).evaluate(
        {Number(5): {ADDR1}, Number(6): {ADDR1}, Number(7): {ADDR1}, Number(8): {ADDR1}}
    )


def test_range():
    # unbounded range, but no matching feature
    # since the lower bound is zero, and there are zero matches, ok
    assert Range(Number(1)).evaluate({Number(2): {}}) == True

    # unbounded range with matching feature should always match
    assert Range(Number(1)).evaluate({Number(1): {}}) == True
    assert Range(Number(1)).evaluate({Number(1): {ADDR1}}) == True

    # unbounded max
    assert Range(Number(1), min=1).evaluate({Number(1): {ADDR1}}) == True
    assert Range(Number(1), min=2).evaluate({Number(1): {ADDR1}}) == False
    assert Range(Number(1), min=2).evaluate({Number(1): {ADDR1, ADDR2}}) == True

    # unbounded min
    assert Range(Number(1), max=0).evaluate({Number(1): {ADDR1}}) == False
    assert Range(Number(1), max=1).evaluate({Number(1): {ADDR1}}) == True
    assert Range(Number(1), max=2).evaluate({Number(1): {ADDR1}}) == True
    assert Range(Number(1), max=2).evaluate({Number(1): {ADDR1, ADDR2}}) == True
    assert Range(Number(1), max=2).evaluate({Number(1): {ADDR1, ADDR2, ADDR3}}) == False

    # we can do an exact match by setting min==max
    assert Range(Number(1), min=1, max=1).evaluate({Number(1): {}}) == False
    assert Range(Number(1), min=1, max=1).evaluate({Number(1): {ADDR1}}) == True
    assert Range(Number(1), min=1, max=1).evaluate({Number(1): {ADDR1, ADDR2}}) == False

    # bounded range
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {}}) == False
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1}}) == True
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1, ADDR2}}) == True
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1, ADDR2, ADDR3}}) == True
    assert Range(Number(1), min=1, max=3).evaluate({Number(1): {ADDR1, ADDR2, ADDR3, ADDR4}}) == False


def test_short_circuit():
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}) == True

    # with short circuiting, only the children up until the first satisfied child are captured.
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}, short_circuit=True).children) == 1
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}, short_circuit=False).children) == 2


def test_eval_order():
    # base cases.
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}) == True
    assert Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}) == True

    # with short circuiting, only the children up until the first satisfied child are captured.
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}).children) == 1
    assert len(Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}).children) == 2
    assert len(Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR1}}).children) == 1

    # and its guaranteed that children are evaluated in order.
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}).children[0].statement == Number(1)
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}}).children[0].statement != Number(2)

    assert Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}).children[1].statement == Number(2)
    assert Or([Number(1), Number(2)]).evaluate({Number(2): {ADDR1}}).children[1].statement != Number(1)
