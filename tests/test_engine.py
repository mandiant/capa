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

import capa.features.address
from capa.engine import Or, And, Not, Some, Range, Sequence
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
    assert bool(Range(Number(1)).evaluate({Number(2): {}})) is True  # type: ignore

    # unbounded range with matching feature should always match
    assert bool(Range(Number(1)).evaluate({Number(1): {}})) is True  # type: ignore
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
    assert bool(Range(Number(1), min=1, max=1).evaluate({Number(1): {}})) is False  # type: ignore
    assert bool(Range(Number(1), min=1, max=1).evaluate({Number(1): {ADDR1}})) is True
    assert bool(Range(Number(1), min=1, max=1).evaluate({Number(1): {ADDR1, ADDR2}})) is False

    # bounded range
    assert bool(Range(Number(1), min=1, max=3).evaluate({Number(1): {}})) is False  # type: ignore
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


def test_sequence():
    # 1 before 2
    assert bool(Sequence([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}})) is True
    # 2 before 1 (fail)
    assert bool(Sequence([Number(1), Number(2)]).evaluate({Number(1): {ADDR2}, Number(2): {ADDR1}})) is False
    # 1 same as 2 (fail)
    assert bool(Sequence([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR1}})) is False

    # 1 before 2 before 3
    assert (
        bool(
            Sequence([Number(1), Number(2), Number(3)]).evaluate(
                {Number(1): {ADDR1}, Number(2): {ADDR2}, Number(3): {ADDR3}}
            )
        )
        is True
    )

    # 1 before 2 before 3 (fail, 3 is early)
    assert (
        bool(
            Sequence([Number(1), Number(2), Number(3)]).evaluate(
                {Number(1): {ADDR1}, Number(2): {ADDR4}, Number(3): {ADDR3}}
            )
        )
        is False
    )

    # 1 before 2 before 3 (fail, 2 is late)
    assert (
        bool(
            Sequence([Number(1), Number(2), Number(3)]).evaluate(
                {Number(1): {ADDR1}, Number(2): {ADDR4}, Number(3): {ADDR3}}
            )
        )
        is False
    )

    # multiple locations for matches
    # 1 at 1, 2 at 2 (match)
    # 1 also at 3
    assert bool(Sequence([Number(1), Number(2)]).evaluate({Number(1): {ADDR1, ADDR3}, Number(2): {ADDR2}})) is True

    # greedy matching?
    # 1 at 2, 2 at 3
    # 1 matches at 2, so min_loc becomes 2.
    # 2 matches at 3, > 2. Match.
    # But wait, 1 also matches at 4.
    # If we picked 4, 1 > 2 would fail? No.
    # The heuristic is: pick the *smallest* location for the current child (that satisfies previous constraint).

    # CASE:
    # 1 matches at 10.
    # 2 matches at 5 and 15.
    # if 2 picks 5, 5 > 10 is False.
    # if 2 picks 15, 15 > 10 is True. Match.

    assert (
        bool(
            Sequence([Number(1), Number(2)]).evaluate(
                {
                    Number(1): {capa.features.address.AbsoluteVirtualAddress(10)},
                    Number(2): {
                        capa.features.address.AbsoluteVirtualAddress(5),
                        capa.features.address.AbsoluteVirtualAddress(15),
                    },
                }
            )
        )
        is True
    )

    # CASE:
    # 1 matches at 10 and 20.
    # 2 matches at 15.
    # 1 should pick 10. 10 < 15. Match.
    assert (
        bool(
            Sequence([Number(1), Number(2)]).evaluate(
                {
                    Number(1): {
                        capa.features.address.AbsoluteVirtualAddress(10),
                        capa.features.address.AbsoluteVirtualAddress(20),
                    },
                    Number(2): {capa.features.address.AbsoluteVirtualAddress(15)},
                }
            )
        )
        is True
    )

    # CASE:
    # 1 matched at 10.
    # 2 matched at 15.
    # 3 matched at 12.
    # 1 -> 10.
    # 2 -> 15 (> 10).
    # 3 -> 12 (not > 15).
    # Fail.
    assert (
        bool(
            Sequence([Number(1), Number(2), Number(3)]).evaluate(
                {
                    Number(1): {capa.features.address.AbsoluteVirtualAddress(10)},
                    Number(2): {capa.features.address.AbsoluteVirtualAddress(15)},
                    Number(3): {capa.features.address.AbsoluteVirtualAddress(12)},
                }
            )
        )
        is False
    )


def test_location_propagation():
    # regression tests for issue where Or/And/Some statements
    # failed to propagate match locations to their results,
    # causing Sequence evaluation to fail.

    # Or
    assert Or([Number(1)]).evaluate({Number(1): {ADDR1}}).locations == {ADDR1}
    assert Or([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}}).locations == {
        ADDR1
    }  # short_circuit=True returns first match
    assert Or([Number(1), Number(2)]).evaluate(
        {Number(1): {ADDR1}, Number(2): {ADDR2}}, short_circuit=False
    ).locations == {ADDR1, ADDR2}

    # And
    assert And([Number(1)]).evaluate({Number(1): {ADDR1}}).locations == {ADDR1}
    assert And([Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}}).locations == {ADDR1, ADDR2}

    # Some
    assert Some(1, [Number(1)]).evaluate({Number(1): {ADDR1}}).locations == {ADDR1}
    assert Some(1, [Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}}).locations == {
        ADDR1
    }  # short_circuit=True returns first sufficient set
    assert Some(2, [Number(1), Number(2)]).evaluate({Number(1): {ADDR1}, Number(2): {ADDR2}}).locations == {
        ADDR1,
        ADDR2,
    }
