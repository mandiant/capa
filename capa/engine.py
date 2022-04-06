# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import copy
import collections
from typing import TYPE_CHECKING, Set, Dict, List, Tuple, Mapping, Iterable

import capa.perf
import capa.features.common
from capa.features.common import Result, Feature

if TYPE_CHECKING:
    # circular import, otherwise
    import capa.rules


# a collection of features and the locations at which they are found.
#
# used throughout matching as the context in which features are searched:
# to check if a feature exists, do: `Number(0x10) in features`.
# to collect the locations of a feature, do: `features[Number(0x10)]`
#
# aliased here so that the type can be documented and xref'd.
FeatureSet = Dict[Feature, Set[int]]


class Statement:
    """
    superclass for structural nodes, such as and/or/not.
    this exists to provide a default impl for `__str__` and `__repr__`,
     and to declare the interface method `evaluate`
    """

    def __init__(self, description=None):
        super(Statement, self).__init__()
        self.name = self.__class__.__name__
        self.description = description

    def __str__(self):
        if self.description:
            return "%s(%s = %s)" % (self.name.lower(), ",".join(map(str, self.get_children())), self.description)
        else:
            return "%s(%s)" % (self.name.lower(), ",".join(map(str, self.get_children())))

    def __repr__(self):
        return str(self)

    def evaluate(self, features: FeatureSet, short_circuit=True) -> Result:
        """
        classes that inherit `Statement` must implement `evaluate`

        args:
            short_circuit (bool): if true, then statements like and/or/some may short circuit.
        """
        raise NotImplementedError()

    def get_children(self):
        if hasattr(self, "child"):
            yield self.child

        if hasattr(self, "children"):
            for child in getattr(self, "children"):
                yield child

    def replace_child(self, existing, new):
        if hasattr(self, "child"):
            if self.child is existing:
                self.child = new

        if hasattr(self, "children"):
            children = getattr(self, "children")
            for i, child in enumerate(children):
                if child is existing:
                    children[i] = new


class And(Statement):
    """
    match if all of the children evaluate to True.

    the order of evaluation is dictated by the property
    `And.children` (type: List[Statement|Feature]).
    a query optimizer may safely manipulate the order of these children.
    """

    def __init__(self, children, description=None):
        super(And, self).__init__(description=description)
        self.children = children

    def evaluate(self, ctx, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.and"] += 1

        if short_circuit:
            results = []
            for child in self.children:
                result = child.evaluate(ctx, short_circuit=short_circuit)
                results.append(result)
                if not result:
                    # short circuit
                    return Result(False, self, results)

            return Result(True, self, results)
        else:
            results = [child.evaluate(ctx, short_circuit=short_circuit) for child in self.children]
            success = all(results)
            return Result(success, self, results)


class Or(Statement):
    """
    match if any of the children evaluate to True.

    the order of evaluation is dictated by the property
    `Or.children` (type: List[Statement|Feature]).
    a query optimizer may safely manipulate the order of these children.
    """

    def __init__(self, children, description=None):
        super(Or, self).__init__(description=description)
        self.children = children

    def evaluate(self, ctx, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.or"] += 1

        if short_circuit:
            results = []
            for child in self.children:
                result = child.evaluate(ctx, short_circuit=short_circuit)
                results.append(result)
                if result:
                    # short circuit as soon as we hit one match
                    return Result(True, self, results)

            return Result(False, self, results)
        else:
            results = [child.evaluate(ctx, short_circuit=short_circuit) for child in self.children]
            success = any(results)
            return Result(success, self, results)


class Not(Statement):
    """match only if the child evaluates to False."""

    def __init__(self, child, description=None):
        super(Not, self).__init__(description=description)
        self.child = child

    def evaluate(self, ctx, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.not"] += 1

        results = [self.child.evaluate(ctx, short_circuit=short_circuit)]
        success = not results[0]
        return Result(success, self, results)


class Some(Statement):
    """
    match if at least N of the children evaluate to True.

    the order of evaluation is dictated by the property
    `Some.children` (type: List[Statement|Feature]).
    a query optimizer may safely manipulate the order of these children.
    """

    def __init__(self, count, children, description=None):
        super(Some, self).__init__(description=description)
        self.count = count
        self.children = children

    def evaluate(self, ctx, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.some"] += 1

        if short_circuit:
            results = []
            satisfied_children_count = 0
            for child in self.children:
                result = child.evaluate(ctx, short_circuit=short_circuit)
                results.append(result)
                if result:
                    satisfied_children_count += 1

                if satisfied_children_count >= self.count:
                    # short circuit as soon as we hit the threshold
                    return Result(True, self, results)

            return Result(False, self, results)
        else:
            results = [child.evaluate(ctx, short_circuit=short_circuit) for child in self.children]
            # note that here we cast the child result as a bool
            # because we've overridden `__bool__` above.
            #
            # we can't use `if child is True` because the instance is not True.
            success = sum([1 for child in results if bool(child) is True]) >= self.count
            return Result(success, self, results)


class Range(Statement):
    """match if the child is contained in the ctx set with a count in the given range."""

    def __init__(self, child, min=None, max=None, description=None):
        super(Range, self).__init__(description=description)
        self.child = child
        self.min = min if min is not None else 0
        self.max = max if max is not None else (1 << 64 - 1)

    def evaluate(self, ctx, **kwargs):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.range"] += 1

        count = len(ctx.get(self.child, []))
        if self.min == 0 and count == 0:
            return Result(True, self, [])

        return Result(self.min <= count <= self.max, self, [], locations=ctx.get(self.child))

    def __str__(self):
        if self.max == (1 << 64 - 1):
            return "range(%s, min=%d, max=infinity)" % (str(self.child), self.min)
        else:
            return "range(%s, min=%d, max=%d)" % (str(self.child), self.min, self.max)


class Subscope(Statement):
    """
    a subscope element is a placeholder in a rule - it should not be evaluated directly.
    the engine should preprocess rules to extract subscope statements into their own rules.
    """

    def __init__(self, scope, child, description=None):
        super(Subscope, self).__init__(description=description)
        self.scope = scope
        self.child = child

    def evaluate(self, ctx, **kwargs):
        raise ValueError("cannot evaluate a subscope directly!")


# mapping from rule name to list of: (location of match, result object)
#
# used throughout matching and rendering to collection the results
#  of statement evaluation and their locations.
#
# to check if a rule matched, do: `"TCP client" in matches`.
# to find where a rule matched, do: `map(first, matches["TCP client"])`
# to see how a rule matched, do:
#
#     for address, match_details in matches["TCP client"]:
#         inspect(match_details)
#
# aliased here so that the type can be documented and xref'd.
MatchResults = Mapping[str, List[Tuple[int, Result]]]


def index_rule_matches(features: FeatureSet, rule: "capa.rules.Rule", locations: Iterable[int]):
    """
    record into the given featureset that the given rule matched at the given locations.

    naively, this is just adding a MatchedRule feature;
    however, we also want to record matches for the rule's namespaces.

    updates `features` in-place. doesn't modify the remaining arguments.
    """
    features[capa.features.common.MatchedRule(rule.name)].update(locations)
    namespace = rule.meta.get("namespace")
    if namespace:
        while namespace:
            features[capa.features.common.MatchedRule(namespace)].update(locations)
            namespace, _, _ = namespace.rpartition("/")


def match(rules: List["capa.rules.Rule"], features: FeatureSet, va: int) -> Tuple[FeatureSet, MatchResults]:
    """
    match the given rules against the given features,
    returning an updated set of features and the matches.

    the updated features are just like the input,
    but extended to include the match features (e.g. names of rules that matched).
    the given feature set is not modified; an updated copy is returned.

    the given list of rules must be ordered topologically by dependency,
    or else `match` statements will not be handled correctly.

    this routine should be fairly optimized, but is not guaranteed to be the fastest matcher possible.
    it has a particularly convenient signature: (rules, features) -> matches
    other strategies can be imagined that match differently; implement these elsewhere.
    specifically, this routine does "top down" matching of the given rules against the feature set.
    """
    results = collections.defaultdict(list)  # type: MatchResults

    # copy features so that we can modify it
    # without affecting the caller (keep this function pure)
    #
    # note: copy doesn't notice this is a defaultdict, so we'll recreate that manually.
    features = collections.defaultdict(set, copy.copy(features))

    for rule in rules:
        res = rule.evaluate(features, short_circuit=True)
        if res:
            # we first matched the rule with short circuiting enabled.
            # this is much faster than without short circuiting.
            # however, we want to collect all results thoroughly,
            # so once we've found a match quickly,
            # go back and capture results without short circuiting.
            res = rule.evaluate(features, short_circuit=False)

            # sanity check
            assert bool(res) is True

            results[rule.name].append((va, res))
            # we need to update the current `features`
            # because subsequent iterations of this loop may use newly added features,
            # such as rule or namespace matches.
            index_rule_matches(features, rule, [va])

    return (features, results)
