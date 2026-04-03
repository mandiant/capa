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


import copy
import collections
from typing import TYPE_CHECKING, Union, Mapping, Iterable, Iterator

import capa.perf
import capa.features.common
from capa.features.common import Result, Feature
from capa.features.address import Address

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
FeatureSet = dict[Feature, set[Address]]


class Statement:
    """
    superclass for structural nodes, such as and/or/not.
    this exists to provide a default impl for `__str__` and `__repr__`,
     and to declare the interface method `evaluate`
    """

    def __init__(self, description=None):
        super().__init__()
        self.name = self.__class__.__name__
        self.description = description

    def __str__(self):
        name = self.name.lower()
        children = ",".join(map(str, self.get_children()))
        if self.description:
            return f"{name}({children} = {self.description})"
        else:
            return f"{name}({children})"

    def __repr__(self):
        return str(self)

    def evaluate(self, features: FeatureSet, short_circuit=True) -> Result:
        """
        classes that inherit `Statement` must implement `evaluate`

        args:
            short_circuit (bool): if true, then statements like and/or/some may short circuit.
        """
        raise NotImplementedError()

    def get_children(self) -> Iterator[Union["Statement", Feature]]:
        if hasattr(self, "child"):
            # this really confuses mypy because the property may not exist
            # since its defined in the subclasses.
            child = self.child  # type: ignore
            assert isinstance(child, (Statement, Feature))
            yield child

        if hasattr(self, "children"):
            for child in self.children:
                assert isinstance(child, (Statement, Feature))
                yield child

    def replace_child(self, existing, new):
        if hasattr(self, "child"):
            # this really confuses mypy because the property may not exist
            # since its defined in the subclasses.
            if self.child is existing:  # type: ignore
                self.child = new

        if hasattr(self, "children"):
            children = self.children
            for i, child in enumerate(children):
                if child is existing:
                    children[i] = new


class And(Statement):
    """
    match if all of the children evaluate to True.

    the order of evaluation is dictated by the property
    `And.children` (type: list[Statement|Feature]).
    a query optimizer may safely manipulate the order of these children.
    """

    def __init__(self, children, description=None):
        super().__init__(description=description)
        self.children = children

    def evaluate(self, features: FeatureSet, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.and"] += 1

        if short_circuit:
            results = []
            for child in self.children:
                result = child.evaluate(features, short_circuit=short_circuit)
                results.append(result)
                if not result:
                    # short circuit
                    return Result(False, self, results)

            return Result(True, self, results)
        else:
            results = [child.evaluate(features, short_circuit=short_circuit) for child in self.children]
            success = all(results)
            return Result(success, self, results)


class Or(Statement):
    """
    match if any of the children evaluate to True.

    the order of evaluation is dictated by the property
    `Or.children` (type: list[Statement|Feature]).
    a query optimizer may safely manipulate the order of these children.
    """

    def __init__(self, children, description=None):
        super().__init__(description=description)
        self.children = children

    def evaluate(self, features: FeatureSet, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.or"] += 1

        if short_circuit:
            results = []
            for child in self.children:
                result = child.evaluate(features, short_circuit=short_circuit)
                results.append(result)
                if result:
                    # short circuit as soon as we hit one match
                    return Result(True, self, results)

            return Result(False, self, results)
        else:
            results = [child.evaluate(features, short_circuit=short_circuit) for child in self.children]
            success = any(results)
            return Result(success, self, results)


class Not(Statement):
    """match only if the child evaluates to False."""

    def __init__(self, child, description=None):
        super().__init__(description=description)
        self.child = child

    def evaluate(self, features: FeatureSet, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.not"] += 1

        results = [self.child.evaluate(features, short_circuit=short_circuit)]
        success = not results[0]
        return Result(success, self, results)


class Some(Statement):
    """
    match if at least N of the children evaluate to True.

    the order of evaluation is dictated by the property
    `Some.children` (type: list[Statement|Feature]).
    a query optimizer may safely manipulate the order of these children.
    """

    def __init__(self, count, children, description=None):
        super().__init__(description=description)
        self.count = count
        self.children = children

    def evaluate(self, features: FeatureSet, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.some"] += 1

        if short_circuit:
            results = []
            satisfied_children_count = 0
            for child in self.children:
                result = child.evaluate(features, short_circuit=short_circuit)
                results.append(result)
                if result:
                    satisfied_children_count += 1

                if satisfied_children_count >= self.count:
                    # short circuit as soon as we hit the threshold
                    return Result(True, self, results)

            return Result(False, self, results)
        else:
            results = [child.evaluate(features, short_circuit=short_circuit) for child in self.children]
            # note that here we cast the child result as a bool
            # because we've overridden `__bool__` above.
            #
            # we can't use `if child is True` because the instance is not True.
            success = sum([1 for child in results if bool(child) is True]) >= self.count
            return Result(success, self, results)


class Range(Statement):
    """match if the child is contained in the feature set with a count in the given range."""

    def __init__(self, child, min=None, max=None, description=None):
        super().__init__(description=description)
        self.child = child
        self.min = min if min is not None else 0
        self.max = max if max is not None else ((1 << 64) - 1)

    def evaluate(self, features: FeatureSet, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.range"] += 1

        count = len(features.get(self.child, []))
        if self.min == 0 and count == 0:
            return Result(True, self, [])

        return Result(self.min <= count <= self.max, self, [], locations=features.get(self.child))

    def __str__(self):
        if self.max == ((1 << 64) - 1):
            return f"range({str(self.child)}, min={self.min}, max=infinity)"
        else:
            return f"range({str(self.child)}, min={self.min}, max={self.max})"


class Subscope(Statement):
    """
    a subscope element is a placeholder in a rule - it should not be evaluated directly.
    the engine should preprocess rules to extract subscope statements into their own rules.
    """

    def __init__(self, scope, child, description=None):
        super().__init__(description=description)
        self.scope = scope
        self.child = child

    def evaluate(self, features: FeatureSet, short_circuit=True):
        raise ValueError("cannot evaluate a subscope directly!")


class _RuleFeatureIndex:
    """
    index rules by their constituent features for efficient candidate selection.
    """

    def __init__(self, rules: Iterable["capa.rules.Rule"]):
        self.features: dict[Feature, list["capa.rules.Rule"]] = collections.defaultdict(list)
        # map from prefix byte (or -1 for empty) to rules containing that byte feature
        self.bytes_prefix_index: dict[int, list["capa.rules.Rule"]] = collections.defaultdict(list)

        for rule in rules:
            for feature in rule.extract_all_features():
                self._index_rule_by_feature(rule, feature)

    def _index_rule_by_feature(self, rule: "capa.rules.Rule", feature: Feature):
        if isinstance(feature, capa.features.common.Bytes):
            # build the prefix index directly, removing one full pass
            prefix = feature.value[0] if len(feature.value) > 0 else -1
            self.bytes_prefix_index[prefix].append(rule)
        else:
            self.features[feature].append(rule)

    def get_candidates(self, features: FeatureSet) -> set["capa.rules.Rule"]:
        candidates = set()

        for feature in features:
            if feature in self.features:
                candidates.update(self.features[feature])

            if isinstance(feature, capa.features.common.Bytes):
                # Bytes.value type is now narrowed via class-level annotation in common.py
                prefix = feature.value[0] if len(feature.value) > 0 else -1
                if prefix in self.bytes_prefix_index:
                    candidates.update(self.bytes_prefix_index[prefix])

        # guard to avoid temporary object creation for the short-pattern fallback
        if -1 in self.bytes_prefix_index:
            candidates.update(self.bytes_prefix_index[-1])

        return candidates


MatchResults = Mapping[str, list[tuple[Address, Result]]]


def get_rule_namespaces(rule: "capa.rules.Rule") -> Iterator[str]:
    namespace = rule.meta.get("namespace")
    if namespace:
        while namespace:
            yield namespace
            namespace, _, _ = namespace.rpartition("/")


def index_rule_matches(features: FeatureSet, rule: "capa.rules.Rule", locations: Iterable[Address]):
    """
    record into the given featureset that the given rule matched at the given locations.

    updates `features` in-place.
    """
    features[capa.features.common.MatchedRule(rule.name)].update(locations)
    for namespace in get_rule_namespaces(rule):
        features[capa.features.common.MatchedRule(namespace)].update(locations)


def match(rules: list["capa.rules.Rule"], features: FeatureSet, addr: Address) -> tuple[FeatureSet, MatchResults]:
    """
    match the given rules against the given features.
    """
    results: MatchResults = collections.defaultdict(list)
    features = collections.defaultdict(set, copy.copy(features))

    # create an index for efficient candidate rule selection
    index = _RuleFeatureIndex(rules)
    candidates = index.get_candidates(features)

    # only evaluate rules that could potentially match based on the feature set
    for rule in rules:
        if rule not in candidates:
            continue

        res = rule.evaluate(features, short_circuit=True)
        if res:
            res = rule.evaluate(features, short_circuit=False)
            assert bool(res) is True

            results[rule.name].append((addr, res))
            index_rule_matches(features, rule, [addr])

    return (features, results)