# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import copy
import collections
from typing import Set, Dict, List, Tuple, Union, Mapping, Iterable

import capa.rules
import capa.features.common
from capa.features.common import Feature

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

    def evaluate(self, features: FeatureSet) -> "Result":
        """
        classes that inherit `Statement` must implement `evaluate`

        args:
          ctx (defaultdict[Feature, set[VA]])

        returns:
          Result
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


class Result:
    """
    represents the results of an evaluation of statements against features.

    instances of this class should behave like a bool,
    e.g. `assert Result(True, ...) == True`

    instances track additional metadata about evaluation results.
    they contain references to the statement node (e.g. an And statement),
     as well as the children Result instances.

    we need this so that we can render the tree of expressions and their results.
    """

    def __init__(self, success: bool, statement: Union[Statement, Feature], children: List["Result"], locations=None):
        """
        args:
          success (bool)
          statement (capa.engine.Statement or capa.features.Feature)
          children (list[Result])
          locations (iterable[VA])
        """
        super(Result, self).__init__()
        self.success = success
        self.statement = statement
        self.children = children
        self.locations = locations if locations is not None else ()

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.success == other
        return False

    def __bool__(self):
        return self.success

    def __nonzero__(self):
        return self.success


class And(Statement):
    """match if all of the children evaluate to True."""

    def __init__(self, children, description=None):
        super(And, self).__init__(description=description)
        self.children = children

    def evaluate(self, ctx):
        results = [child.evaluate(ctx) for child in self.children]
        success = all(results)
        return Result(success, self, results)


class Or(Statement):
    """match if any of the children evaluate to True."""

    def __init__(self, children, description=None):
        super(Or, self).__init__(description=description)
        self.children = children

    def evaluate(self, ctx):
        results = [child.evaluate(ctx) for child in self.children]
        success = any(results)
        return Result(success, self, results)


class Not(Statement):
    """match only if the child evaluates to False."""

    def __init__(self, child, description=None):
        super(Not, self).__init__(description=description)
        self.child = child

    def evaluate(self, ctx):
        results = [self.child.evaluate(ctx)]
        success = not results[0]
        return Result(success, self, results)


class Some(Statement):
    """match if at least N of the children evaluate to True."""

    def __init__(self, count, children, description=None):
        super(Some, self).__init__(description=description)
        self.count = count
        self.children = children

    def evaluate(self, ctx):
        results = [child.evaluate(ctx) for child in self.children]
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

    def evaluate(self, ctx):
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

    def __init__(self, scope, child):
        super(Subscope, self).__init__()
        self.scope = scope
        self.child = child

    def evaluate(self, ctx):
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
    Args:
      rules (List[capa.rules.Rule]): these must already be ordered topologically by dependency.
      features (Mapping[capa.features.Feature, int]):
      va (int): location of the features

    Returns:
      Tuple[FeatureSet, MatchResults]: two-tuple with entries:
        - set of features used for matching (which may be a superset of the given `features` argument, due to rule match features), and
        - mapping from rule name to [(location of match, result object)]
    """
    results = collections.defaultdict(list)  # type: MatchResults

    # copy features so that we can modify it
    # without affecting the caller (keep this function pure)
    #
    # note: copy doesn't notice this is a defaultdict, so we'll recreate that manually.
    features = collections.defaultdict(set, copy.copy(features))

    for rule in rules:
        res = rule.evaluate(features)
        if res:
            results[rule.name].append((va, res))
            # we need to update the current `features`
            # because subsequent iterations of this loop may use newly added features,
            # such as rule or namespace matches.
            index_rule_matches(features, rule, [va])

    return (features, results)
