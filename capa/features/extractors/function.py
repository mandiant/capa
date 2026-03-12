# Copyright 2025 Google LLC
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

from __future__ import annotations

from typing import Mapping, Iterable

from capa.engine import FeatureSet
from capa.features.common import Feature, Characteristic, CallChain
from capa.features.address import Address


CALLS_FROM_FEATURE = Characteristic("calls from")
CALLS_TO_FEATURE = Characteristic("calls to")


def build_function_call_graph(function_features_by_address: Mapping[Address, FeatureSet]) -> dict[Address, set[Address]]:
    """
    Build caller -> callee edges between known functions.

    This uses both:
      - `characteristic(calls from)` found at instruction scope, and
      - `characteristic(calls to)` found at function scope.
    """
    function_addresses = set(function_features_by_address.keys())
    call_graph: dict[Address, set[Address]] = {f: set() for f in function_addresses}

    for function_address, features in function_features_by_address.items():
        for callee in features.get(CALLS_FROM_FEATURE, set()):
            if callee in function_addresses:
                call_graph[function_address].add(callee)

        for caller in features.get(CALLS_TO_FEATURE, set()):
            if caller in function_addresses:
                call_graph[caller].add(function_address)

    return call_graph


def find_call_chain_starts(
    function_features_by_address: Mapping[Address, FeatureSet],
    call_graph: Mapping[Address, set[Address]],
    chain: tuple[Feature, ...],
) -> set[Address]:
    """Return functions that satisfy a chain, anchored at the first element."""
    if not chain:
        return set()

    # Working set of functions that satisfy suffix chain[i+1:].
    suffix_matches = {f for f, features in function_features_by_address.items() if chain[-1] in features}

    # Walk backwards and require one call edge per chain step.
    for required_feature in reversed(chain[:-1]):
        next_matches: set[Address] = set()
        for function_address, features in function_features_by_address.items():
            if required_feature not in features:
                continue

            callees = call_graph.get(function_address, set())
            if any(callee in suffix_matches for callee in callees):
                next_matches.add(function_address)

        suffix_matches = next_matches
        if not suffix_matches:
            break

    return suffix_matches


def add_call_chain_features(
    function_features_by_address: Mapping[Address, FeatureSet],
    call_graph: Mapping[Address, set[Address]],
    chains: Iterable[tuple[Feature, ...]],
) -> None:
    """Resolve call-chain statements and annotate matching function feature sets."""
    for chain in chains:
        call_chain_feature = CallChain(chain)
        for function_address in find_call_chain_starts(function_features_by_address, call_graph, chain):
            function_features_by_address[function_address][call_chain_feature].add(function_address)
