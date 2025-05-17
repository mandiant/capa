# -*- coding: utf-8 -*-
# Copyright 2023 Google LLC
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

import time
import logging
import itertools
import collections
from typing import Optional
from dataclasses import dataclass

import intervaltree

import capa.perf
import capa.helpers
import capa.features.freeze as frz
import capa.render.result_document as rdoc
from capa.rules import Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
from capa.features.common import Result
from capa.features.address import Address, SuperblockAddress
from capa.capabilities.common import Capabilities, find_file_capabilities
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, StaticFeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class InstructionCapabilities:
    features: FeatureSet
    matches: MatchResults


def find_instruction_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
) -> InstructionCapabilities:
    """
    find matches for the given rules for the given instruction.
    """
    # all features found for the instruction.
    features: FeatureSet = collections.defaultdict(set)

    for feature, addr in itertools.chain(
        extractor.extract_insn_features(f, bb, insn), extractor.extract_global_features()
    ):
        features[feature].add(addr)

    # matches found at this instruction.
    _, matches = ruleset.match(Scope.INSTRUCTION, features, insn.address)

    for rule_name, res in matches.items():
        rule = ruleset[rule_name]
        for addr, _ in res:
            capa.engine.index_rule_matches(features, rule, [addr])

    return InstructionCapabilities(features, matches)


@dataclass
class BasicBlockCapabilities:
    features: FeatureSet
    basic_block_matches: MatchResults
    instruction_matches: MatchResults


def find_basic_block_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, f: FunctionHandle, bb: BBHandle
) -> BasicBlockCapabilities:
    """
    find matches for the given rules within the given basic block.
    """
    # all features found within this basic block,
    # includes features found within instructions.
    features: FeatureSet = collections.defaultdict(set)

    # matches found at the instruction scope.
    # might be found at different instructions, that's ok.
    insn_matches: MatchResults = collections.defaultdict(list)

    for insn in extractor.get_instructions(f, bb):
        instruction_capabilities = find_instruction_capabilities(ruleset, extractor, f, bb, insn)
        for feature, vas in instruction_capabilities.features.items():
            features[feature].update(vas)

        for rule_name, res in instruction_capabilities.matches.items():
            insn_matches[rule_name].extend(res)

    for feature, va in itertools.chain(
        extractor.extract_basic_block_features(f, bb), extractor.extract_global_features()
    ):
        features[feature].add(va)

    # matches found within this basic block.
    _, matches = ruleset.match(Scope.BASIC_BLOCK, features, bb.address)

    for rule_name, res in matches.items():
        rule = ruleset[rule_name]
        for va, _ in res:
            capa.engine.index_rule_matches(features, rule, [va])

    return BasicBlockCapabilities(features, matches, insn_matches)


@dataclass
class CodeCapabilities:
    function_matches: MatchResults
    superblock_matches: MatchResults
    basic_block_matches: MatchResults
    instruction_matches: MatchResults
    feature_count: int


@dataclass
class FlowGraphNode:
    # This dataclass will be used in the construction of the function's basic block flow graph.
    # Some analysis backends provide native support for flow graphs, but we construct it here regardless
    # to decrease the amount of code required on the analysis backend's side (feature extractors).
    bva: Address
    left: Optional[Address]
    right: Optional[Address]


class SuperblockMatcher:
    def __init__(self, ruleset: RuleSet, extractor: StaticFeatureExtractor):
        self.ruleset: RuleSet = ruleset
        self.extractor: StaticFeatureExtractor = extractor
        self.features: FeatureSet = collections.defaultdict(set)
        self.matches: MatchResults = collections.defaultdict(list)
        self.flow_graph: dict[Address, FlowGraphNode] = {}
        self.addr_to_bb = intervaltree.IntervalTree()

    def add_basic_block(self, bb: BBHandle, features: FeatureSet):
        """
        Register a basic block and its features inot the superblock matcher.

        The basic block is added to the flowgraph tree maintained by the matcher object,
        and its features are added to the global feature set maintained by the matcher object.

        Capabilities will later be extracted from all the registered features (as if they were extracted at the same level),
        and will be pruned after that while keeping only capabilities matched on superblocks (i.e., relevant basic blocks
        in series with no interruptions between)
        """
        # Get the basic blocks that follow the current one.
        branches = list(self.extractor.get_next_basic_blocks(bb))
        # Get the current bb's size
        bb_size = self.extractor.get_basic_block_size(bb)

        # Add the basic block to the flow graph.
        self.flow_graph[bb.address] = FlowGraphNode(
            bva=bb.address,
            left=branches[0] if branches and branches[0] != bb.address else None,
            right=branches[1] if len(branches) > 1 and branches[1] != bb.address else None,
        )

        # Register bb's address space in the interval tree.
        # This will later be used to determine the bb that a feature was extracted from.
        if bb_size != 0:
            self.addr_to_bb[int(bb.address) : int(bb.address) + bb_size] = bb.address

        # Add features extracted from this bb into the matcher's overall collection of features.
        for feature, va in features.items():
            self.features[feature].update(va)

    def _prune(self):
        # go through each rule in self.matches, and each match in self.matches[rule_name],
        # and then check if the self.matches[rule_name].locations or locations in each child of self.matches[rule_name].children
        # have basic block gaps in them. If so, remove that specific match from self.matches[rule_name].
        # if self.matches[rule_name] then becomes empty, remove it from self.matches.
        def form_superblock_from_bbs(bb_locations: set[Address]) -> list[Address]:
            cycle_heads: dict[Address, list] = collections.defaultdict(list)

            # If one of the basic blocks has both a left and a right branch in the list of basic blocks,
            # then we cannot form a superblock and we return an empty list
            for location in bb_locations:
                if self.flow_graph[location].left in bb_locations and self.flow_graph[location].right in bb_locations:
                    return []

            # Go through the list of provided basic blocks and form superblocks from it.
            # If we find that only one cycle exits, and not multiple disjoint cycles, we return that cycle.
            # Otherwise, we return an empty list.
            while bb_locations:
                # We pick a random basic block and try to form a cycle from it.
                # The resulting cycle (of length greater or equal to 1) is storred
                head: FlowGraphNode = self.flow_graph[bb_locations.pop()]
                node = head
                while node:
                    cycle_heads[head.bva].append(node.bva)
                    # Check if branch is in the list of basic blocks. If so, add to current cycle.
                    if node.left in bb_locations:
                        bb_locations.remove(node.left)
                        node = self.flow_graph[node.left]
                    elif node.right in bb_locations:
                        bb_locations.remove(node.right)
                        node = self.flow_graph[node.right]
                    # Check if branch is the start of an encountered cycle. If so, connect the two cycles.
                    elif node.left in cycle_heads:
                        cycle_heads[head.bva] += cycle_heads.pop(node.left)
                        break
                    elif node.right in cycle_heads:
                        cycle_heads[head.bva] += cycle_heads.pop(node.right)
                        break
                    # The current basic block either branches to a basic block that holds no relevant features,
                    # or loops back to a basic block in the cycle, or the basic block is at the end of the function.
                    else:
                        break

            if len(cycle_heads) == 1 and len(list(cycle_heads.values())[0]) > 1:
                # Inputted basic blocks form a single cycle (i.e., superblock) of length > 1.
                # Return that cycle (superblock).
                return cycle_heads.popitem()[1]
            else:
                # Inputted basic blocks form either multiple disjoint cycles, or a cycle of length <= 1.
                # Return an empty list (i.e., boolean False).
                return []

        def get_bbs_from_locations(locations: set[Address]) -> set[Address]:
            bbs_addresses = set()
            for location in locations:
                # get the bb address from the location
                # and add it to the set of bb addresses.
                bbs_addresses.add(list(self.addr_to_bb[int(location)])[0].begin)
            return bbs_addresses

        def get_locations(result: Result) -> set[Address]:
            # get all locations of found features in the result.
            if not result.success:
                # Not statements are an edge case, but the locations of their children is not set anyways.
                # Logically this is still valid because "not" is usually used to make sure features do not exist.
                return set()
            if result.children:
                # Statements are usually what returns children, and they usually do not have locations.
                locations: set[Address] = set()
                for child in result.children:
                    locations.update(get_locations(child))
                return locations
            if result.locations:
                # We are dealing with a feature. Convert locations from frozenset to set then return it.
                return set(result.locations)
            return set()

        pruned_matches: MatchResults = collections.defaultdict(list)
        for rule_name, matches in self.matches.items():
            for _, result in matches:
                locations = get_locations(result)
                features_bbs = get_bbs_from_locations(locations)
                superblock = form_superblock_from_bbs(features_bbs)
                if superblock:
                    # The match spans multiple basic blocks that form a superblock. Therefore, we keep it.
                    pruned_matches[rule_name].append((SuperblockAddress(superblock), result))

        # update the list of valid matches.
        self.matches = pruned_matches

    def match(self, f_address: Address):
        # match superblock rules against the constructed flow graph.
        _, self.matches = self.ruleset.match(Scope.SUPERBLOCK, self.features, f_address)
        self._prune()


def find_code_capabilities(ruleset: RuleSet, extractor: StaticFeatureExtractor, fh: FunctionHandle) -> CodeCapabilities:
    """
    find matches for the given rules within the given function.
    """
    # all features found within this function,
    # includes features found within basic blocks (and instructions).
    function_features: FeatureSet = collections.defaultdict(set)

    # matches found at the constituent superblocks of this function.
    superblock_matches: MatchResults = collections.defaultdict(list)

    # matches found at the basic block scope.
    # might be found at different basic blocks, that's ok.
    bb_matches: MatchResults = collections.defaultdict(list)

    # matches found at the instruction scope.
    # might be found at different instructions, that's ok.
    insn_matches: MatchResults = collections.defaultdict(list)

    superblock_matcher = SuperblockMatcher(ruleset, extractor)

    for bb in extractor.get_basic_blocks(fh):
        basic_block_capabilities = find_basic_block_capabilities(ruleset, extractor, fh, bb)
        for feature, vas in basic_block_capabilities.features.items():
            function_features[feature].update(vas)

        for rule_name, res in basic_block_capabilities.basic_block_matches.items():
            bb_matches[rule_name].extend(res)

        for rule_name, res in basic_block_capabilities.instruction_matches.items():
            insn_matches[rule_name].extend(res)

        # add basic block and its features and capabilities to the superblock matcher.
        superblock_matcher.add_basic_block(bb, basic_block_capabilities.features)

    # match capabilities at the superblock scope once all basic blocks have been added.
    superblock_matcher.match(fh.address)
    for rule_name, res in superblock_matcher.matches.items():
        superblock_matches[rule_name].extend(res)
        rule = ruleset[rule_name]
        for va, _ in res:
            capa.engine.index_rule_matches(function_features, rule, [va])

    for feature, va in itertools.chain(extractor.extract_function_features(fh), extractor.extract_global_features()):
        function_features[feature].add(va)

    _, function_matches = ruleset.match(Scope.FUNCTION, function_features, fh.address)
    return CodeCapabilities(function_matches, superblock_matches, bb_matches, insn_matches, len(function_features))


def find_static_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, disable_progress=None
) -> Capabilities:
    all_function_matches: MatchResults = collections.defaultdict(list)
    all_superblock_matches: MatchResults = collections.defaultdict(list)
    all_bb_matches: MatchResults = collections.defaultdict(list)
    all_insn_matches: MatchResults = collections.defaultdict(list)

    feature_counts = rdoc.StaticFeatureCounts(file=0, functions=())
    library_functions: tuple[rdoc.LibraryFunction, ...] = ()

    assert isinstance(extractor, StaticFeatureExtractor)
    functions: list[FunctionHandle] = list(extractor.get_functions())
    n_funcs: int = len(functions)
    n_libs: int = 0
    percentage: float = 0

    with capa.helpers.CapaProgressBar(
        console=capa.helpers.log_console, transient=True, disable=disable_progress
    ) as pbar:
        task = pbar.add_task(
            "matching", total=n_funcs, unit="functions", postfix=f"skipped {n_libs} library functions, {percentage}%"
        )
        for f in functions:
            t0 = time.time()
            if extractor.is_library_function(f.address):
                function_name = extractor.get_function_name(f.address)
                logger.debug("skipping library function 0x%x (%s)", f.address, function_name)
                library_functions += (
                    rdoc.LibraryFunction(address=frz.Address.from_capa(f.address), name=function_name),
                )
                n_libs = len(library_functions)
                percentage = round(100 * (n_libs / n_funcs))
                pbar.update(task, postfix=f"skipped {n_libs} library functions, {percentage}%")
                pbar.advance(task)
                continue

            code_capabilities = find_code_capabilities(ruleset, extractor, f)
            feature_counts.functions += (
                rdoc.FunctionFeatureCount(
                    address=frz.Address.from_capa(f.address), count=code_capabilities.feature_count
                ),
            )
            t1 = time.time()

            match_count = 0
            for name, matches_ in itertools.chain(
                code_capabilities.function_matches.items(),
                code_capabilities.superblock_matches.items(),
                code_capabilities.basic_block_matches.items(),
                code_capabilities.instruction_matches.items(),
            ):
                if not ruleset.rules[name].is_subscope_rule():
                    match_count += len(matches_)

            logger.debug(
                "analyzed function 0x%x and extracted %d features, %d matches in %0.02fs",
                f.address,
                code_capabilities.feature_count,
                match_count,
                t1 - t0,
            )

            for rule_name, res in code_capabilities.function_matches.items():
                all_function_matches[rule_name].extend(res)
            for rule_name, res in code_capabilities.superblock_matches.items():
                all_superblock_matches[rule_name].extend(res)
            for rule_name, res in code_capabilities.basic_block_matches.items():
                all_bb_matches[rule_name].extend(res)
            for rule_name, res in code_capabilities.instruction_matches.items():
                all_insn_matches[rule_name].extend(res)

            pbar.advance(task)

    # collection of features that captures the rule matches within function, BB, and instruction scopes.
    # mapping from feature (matched rule) to set of addresses at which it matched.
    function_and_lower_features: FeatureSet = collections.defaultdict(set)
    for rule_name, results in itertools.chain(
        all_function_matches.items(), all_superblock_matches.items(), all_bb_matches.items(), all_insn_matches.items()
    ):
        locations = {p[0] for p in results}
        rule = ruleset[rule_name]
        capa.engine.index_rule_matches(function_and_lower_features, rule, locations)

    all_file_capabilities = find_file_capabilities(ruleset, extractor, function_and_lower_features)
    feature_counts.file = all_file_capabilities.feature_count

    matches: MatchResults = dict(
        itertools.chain(
            # each rule exists in exactly one scope,
            # so there won't be any overlap among these following MatchResults,
            # and we can merge the dictionaries naively.
            all_insn_matches.items(),
            all_bb_matches.items(),
            all_superblock_matches.items(),
            all_function_matches.items(),
            all_file_capabilities.matches.items(),
        )
    )

    return Capabilities(matches, feature_counts, library_functions)
