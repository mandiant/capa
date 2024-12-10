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
from dataclasses import dataclass

import capa.perf
import capa.helpers
import capa.features.freeze as frz
import capa.render.result_document as rdoc
from capa.rules import Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
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
    basic_block_matches: MatchResults
    instruction_matches: MatchResults
    feature_count: int


def find_code_capabilities(ruleset: RuleSet, extractor: StaticFeatureExtractor, fh: FunctionHandle) -> CodeCapabilities:
    """
    find matches for the given rules within the given function.
    """
    # all features found within this function,
    # includes features found within basic blocks (and instructions).
    function_features: FeatureSet = collections.defaultdict(set)

    # matches found at the basic block scope.
    # might be found at different basic blocks, that's ok.
    bb_matches: MatchResults = collections.defaultdict(list)

    # matches found at the instruction scope.
    # might be found at different instructions, that's ok.
    insn_matches: MatchResults = collections.defaultdict(list)

    for bb in extractor.get_basic_blocks(fh):
        basic_block_capabilities = find_basic_block_capabilities(ruleset, extractor, fh, bb)
        for feature, vas in basic_block_capabilities.features.items():
            function_features[feature].update(vas)

        for rule_name, res in basic_block_capabilities.basic_block_matches.items():
            bb_matches[rule_name].extend(res)

        for rule_name, res in basic_block_capabilities.instruction_matches.items():
            insn_matches[rule_name].extend(res)

    for feature, va in itertools.chain(extractor.extract_function_features(fh), extractor.extract_global_features()):
        function_features[feature].add(va)

    _, function_matches = ruleset.match(Scope.FUNCTION, function_features, fh.address)
    return CodeCapabilities(function_matches, bb_matches, insn_matches, len(function_features))


def find_static_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, disable_progress=None
) -> Capabilities:
    all_function_matches: MatchResults = collections.defaultdict(list)
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
            for rule_name, res in code_capabilities.basic_block_matches.items():
                all_bb_matches[rule_name].extend(res)
            for rule_name, res in code_capabilities.instruction_matches.items():
                all_insn_matches[rule_name].extend(res)

            pbar.advance(task)

    # collection of features that captures the rule matches within function, BB, and instruction scopes.
    # mapping from feature (matched rule) to set of addresses at which it matched.
    function_and_lower_features: FeatureSet = collections.defaultdict(set)
    for rule_name, results in itertools.chain(
        all_function_matches.items(), all_bb_matches.items(), all_insn_matches.items()
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
            all_function_matches.items(),
            all_file_capabilities.matches.items(),
        )
    )

    return Capabilities(matches, feature_counts, library_functions)
