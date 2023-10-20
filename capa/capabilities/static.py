# -*- coding: utf-8 -*-
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import time
import logging
import itertools
import collections
from typing import Any, Tuple

import tqdm.contrib.logging

import capa.perf
import capa.features.freeze as frz
import capa.render.result_document as rdoc
from capa.rules import Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
from capa.helpers import redirecting_print_to_tqdm
from capa.capabilities.common import find_file_capabilities
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, StaticFeatureExtractor

logger = logging.getLogger(__name__)


def find_instruction_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
) -> Tuple[FeatureSet, MatchResults]:
    """
    find matches for the given rules for the given instruction.

    returns: tuple containing (features for instruction, match results for instruction)
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

    return features, matches


def find_basic_block_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, f: FunctionHandle, bb: BBHandle
) -> Tuple[FeatureSet, MatchResults, MatchResults]:
    """
    find matches for the given rules within the given basic block.

    returns: tuple containing (features for basic block, match results for basic block, match results for instructions)
    """
    # all features found within this basic block,
    # includes features found within instructions.
    features: FeatureSet = collections.defaultdict(set)

    # matches found at the instruction scope.
    # might be found at different instructions, thats ok.
    insn_matches: MatchResults = collections.defaultdict(list)

    for insn in extractor.get_instructions(f, bb):
        ifeatures, imatches = find_instruction_capabilities(ruleset, extractor, f, bb, insn)
        for feature, vas in ifeatures.items():
            features[feature].update(vas)

        for rule_name, res in imatches.items():
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

    return features, matches, insn_matches


def find_code_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, fh: FunctionHandle
) -> Tuple[MatchResults, MatchResults, MatchResults, int]:
    """
    find matches for the given rules within the given function.

    returns: tuple containing (match results for function, match results for basic blocks, match results for instructions, number of features)
    """
    # all features found within this function,
    # includes features found within basic blocks (and instructions).
    function_features: FeatureSet = collections.defaultdict(set)

    # matches found at the basic block scope.
    # might be found at different basic blocks, thats ok.
    bb_matches: MatchResults = collections.defaultdict(list)

    # matches found at the instruction scope.
    # might be found at different instructions, thats ok.
    insn_matches: MatchResults = collections.defaultdict(list)

    for bb in extractor.get_basic_blocks(fh):
        features, bmatches, imatches = find_basic_block_capabilities(ruleset, extractor, fh, bb)
        for feature, vas in features.items():
            function_features[feature].update(vas)

        for rule_name, res in bmatches.items():
            bb_matches[rule_name].extend(res)

        for rule_name, res in imatches.items():
            insn_matches[rule_name].extend(res)

    for feature, va in itertools.chain(extractor.extract_function_features(fh), extractor.extract_global_features()):
        function_features[feature].add(va)

    _, function_matches = ruleset.match(Scope.FUNCTION, function_features, fh.address)
    return function_matches, bb_matches, insn_matches, len(function_features)


def find_static_capabilities(
    ruleset: RuleSet, extractor: StaticFeatureExtractor, disable_progress=None
) -> Tuple[MatchResults, Any]:
    all_function_matches: MatchResults = collections.defaultdict(list)
    all_bb_matches: MatchResults = collections.defaultdict(list)
    all_insn_matches: MatchResults = collections.defaultdict(list)

    feature_counts = rdoc.StaticFeatureCounts(file=0, functions=())
    library_functions: Tuple[rdoc.LibraryFunction, ...] = ()

    assert isinstance(extractor, StaticFeatureExtractor)
    with redirecting_print_to_tqdm(disable_progress):
        with tqdm.contrib.logging.logging_redirect_tqdm():
            pbar = tqdm.tqdm
            if capa.helpers.is_runtime_ghidra():
                # Ghidrathon interpreter cannot properly handle
                # the TMonitor thread that is created via a monitor_interval
                # > 0
                pbar.monitor_interval = 0
            if disable_progress:
                # do not use tqdm to avoid unnecessary side effects when caller intends
                # to disable progress completely
                def pbar(s, *args, **kwargs):
                    return s

            functions = list(extractor.get_functions())
            n_funcs = len(functions)

            pb = pbar(functions, desc="matching", unit=" functions", postfix="skipped 0 library functions", leave=False)
            for f in pb:
                t0 = time.time()
                if extractor.is_library_function(f.address):
                    function_name = extractor.get_function_name(f.address)
                    logger.debug("skipping library function 0x%x (%s)", f.address, function_name)
                    library_functions += (
                        rdoc.LibraryFunction(address=frz.Address.from_capa(f.address), name=function_name),
                    )
                    n_libs = len(library_functions)
                    percentage = round(100 * (n_libs / n_funcs))
                    if isinstance(pb, tqdm.tqdm):
                        pb.set_postfix_str(f"skipped {n_libs} library functions ({percentage}%)")
                    continue

                function_matches, bb_matches, insn_matches, feature_count = find_code_capabilities(
                    ruleset, extractor, f
                )
                feature_counts.functions += (
                    rdoc.FunctionFeatureCount(address=frz.Address.from_capa(f.address), count=feature_count),
                )
                t1 = time.time()

                match_count = sum(len(res) for res in function_matches.values())
                match_count += sum(len(res) for res in bb_matches.values())
                match_count += sum(len(res) for res in insn_matches.values())
                logger.debug(
                    "analyzed function 0x%x and extracted %d features, %d matches in %0.02fs",
                    f.address,
                    feature_count,
                    match_count,
                    t1 - t0,
                )

                for rule_name, res in function_matches.items():
                    all_function_matches[rule_name].extend(res)
                for rule_name, res in bb_matches.items():
                    all_bb_matches[rule_name].extend(res)
                for rule_name, res in insn_matches.items():
                    all_insn_matches[rule_name].extend(res)

    # collection of features that captures the rule matches within function, BB, and instruction scopes.
    # mapping from feature (matched rule) to set of addresses at which it matched.
    function_and_lower_features: FeatureSet = collections.defaultdict(set)
    for rule_name, results in itertools.chain(
        all_function_matches.items(), all_bb_matches.items(), all_insn_matches.items()
    ):
        locations = {p[0] for p in results}
        rule = ruleset[rule_name]
        capa.engine.index_rule_matches(function_and_lower_features, rule, locations)

    all_file_matches, feature_count = find_file_capabilities(ruleset, extractor, function_and_lower_features)
    feature_counts.file = feature_count

    matches = dict(
        itertools.chain(
            # each rule exists in exactly one scope,
            # so there won't be any overlap among these following MatchResults,
            # and we can merge the dictionaries naively.
            all_insn_matches.items(),
            all_bb_matches.items(),
            all_function_matches.items(),
            all_file_matches.items(),
        )
    )

    meta = {
        "feature_counts": feature_counts,
        "library_functions": library_functions,
    }

    return matches, meta
