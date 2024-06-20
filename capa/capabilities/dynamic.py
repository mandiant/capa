# -*- coding: utf-8 -*-
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import logging
import itertools
import collections
from typing import Any, Tuple

import tqdm

import capa.perf
import capa.features.freeze as frz
import capa.render.result_document as rdoc
from capa.rules import Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
from capa.helpers import redirecting_print_to_tqdm
from capa.capabilities.common import find_file_capabilities
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle, DynamicFeatureExtractor

logger = logging.getLogger(__name__)


def find_call_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
) -> Tuple[FeatureSet, MatchResults]:
    """
    find matches for the given rules for the given call.

    returns: tuple containing (features for call, match results for call)
    """
    # all features found for the call.
    features: FeatureSet = collections.defaultdict(set)

    for feature, addr in itertools.chain(
        extractor.extract_call_features(ph, th, ch), extractor.extract_global_features()
    ):
        features[feature].add(addr)

    # matches found at this thread.
    _, matches = ruleset.match(Scope.CALL, features, ch.address)

    for rule_name, res in matches.items():
        rule = ruleset[rule_name]
        for addr, _ in res:
            capa.engine.index_rule_matches(features, rule, [addr])

    return features, matches


def find_thread_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, ph: ProcessHandle, th: ThreadHandle
) -> Tuple[FeatureSet, MatchResults, MatchResults]:
    """
    find matches for the given rules within the given thread.

    returns: tuple containing (features for thread, match results for thread, match results for calls)
    """
    # all features found within this thread,
    # includes features found within calls.
    features: FeatureSet = collections.defaultdict(set)

    # matches found at the call scope.
    # might be found at different calls, that's ok.
    call_matches: MatchResults = collections.defaultdict(list)

    for ch in extractor.get_calls(ph, th):
        ifeatures, imatches = find_call_capabilities(ruleset, extractor, ph, th, ch)
        for feature, vas in ifeatures.items():
            features[feature].update(vas)

        for rule_name, res in imatches.items():
            call_matches[rule_name].extend(res)

    for feature, va in itertools.chain(extractor.extract_thread_features(ph, th), extractor.extract_global_features()):
        features[feature].add(va)

    # matches found within this thread.
    _, matches = ruleset.match(Scope.THREAD, features, th.address)

    for rule_name, res in matches.items():
        rule = ruleset[rule_name]
        for va, _ in res:
            capa.engine.index_rule_matches(features, rule, [va])

    return features, matches, call_matches


def find_process_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, ph: ProcessHandle
) -> Tuple[MatchResults, MatchResults, MatchResults, int]:
    """
    find matches for the given rules within the given process.

    returns: tuple containing (match results for process, match results for threads, match results for calls, number of features)
    """
    # all features found within this process,
    # includes features found within threads (and calls).
    process_features: FeatureSet = collections.defaultdict(set)

    # matches found at the basic threads.
    # might be found at different threads, that's ok.
    thread_matches: MatchResults = collections.defaultdict(list)

    # matches found at the call scope.
    # might be found at different calls, that's ok.
    call_matches: MatchResults = collections.defaultdict(list)

    for th in extractor.get_threads(ph):
        features, tmatches, cmatches = find_thread_capabilities(ruleset, extractor, ph, th)
        for feature, vas in features.items():
            process_features[feature].update(vas)

        for rule_name, res in tmatches.items():
            thread_matches[rule_name].extend(res)

        for rule_name, res in cmatches.items():
            call_matches[rule_name].extend(res)

    for feature, va in itertools.chain(extractor.extract_process_features(ph), extractor.extract_global_features()):
        process_features[feature].add(va)

    _, process_matches = ruleset.match(Scope.PROCESS, process_features, ph.address)
    return process_matches, thread_matches, call_matches, len(process_features)


def find_dynamic_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, disable_progress=None
) -> Tuple[MatchResults, Any]:
    all_process_matches: MatchResults = collections.defaultdict(list)
    all_thread_matches: MatchResults = collections.defaultdict(list)
    all_call_matches: MatchResults = collections.defaultdict(list)

    feature_counts = rdoc.DynamicFeatureCounts(file=0, processes=())

    assert isinstance(extractor, DynamicFeatureExtractor)
    with redirecting_print_to_tqdm(disable_progress):
        with tqdm.contrib.logging.logging_redirect_tqdm():
            pbar = tqdm.tqdm
            if disable_progress:
                # do not use tqdm to avoid unnecessary side effects when caller intends
                # to disable progress completely
                def pbar(s, *args, **kwargs):
                    return s

            elif not sys.stderr.isatty():
                # don't display progress bar when stderr is redirected to a file
                def pbar(s, *args, **kwargs):
                    return s

            processes = list(extractor.get_processes())

            pb = pbar(processes, desc="matching", unit=" processes", leave=False)
            for p in pb:
                process_matches, thread_matches, call_matches, feature_count = find_process_capabilities(
                    ruleset, extractor, p
                )
                feature_counts.processes += (
                    rdoc.ProcessFeatureCount(address=frz.Address.from_capa(p.address), count=feature_count),
                )
                logger.debug("analyzed %s and extracted %d features", p.address, feature_count)

                for rule_name, res in process_matches.items():
                    all_process_matches[rule_name].extend(res)
                for rule_name, res in thread_matches.items():
                    all_thread_matches[rule_name].extend(res)
                for rule_name, res in call_matches.items():
                    all_call_matches[rule_name].extend(res)

    # collection of features that captures the rule matches within process and thread scopes.
    # mapping from feature (matched rule) to set of addresses at which it matched.
    process_and_lower_features: FeatureSet = collections.defaultdict(set)
    for rule_name, results in itertools.chain(
        all_process_matches.items(), all_thread_matches.items(), all_call_matches.items()
    ):
        locations = {p[0] for p in results}
        rule = ruleset[rule_name]
        capa.engine.index_rule_matches(process_and_lower_features, rule, locations)

    all_file_matches, feature_count = find_file_capabilities(ruleset, extractor, process_and_lower_features)
    feature_counts.file = feature_count

    matches = dict(
        itertools.chain(
            # each rule exists in exactly one scope,
            # so there won't be any overlap among these following MatchResults,
            # and we can merge the dictionaries naively.
            all_thread_matches.items(),
            all_process_matches.items(),
            all_call_matches.items(),
            all_file_matches.items(),
        )
    )

    meta = {
        "feature_counts": feature_counts,
    }

    return matches, meta
