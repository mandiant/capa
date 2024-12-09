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

import logging
import itertools
import collections
from dataclasses import dataclass

import capa.perf
import capa.features.freeze as frz
import capa.render.result_document as rdoc
from capa.rules import Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
from capa.capabilities.common import Capabilities, find_file_capabilities
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle, DynamicFeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class CallCapabilities:
    features: FeatureSet
    matches: MatchResults


# The number of calls that make up a sequence.
SEQUENCE_SIZE = 5


def find_call_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
) -> CallCapabilities:
    """
    find matches for the given rules for the given call.
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

    return CallCapabilities(features, matches)


@dataclass
class ThreadCapabilities:
    features: FeatureSet
    thread_matches: MatchResults
    sequence_matches: MatchResults
    call_matches: MatchResults


def find_thread_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, ph: ProcessHandle, th: ThreadHandle
) -> ThreadCapabilities:
    """
    find matches for the given rules within the given thread.
    """
    # all features found within this thread,
    # includes features found within calls.
    features: FeatureSet = collections.defaultdict(set)

    # matches found at the call scope.
    # might be found at different calls, that's ok.
    call_matches: MatchResults = collections.defaultdict(list)

    # matches found at the sequence scope.
    sequence_matches: MatchResults = collections.defaultdict(list)

    sequence: collections.deque[FeatureSet] = collections.deque(maxlen=SEQUENCE_SIZE)

    for ch in extractor.get_calls(ph, th):
        call_capabilities = find_call_capabilities(ruleset, extractor, ph, th, ch)
        for feature, vas in call_capabilities.features.items():
            features[feature].update(vas)

        for rule_name, res in call_capabilities.matches.items():
            call_matches[rule_name].extend(res)

        sequence.append(call_capabilities.features)
        sequence_features: FeatureSet = collections.defaultdict(set)
        for call in sequence:
            for feature, vas in call.items():
                sequence_features[feature].update(vas)

        _, smatches = ruleset.match(Scope.SEQUENCE, sequence_features, ch.address)
        for rule_name, res in smatches.items():
            sequence_matches[rule_name].extend(res)

    for feature, va in itertools.chain(extractor.extract_thread_features(ph, th), extractor.extract_global_features()):
        features[feature].add(va)

    # matches found within this thread.
    _, matches = ruleset.match(Scope.THREAD, features, th.address)

    for rule_name, res in matches.items():
        rule = ruleset[rule_name]
        for va, _ in res:
            capa.engine.index_rule_matches(features, rule, [va])

    return ThreadCapabilities(features, matches, sequence_matches, call_matches)


@dataclass
class ProcessCapabilities:
    process_matches: MatchResults
    thread_matches: MatchResults
    call_matches: MatchResults
    feature_count: int


def find_process_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, ph: ProcessHandle
) -> ProcessCapabilities:
    """
    find matches for the given rules within the given process.
    """
    # all features found within this process,
    # includes features found within threads (and calls).
    process_features: FeatureSet = collections.defaultdict(set)

    # matches found at the basic threads.
    # might be found at different threads, that's ok.
    thread_matches: MatchResults = collections.defaultdict(list)

    # matches found at the sequence scope.
    # might be found at different sequences, that's ok.
    sequence_matches: MatchResults = collections.defaultdict(list)

    # matches found at the call scope.
    # might be found at different calls, that's ok.
    call_matches: MatchResults = collections.defaultdict(list)

    for th in extractor.get_threads(ph):
        thread_capabilities = find_thread_capabilities(ruleset, extractor, ph, th)
        for feature, vas in thread_capabilities.features.items():
            process_features[feature].update(vas)

        for rule_name, res in thread_capabilities.thread_matches.items():
            thread_matches[rule_name].extend(res)

        for rule_name, res in thread_capabilities.sequence_matches.items():
            sequence_matches[rule_name].extend(res)

        for rule_name, res in thread_capabilities.call_matches.items():
            call_matches[rule_name].extend(res)

    for feature, va in itertools.chain(extractor.extract_process_features(ph), extractor.extract_global_features()):
        process_features[feature].add(va)

    _, process_matches = ruleset.match(Scope.PROCESS, process_features, ph.address)
    return ProcessCapabilities(process_matches, thread_matches, call_matches, len(process_features))


def find_dynamic_capabilities(
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, disable_progress=None
) -> Capabilities:
    all_process_matches: MatchResults = collections.defaultdict(list)
    all_thread_matches: MatchResults = collections.defaultdict(list)
    all_sequence_matches: MatchResults = collections.defaultdict(list)
    all_call_matches: MatchResults = collections.defaultdict(list)

    feature_counts = rdoc.DynamicFeatureCounts(file=0, processes=())

    assert isinstance(extractor, DynamicFeatureExtractor)
    processes: list[ProcessHandle] = list(extractor.get_processes())
    n_processes: int = len(processes)

    with capa.helpers.CapaProgressBar(
        console=capa.helpers.log_console, transient=True, disable=disable_progress
    ) as pbar:
        task = pbar.add_task("matching", total=n_processes, unit="processes")
        for p in processes:
            process_capabilities = find_process_capabilities(ruleset, extractor, p)
            feature_counts.processes += (
                rdoc.ProcessFeatureCount(
                    address=frz.Address.from_capa(p.address), count=process_capabilities.feature_count
                ),
            )
            logger.debug("analyzed %s and extracted %d features", p.address, process_capabilities.feature_count)

            for rule_name, res in process_capabilities.process_matches.items():
                all_process_matches[rule_name].extend(res)
            for rule_name, res in process_capabilities.thread_matches.items():
                all_thread_matches[rule_name].extend(res)
            for rule_name, res in process_capabilities.sequence_matches.items():
                all_sequence_matches[rule_name].extend(res)
            for rule_name, res in process_capabilities.call_matches.items():
                all_call_matches[rule_name].extend(res)

            pbar.advance(task)

    # collection of features that captures the rule matches within process and thread scopes.
    # mapping from feature (matched rule) to set of addresses at which it matched.
    process_and_lower_features: FeatureSet = collections.defaultdict(set)
    for rule_name, results in itertools.chain(
        all_process_matches.items(), all_thread_matches.items(), all_sequence_matches.items(), all_call_matches.items()
    ):
        locations = {p[0] for p in results}
        rule = ruleset[rule_name]
        capa.engine.index_rule_matches(process_and_lower_features, rule, locations)

    all_file_capabilities = find_file_capabilities(ruleset, extractor, process_and_lower_features)
    feature_counts.file = all_file_capabilities.feature_count

    matches = dict(
        itertools.chain(
            # each rule exists in exactly one scope,
            # so there won't be any overlap among these following MatchResults,
            # and we can merge the dictionaries naively.
            all_call_matches.items(),
            all_sequence_matches.items(),
            all_thread_matches.items(),
            all_process_matches.items(),
            all_file_capabilities.matches.items(),
        )
    )

    return Capabilities(matches, feature_counts)
