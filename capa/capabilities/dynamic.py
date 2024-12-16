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
from capa.features.address import _NoAddress
from capa.capabilities.common import Capabilities, find_file_capabilities
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle, DynamicFeatureExtractor

logger = logging.getLogger(__name__)


# The number of calls that make up a sequence.
#
# The larger this is, the more calls are grouped together to match rule logic.
# This means a longer chain can be recognized; however, its a bit more expensive.
SEQUENCE_SIZE = 20


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
    find matches for the given rules within the given thread,
    which includes matches for all the sequences and calls within it.
    """
    # all features found within this thread,
    # includes features found within calls.
    features: FeatureSet = collections.defaultdict(set)

    # matches found at the call scope.
    # might be found at different calls, that's ok.
    call_matches: MatchResults = collections.defaultdict(list)

    # matches found at the sequence scope.
    sequence_matches: MatchResults = collections.defaultdict(list)

    # We matches sequences as the sliding window of calls with size SEQUENCE_SIZE.
    #
    # For each call, we consider the window of SEQUENCE_SIZE calls leading up to it,
    #  merging all their features and doing a match.
    #
    # We track these features in two data structures:
    #   1. a deque of those features found in the prior calls.
    #      We'll append to it, and as it grows larger than SEQUENCE_SIZE, the oldest items are removed.
    #   2. a live set of features seen in the sequence.
    #      As we pop from the deque, we remove features from the current set,
    #      and as we push to the deque, we insert features to the current set.
    # With this approach, our algorithm performance is independent of SEQUENCE_SIZE.
    # The naive algorithm, of merging all the trailing feature sets at each call, is dependent upon SEQUENCE_SIZE
    # (that is, runtime gets slower the larger SEQUENCE_SIZE is).
    sequence_feature_sets: collections.deque[FeatureSet] = collections.deque(maxlen=SEQUENCE_SIZE)
    sequence_features: FeatureSet = collections.defaultdict(set)

    # the names of rules matched at the last sequence,
    # so that we can deduplicate long strings of the same matche.
    last_sequence_matches: set[str] = set()

    for ch in extractor.get_calls(ph, th):
        call_capabilities = find_call_capabilities(ruleset, extractor, ph, th, ch)
        for feature, vas in call_capabilities.features.items():
            features[feature].update(vas)

        for rule_name, res in call_capabilities.matches.items():
            call_matches[rule_name].extend(res)

        #
        # sequence scope matching
        #
        # As we add items to the end of the deque, overflow and drop the oldest items (at the left end).
        # While we could rely on `deque.append` with `maxlen` set (which we provide above),
        # we want to use the dropped item first, to remove the old features, so we manually pop it here.
        if len(sequence_feature_sets) == SEQUENCE_SIZE:
            overflowing_feature_set = sequence_feature_sets.popleft()

            for feature, vas in overflowing_feature_set.items():
                if len(vas) == 1 and isinstance(next(iter(vas)), _NoAddress):
                    # `vas == { NO_ADDRESS }` without the garbage.
                    #
                    # ignore the common case of global features getting added/removed/trimmed repeatedly,
                    # like arch/os/format.
                    continue

                feature_vas = sequence_features[feature]
                feature_vas.difference_update(vas)
                if not feature_vas:
                    del sequence_features[feature]

        # update the deque and set of features with the latest call's worth of features.
        latest_features = call_capabilities.features
        sequence_feature_sets.append(latest_features)
        for feature, vas in latest_features.items():
            sequence_features[feature].update(vas)

        _, smatches = ruleset.match(Scope.SEQUENCE, sequence_features, ch.address)
        for rule_name, res in smatches.items():
            if rule_name in last_sequence_matches:
                # don't emit match results for rules seen during the immediately preceeding sequence.
                #
                # This means that we won't emit duplicate matches when there are multiple sequences
                #  that overlap a single matching event.
                # It also handles the case of a tight loop containing matched logic;
                #  only the first match will be recorded.
                #
                # In theory, this means the result document doesn't have *every* possible match location,
                # but in practice, humans will only be interested in the first handful anyways.
                continue
            sequence_matches[rule_name].extend(res)

        last_sequence_matches = set(smatches.keys())

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
    ruleset: RuleSet, extractor: DynamicFeatureExtractor, disable_progress: bool = False
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
