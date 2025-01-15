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


from __future__ import annotations

import itertools
import collections
from typing import Union, Optional

import capa.engine
from capa.rules import Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
from capa.features.address import NO_ADDRESS, Address
from capa.ida.plugin.extractor import CapaExplorerFeatureExtractor
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle


class CapaRuleGenFeatureCacheNode:
    def __init__(
        self,
        inner: Optional[Union[FunctionHandle, BBHandle, InsnHandle]],
        parent: Optional[CapaRuleGenFeatureCacheNode],
    ):
        self.inner: Optional[Union[FunctionHandle, BBHandle, InsnHandle]] = inner
        self.address = NO_ADDRESS if self.inner is None else self.inner.address
        self.parent: Optional[CapaRuleGenFeatureCacheNode] = parent

        if self.parent is not None:
            self.parent.children.add(self)

        self.features: FeatureSet = collections.defaultdict(set)
        self.children: set[CapaRuleGenFeatureCacheNode] = set()

    def __hash__(self):
        # TODO(mike-hunhoff): confirm this is unique enough
        # https://github.com/mandiant/capa/issues/1604
        return hash((self.address,))

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        # TODO(mike-hunhoff): confirm this is unique enough
        # https://github.com/mandiant/capa/issues/1604
        return self.address == other.address


class CapaRuleGenFeatureCache:
    def __init__(self, extractor: CapaExplorerFeatureExtractor):
        self.extractor = extractor
        self.global_features: FeatureSet = collections.defaultdict(set)

        self.file_node: CapaRuleGenFeatureCacheNode = CapaRuleGenFeatureCacheNode(None, None)
        self.func_nodes: dict[Address, CapaRuleGenFeatureCacheNode] = {}
        self.bb_nodes: dict[Address, CapaRuleGenFeatureCacheNode] = {}
        self.insn_nodes: dict[Address, CapaRuleGenFeatureCacheNode] = {}

        self._find_global_features()
        self._find_file_features()

    def _find_global_features(self):
        for feature, addr in self.extractor.extract_global_features():
            # not all global features may have virtual addresses.
            # if not, then at least ensure the feature shows up in the index.
            # the set of addresses will still be empty.
            if addr is not None:
                self.global_features[feature].add(addr)
            else:
                if feature not in self.global_features:
                    self.global_features[feature] = set()

    def _find_file_features(self):
        # not all file features may have virtual addresses.
        # if not, then at least ensure the feature shows up in the index.
        # the set of addresses will still be empty.
        for feature, addr in self.extractor.extract_file_features():
            if addr is not None:
                self.file_node.features[feature].add(addr)
            else:
                if feature not in self.file_node.features:
                    self.file_node.features[feature] = set()

    def _find_function_and_below_features(self, fh: FunctionHandle):
        f_node: CapaRuleGenFeatureCacheNode = CapaRuleGenFeatureCacheNode(fh, self.file_node)

        # extract basic block and below features
        for bbh in self.extractor.get_basic_blocks(fh):
            bb_node: CapaRuleGenFeatureCacheNode = CapaRuleGenFeatureCacheNode(bbh, f_node)

            # extract instruction features
            for ih in self.extractor.get_instructions(fh, bbh):
                inode: CapaRuleGenFeatureCacheNode = CapaRuleGenFeatureCacheNode(ih, bb_node)

                for feature, addr in self.extractor.extract_insn_features(fh, bbh, ih):
                    inode.features[feature].add(addr)

                self.insn_nodes[inode.address] = inode

            # extract basic block features
            for feature, addr in self.extractor.extract_basic_block_features(fh, bbh):
                bb_node.features[feature].add(addr)

            # store basic block features in cache and function parent
            self.bb_nodes[bb_node.address] = bb_node

        # extract function features
        for feature, addr in self.extractor.extract_function_features(fh):
            f_node.features[feature].add(addr)

        self.func_nodes[f_node.address] = f_node

    def _find_instruction_capabilities(
        self, ruleset: RuleSet, insn: CapaRuleGenFeatureCacheNode
    ) -> tuple[FeatureSet, MatchResults]:
        features: FeatureSet = collections.defaultdict(set)

        for feature, locs in itertools.chain(insn.features.items(), self.global_features.items()):
            features[feature].update(locs)

        _, matches = ruleset.match(Scope.INSTRUCTION, features, insn.address)
        for name, result in matches.items():
            rule = ruleset[name]
            for addr, _ in result:
                capa.engine.index_rule_matches(features, rule, [addr])

        return features, matches

    def _find_basic_block_capabilities(
        self, ruleset: RuleSet, bb: CapaRuleGenFeatureCacheNode
    ) -> tuple[FeatureSet, MatchResults, MatchResults]:
        features: FeatureSet = collections.defaultdict(set)
        insn_matches: MatchResults = collections.defaultdict(list)

        for insn in bb.children:
            ifeatures, imatches = self._find_instruction_capabilities(ruleset, insn)
            for feature, locs in ifeatures.items():
                features[feature].update(locs)
            for name, result in imatches.items():
                insn_matches[name].extend(result)

        for feature, locs in itertools.chain(bb.features.items(), self.global_features.items()):
            features[feature].update(locs)

        _, matches = ruleset.match(Scope.BASIC_BLOCK, features, bb.address)
        for name, result in matches.items():
            rule = ruleset[name]
            for loc, _ in result:
                capa.engine.index_rule_matches(features, rule, [loc])

        return features, matches, insn_matches

    def find_code_capabilities(
        self, ruleset: RuleSet, fh: FunctionHandle
    ) -> tuple[FeatureSet, MatchResults, MatchResults, MatchResults]:
        f_node: Optional[CapaRuleGenFeatureCacheNode] = self._get_cached_func_node(fh)
        if f_node is None:
            return {}, {}, {}, {}

        insn_matches: MatchResults = collections.defaultdict(list)
        bb_matches: MatchResults = collections.defaultdict(list)
        function_features: FeatureSet = collections.defaultdict(set)

        for bb in f_node.children:
            features, bmatches, imatches = self._find_basic_block_capabilities(ruleset, bb)
            for feature, locs in features.items():
                function_features[feature].update(locs)
            for name, result in bmatches.items():
                bb_matches[name].extend(result)
            for name, result in imatches.items():
                insn_matches[name].extend(result)

        for feature, locs in itertools.chain(f_node.features.items(), self.global_features.items()):
            function_features[feature].update(locs)

        _, function_matches = ruleset.match(Scope.FUNCTION, function_features, f_node.address)
        return function_features, function_matches, bb_matches, insn_matches

    def find_file_capabilities(self, ruleset: RuleSet) -> tuple[FeatureSet, MatchResults]:
        features: FeatureSet = collections.defaultdict(set)

        for func_node in self.file_node.children:
            assert func_node.inner is not None
            assert isinstance(func_node.inner, FunctionHandle)

            func_features, _, _, _ = self.find_code_capabilities(ruleset, func_node.inner)
            for feature, locs in func_features.items():
                features[feature].update(locs)

        for feature, locs in itertools.chain(self.file_node.features.items(), self.global_features.items()):
            features[feature].update(locs)

        _, matches = ruleset.match(Scope.FILE, features, NO_ADDRESS)
        return features, matches

    def _get_cached_func_node(self, fh: FunctionHandle) -> Optional[CapaRuleGenFeatureCacheNode]:
        f_node: Optional[CapaRuleGenFeatureCacheNode] = self.func_nodes.get(fh.address)
        if f_node is None:
            # function is not in our cache, do extraction now
            self._find_function_and_below_features(fh)
            f_node = self.func_nodes.get(fh.address)
        return f_node

    def get_all_function_features(self, fh: FunctionHandle) -> FeatureSet:
        f_node: Optional[CapaRuleGenFeatureCacheNode] = self._get_cached_func_node(fh)
        if f_node is None:
            return {}

        all_function_features: FeatureSet = collections.defaultdict(set)
        all_function_features.update(f_node.features)

        for bb_node in f_node.children:
            for i_node in bb_node.children:
                for feature, locs in i_node.features.items():
                    all_function_features[feature].update(locs)
            for feature, locs in bb_node.features.items():
                all_function_features[feature].update(locs)

        # include global features just once
        for feature, locs in self.global_features.items():
            all_function_features[feature].update(locs)

        return all_function_features

    def get_all_file_features(self):
        yield from itertools.chain(self.file_node.features.items(), self.global_features.items())
