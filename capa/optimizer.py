# Copyright 2021 Google LLC
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

import capa.engine as ceng
import capa.features.common

logger = logging.getLogger(__name__)


def get_node_cost(node):
    if isinstance(node, (capa.features.common.OS, capa.features.common.Arch, capa.features.common.Format)):
        # we assume these are the most restrictive features:
        # authors commonly use them at the start of rules to restrict the category of samples to inspect
        return 0

    # elif "everything else":
    #   return 1
    #
    # this should be all hash-lookup features.
    # see below.

    elif isinstance(node, (capa.features.common.Substring, capa.features.common.Regex, capa.features.common.Bytes)):
        # substring and regex features require a full scan of each string
        # which we anticipate is more expensive then a hash lookup feature (e.g. mnemonic or count).
        #
        # fun research: compute the average cost of these feature relative to hash feature
        # and adjust the factor accordingly.
        return 2

    elif isinstance(node, (ceng.Not, ceng.Range)):
        # the cost of these nodes are defined by the complexity of their single child.
        return 1 + get_node_cost(node.child)

    elif isinstance(node, (ceng.And, ceng.Or, ceng.Some)):
        # the cost of these nodes is the full cost of their children
        # as this is the worst-case scenario.
        return 1 + sum(map(get_node_cost, node.children))

    else:
        # this should be all hash-lookup features.
        # we give this a arbitrary weight of 1.
        # the only thing more "important" than this is checking OS/Arch/Format.
        return 1


def optimize_statement(statement):
    # this routine operates in-place

    if isinstance(statement, (ceng.And, ceng.Or, ceng.Some)):
        # has .children
        statement.children = sorted(statement.children, key=get_node_cost)
        return
    elif isinstance(statement, (ceng.Not, ceng.Range)):
        # has .child
        optimize_statement(statement.child)
        return
    else:
        # appears to be "simple"
        return


def optimize_rule(rule):
    # this routine operates in-place
    optimize_statement(rule.statement)


def optimize_rules(rules):
    logger.debug("optimizing %d rules", len(rules))
    for rule in rules:
        optimize_rule(rule)
    return rules
