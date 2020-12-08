# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import json

import six

import capa.rules
import capa.engine


def convert_statement_to_result_document(statement):
    """
    "statement": {
        "type": "or"
    },

    "statement": {
        "max": 9223372036854775808,
        "min": 2,
        "type": "range"
    },
    """
    statement_type = statement.name.lower()
    result = {"type": statement_type}
    if statement.description:
        result["description"] = statement.description

    if statement_type == "some" and statement.count == 0:
        result["type"] = "optional"
    elif statement_type == "some":
        result["count"] = statement.count
    elif statement_type == "range":
        result["min"] = statement.min
        result["max"] = statement.max
        result["child"] = convert_feature_to_result_document(statement.child)
    elif statement_type == "subscope":
        result["subscope"] = statement.scope

    return result


def convert_feature_to_result_document(feature):
    """
    "feature": {
        "number": 6,
        "type": "number"
    },

    "feature": {
        "api": "ws2_32.WSASocket",
        "type": "api"
    },

    "feature": {
        "match": "create TCP socket",
        "type": "match"
    },

    "feature": {
        "characteristic": [
            "loop",
            true
        ],
        "type": "characteristic"
    },
    """
    result = {"type": feature.name, feature.name: feature.get_value_str()}
    if feature.description:
        result["description"] = feature.description
    if feature.name == "regex":
        result["match"] = feature.match
    return result


def convert_node_to_result_document(node):
    """
    "node": {
        "type": "statement",
        "statement": { ... }
    },

    "node": {
        "type": "feature",
        "feature": { ... }
    },
    """

    if isinstance(node, capa.engine.Statement):
        return {
            "type": "statement",
            "statement": convert_statement_to_result_document(node),
        }
    elif isinstance(node, capa.features.Feature):
        return {
            "type": "feature",
            "feature": convert_feature_to_result_document(node),
        }
    else:
        raise RuntimeError("unexpected match node type")


def convert_match_to_result_document(rules, capabilities, result):
    """
    convert the given Result instance into a common, Python-native data structure.
    this will become part of the "result document" format that can be emitted to JSON.
    """
    doc = {
        "success": bool(result.success),
        "node": convert_node_to_result_document(result.statement),
        "children": [convert_match_to_result_document(rules, capabilities, child) for child in result.children],
    }

    # logic expression, like `and`, don't have locations - their children do.
    # so only add `locations` to feature nodes.
    if isinstance(result.statement, capa.features.Feature):
        if bool(result.success):
            doc["locations"] = result.locations
    elif isinstance(result.statement, capa.rules.Range):
        if bool(result.success):
            doc["locations"] = result.locations

    # if we have a `match` statement, then we're referencing another rule.
    # this could an external rule (written by a human), or
    #  rule generated to support a subscope (basic block, etc.)
    # we still want to include the matching logic in this tree.
    #
    # so, we need to lookup the other rule results
    # and then filter those down to the address used here.
    # finally, splice that logic into this tree.
    if (
        doc["node"]["type"] == "feature"
        and doc["node"]["feature"]["type"] == "match"
        # only add subtree on success,
        # because there won't be results for the other rule on failure.
        and doc["success"]
    ):

        rule_name = doc["node"]["feature"]["match"]
        rule = rules[rule_name]
        rule_matches = {address: result for (address, result) in capabilities[rule_name]}

        if rule.meta.get("capa/subscope-rule"):
            # for a subscope rule, fixup the node to be a scope node, rather than a match feature node.
            #
            # e.g. `contain loop/30c4c78e29bf4d54894fc74f664c62e8` -> `basic block`
            scope = rule.meta["scope"]
            doc["node"] = {
                "type": "statement",
                "statement": {
                    "type": "subscope",
                    "subscope": scope,
                },
            }

        for location in doc["locations"]:
            doc["children"].append(convert_match_to_result_document(rules, capabilities, rule_matches[location]))

    return doc


def convert_capabilities_to_result_document(meta, rules, capabilities):
    """
    convert the given rule set and capabilities result to a common, Python-native data structure.
    this format can be directly emitted to JSON, or passed to the other `render_*` routines
     to render as text.

    see examples of substructures in above routines.

    schema:

    ```json
    {
      "meta": {...},
      "rules: {
        $rule-name: {
          "meta": {...copied from rule.meta...},
          "matches: {
            $address: {...match details...},
            ...
          }
        },
        ...
      }
    }
    ```

    Args:
      meta (Dict[str, Any]):
      rules (RuleSet):
      capabilities (Dict[str, List[Tuple[int, Result]]]):
    """
    doc = {
        "meta": meta,
        "rules": {},
    }

    for rule_name, matches in capabilities.items():
        rule = rules[rule_name]

        if rule.meta.get("capa/subscope-rule"):
            continue

        doc["rules"][rule_name] = {
            "meta": dict(rule.meta),
            "source": rule.definition,
            "matches": {
                addr: convert_match_to_result_document(rules, capabilities, match) for (addr, match) in matches
            },
        }

    return doc


def render_vverbose(meta, rules, capabilities):
    # there's an import loop here
    # if capa.render imports capa.render.vverbose
    # and capa.render.vverbose import capa.render (implicitly, as a submodule)
    # so, defer the import until routine is called, breaking the import loop.
    import capa.render.vverbose

    doc = convert_capabilities_to_result_document(meta, rules, capabilities)
    return capa.render.vverbose.render_vverbose(doc)


def render_verbose(meta, rules, capabilities):
    # break import loop
    import capa.render.verbose

    doc = convert_capabilities_to_result_document(meta, rules, capabilities)
    return capa.render.verbose.render_verbose(doc)


def render_default(meta, rules, capabilities):
    # break import loop
    import capa.render.default
    import capa.render.verbose

    doc = convert_capabilities_to_result_document(meta, rules, capabilities)
    return capa.render.default.render_default(doc)


class CapaJsonObjectEncoder(json.JSONEncoder):
    """JSON encoder that emits Python sets as sorted lists"""

    def default(self, obj):
        if isinstance(obj, (list, dict, int, float, bool, type(None))) or isinstance(obj, six.string_types):
            return json.JSONEncoder.default(self, obj)
        elif isinstance(obj, set):
            return list(sorted(obj))
        else:
            # probably will TypeError
            return json.JSONEncoder.default(self, obj)


def render_json(meta, rules, capabilities):
    return json.dumps(
        convert_capabilities_to_result_document(meta, rules, capabilities),
        cls=CapaJsonObjectEncoder,
        sort_keys=True,
    )
