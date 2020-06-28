import json

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
    if isinstance(statement, capa.engine.And):
        return {
            'type': 'and',
        }
    elif isinstance(statement, capa.engine.Or):
        return {
            'type': 'or',
        }
    elif isinstance(statement, capa.engine.Not):
        return {
            'type': 'not',
        }
    elif isinstance(statement, capa.engine.Or):
        return {
            'type': 'or',
        }
    elif isinstance(statement, capa.engine.Some) and statement.count == 0:
        return {
            'type': 'optional'
        }
    elif isinstance(statement, capa.engine.Some) and statement.count > 0:
        return {
            'type': 'some',
            'count': statement.count,
        }
    elif isinstance(statement, capa.engine.Range):
        return {
            'type': 'range',
            'min': statement.min,
            'max': statement.max,
        }
    elif isinstance(statement, capa.engine.Regex):
        return {
            'type': 'regex',
            'pattern': statement.pattern,
        }
    elif isinstance(statement, capa.engine.Subscope):
        return {
            'type': 'subscope',
            'subscope': statement.scope,
        }
    else:
        raise RuntimeError("unexpected match statement type: " + str(statement))


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
    name, value = feature.freeze_serialize()

    # make the terms pretty
    name = name.lower()
    if name == 'matchedrule':
        name = 'match'

    # in the common case, there's a single argument
    # so use it directly.
    # like: name=number value=1
    if isinstance(value, list) and len(value) == 1:
        value = value[0]

    return {
        'type': name,
        name: value,
    }


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
            'type': 'statement',
            'statement': convert_statement_to_result_document(node),
        }
    elif isinstance(node, capa.features.Feature):
        return {
            'type': 'feature',
            'feature': convert_feature_to_result_document(node),
        }
    else:
        raise RuntimeError("unexpected match node type")


def convert_match_to_result_document(rules, capabilities, result):
    """
    convert the given Result instance into a common, Python-native data structure.
    this will become part of the "result document" format that can be emitted to JSON.

    args:
      rules (RuleSet):
      result (Result):

    returns: Dict[str, Any]
    """
    doc = {
        'success': bool(result.success),
        'node': convert_node_to_result_document(result.statement),
        'children': [
            convert_match_to_result_document(rules, capabilities, child)
            for child in result.children
        ],
    }

    # logic expression, like `and`, don't have locations - their children do.
    # so only add `locations` to feature nodes.
    if isinstance(result.statement, capa.features.Feature):
        if bool(result.success):
            doc['locations'] = result.locations

    # if we have a `match` statement, then we're referencing another rule.
    # this could an external rule (written by a human), or
    #  rule generated to support a subscope (basic block, etc.)
    # we still want to include the matching logic in this tree.
    #
    # so, we need to lookup the other rule results
    # and then filter those down to the address used here.
    # finally, splice that logic into this tree.
    if (doc['node']['type'] == 'feature'
            and doc['node']['feature']['type'] == 'match'
            # only add subtree on success,
            # because there won't be results for the other rule on failure.
            and doc['success']):

        rule_name = doc['node']['feature']['match']
        rule = rules[rule_name]
        rule_matches = {address: result for (address, result) in capabilities[rule_name]}

        if rule.meta.get('capa/subscope-rule'):
            # for a subscope rule, fixup the node to be a scope node, rather than a match feature node.
            #
            # e.g. `contain loop/30c4c78e29bf4d54894fc74f664c62e8` -> `basic block`
            scope = rule.meta['scope']
            doc['node'] = {
                'type': 'statement',
                'statement': {
                    'type': 'subscope',
                    'subscope': scope,
                },
            }

        for location in doc['locations']:
            doc['children'].append(convert_match_to_result_document(rules, capabilities, rule_matches[location]))

    return doc


def convert_capabilities_to_result_document(rules, capabilities):
    """
    convert the given rule set and capabilities result to a common, Python-native data structure.
    this format can be directly emitted to JSON, or passed to the other `render_*` routines
     to render as text.

    see examples of substructures in above routines.

    schema:

    ```json
    {
      $rule-name: {
        "meta": {...copied from rule.meta...},
        "matches: {
          $address: {...match details...},
          ...
        }
      },
      ...
    }
    ```

    Args:
      rules (RuleSet):
      capabilities (Dict[str, List[Tuple[int, Result]]]):
    """
    doc = {}

    for rule_name, matches in capabilities.items():
        rule = rules[rule_name]

        if rule.meta.get('capa/subscope-rule'):
            continue

        doc[rule_name] = {
            'meta': dict(rule.meta),
            'matches': {
                addr: convert_match_to_result_document(rules, capabilities, match)
                for (addr, match) in matches
            },
        }

    return doc


def render_vverbose(rules, capabilities):
    import capa.render.vverbose
    doc = convert_capabilities_to_result_document(rules, capabilities)
    return capa.render.vverbose.render_vverbose(doc)


def render_verbose(rules, capabilities):
    import capa.render.verbose
    doc = convert_capabilities_to_result_document(rules, capabilities)
    return capa.render.verbose.render_verbose(doc)


def render_default(rules, capabilities):
    import capa.render.default
    doc = convert_capabilities_to_result_document(rules, capabilities)
    return capa.render.default.render_default(doc)


class CapaJsonObjectEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (list, dict, str, unicode, int, float, bool, type(None))):
            return json.JSONEncoder.default(self, obj)
        elif isinstance(obj, set):
            return list(sorted(obj))
        else:
            # probably will TypeError
            return json.JSONEncoder.default(self, obj)


def render_json(rules, capabilities):
    return json.dumps(
        convert_capabilities_to_result_document(rules, capabilities),
        cls=CapaJsonObjectEncoder,
        sort_keys=True,
    )
