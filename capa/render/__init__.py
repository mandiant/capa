import json

import capa.engine


def convert_statement_to_result_document(rules, statement):
    """
    args:
      rules (RuleSet):
      node (Statement):

    returns: Dict[str, Any]
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
            'scope': statement.scope,
        }
    else:
        raise RuntimeError("unexpected match statement type: " + str(statement))


def convert_feature_to_result_document(rules, feature):
    """
    args:
      rules (RuleSet):
      node (Feature):

    returns: Dict[str, Any]
    """
    name, value = feature.freeze_serialize()

    name = name.lower()
    if name == 'matchedrule':
        name = 'match'

    if isinstance(value, list) and len(value) == 1:
        value = value[0]

    if name == 'match':
        rule_name = value
        rule = rules[rule_name]
        if rule.meta.get('capa/subscope-rule'):
            name = rule.meta['scope']
            # TODO: link this logic together, when present

    return {
        'type': name,
        name: value,
    }


def convert_node_to_result_document(rules, node):
    """

    args:
      rules (RuleSet):
      node (Statement|Feature):

    returns: Dict[str, Any]
    """

    if isinstance(node, capa.engine.Statement):
        return {
            'type': 'statement',
            'statement': convert_statement_to_result_document(rules, node),
        }
    elif isinstance(node, capa.features.Feature):
        return {
            'type': 'feature',
            'feature': convert_feature_to_result_document(rules, node),
        }
    else:
        raise RuntimeError("unexpected match node type")


def convert_match_to_result_document(rules, result):
    """
    convert the given rule set and Result instance into a common, Python-native data structure.
    this will become part of the "result document" format that can be emitted to JSON.

    args:
      rules (RuleSet):
      result (Result):

    returns: Dict[str, Any]
    """
    doc = {
        'success': bool(result.success),
        'node': convert_node_to_result_document(rules, result.statement),
        'children': [
            convert_match_to_result_document(rules, child)
            for child in result.children
        ],
    }

    if isinstance(result.statement, capa.features.Feature):
        if bool(result.success):
            doc['locations'] = result.locations

    # TODO: can a feature ever have children? suspect so with `match`?

    return doc


def convert_capabilities_to_result_document(rules, capabilities):
    """
    convert the given rule set and capabilties result to a common, Python-native data structure.
    this format can be directly emitted to JSON, or passed to the other `render_*` routines
     to render as text.

     TODO: document the structure and provide examples

    schema:

    ```json
    {
      $rule-name: {
        "meta": {...copied from rule.meta...},
        "matches: {
          $address: {...TODO: match details...},
          ...
        }
      },
      ...
    }
    ```

    args:
      rules (RuleSet):
      capabilities (Dict[str, List[Tuple[int, Result]]]):

    returns: Dict[str, Any]
    """
    doc = {}

    for rule_name, matches in capabilities.items():
        rule = rules[rule_name]

        if rule.meta.get('capa/subscope-rule'):
            continue

        doc[rule_name] = {
            'meta': dict(rule.meta),
            'matches': {
                addr: convert_match_to_result_document(rules, match)
                for (addr, match) in matches
            },
        }

    return doc


def render_vverbose(rules, capabilities):
    doc = convert_capabilities_to_result_document(rules, capabilities)
    return ''


def render_verbose(rules, capabilities):
    doc = convert_capabilities_to_result_document(rules, capabilities)
    return ''


def render_default(rules, capabilities):
    doc = convert_capabilities_to_result_document(rules, capabilities)
    return ''


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
        indent=4,
    )
