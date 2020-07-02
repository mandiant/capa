import tabulate

import capa.rules
import capa.render.utils as rutils


def render_locations(ostream, match):
    # its possible to have an empty locations array here,
    # such as when we're in MODE_FAILURE and showing the logic
    # under a `not` statement (which will have no matched locations).
    locations = list(sorted(match.get('locations', [])))
    if len(locations) == 1:
        ostream.write(' @ ')
        ostream.write(rutils.hex(locations[0]))
    elif len(locations) > 1:
        ostream.write(' @ ')
        if len(locations) > 4:
            # don't display too many locations, because it becomes very noisy.
            # probably only the first handful of locations will be useful for inspection.
            ostream.write(', '.join(map(rutils.hex, locations[0:4])))
            ostream.write(', and %d more...' % (len(locations) - 4))
        else:
            ostream.write(', '.join(map(rutils.hex, locations)))


def render_statement(ostream, match, statement, indent=0):
    ostream.write('  ' * indent)
    if statement['type'] in ('and', 'or', 'optional'):
        ostream.write(statement['type'])
        ostream.writeln(':')
    elif statement['type'] == 'not':
        # this statement is handled specially in `render_match` using the MODE_SUCCESS/MODE_FAILURE flags.
        ostream.writeln("not:")
    elif statement["type"] == "some":
        ostream.write(statement["count"] + " or more")
        ostream.writeln(":")
    elif statement["type"] == "range":
        # `range` is a weird node, its almost a hybrid of statement+feature.
        # it is a specific feature repeated multiple times.
        # there's no additional logic in the feature part, just the existence of a feature.
        # so, we have to inline some of the feature rendering here.

        child = statement['child']
        if child['type'] in ('string', 'api', 'mnemonic', 'basic block', 'export', 'import', 'section', 'match', 'characteristic'):
            value = rutils.bold2(child[child['type']])
        elif child['type'] in ('number', 'offset'):
            value = rutils.bold2(rutils.hex(child[child['type']]))
        elif child['type'] == 'bytes':
            value = rutils.bold2(rutils.hex_string(child[child['type']]))
        else:
            raise RuntimeError("unexpected feature type: " + str(child))

        if child['description']:
            ostream.write('count(%s(%s = %s)): ' % (child['type'], value, child['description']))
        else:
            ostream.write('count(%s(%s)): ' % (child['type'], value))

        if statement['max'] == statement['min']:
            ostream.write('%d' % (statement['min']))
        elif statement['min'] == 0:
            ostream.write('%d or fewer' % (statement['max']))
        elif statement['max'] == (1 << 64 - 1):
            ostream.write('%d or more' % (statement['min']))
        else:
            ostream.write('between %d and %d' % (statement['min'], statement['max']))

        render_locations(ostream, match)
        ostream.write('\n')
    elif statement['type'] == 'subscope':
        ostream.write(statement['subscope'])
        ostream.writeln(':')
    elif statement['type'] == 'regex':
        # regex is a `Statement` not a `Feature`
        # this is because it doesn't get extracted, but applies to all strings in scope.
        # so we have to handle it here
        ostream.writeln("string: %s" % (statement["match"]))
    else:
        raise RuntimeError("unexpected match statement type: " + str(statement))


def render_feature(ostream, match, feature, indent=0):
    ostream.write('  ' * indent)

    if feature['type'] in ('string', 'api', 'mnemonic', 'basic block', 'export', 'import', 'section', 'match', 'characteristic'):
        ostream.write(feature['type'])
        ostream.write(': ')
        ostream.write(rutils.bold2(feature[feature['type']]))
    elif feature['type'] in ('number', 'offset'):
        ostream.write(feature['type'])
        ostream.write(': ')
        ostream.write(rutils.bold2(rutils.hex(feature[feature['type']])))
    elif feature['type'] == 'bytes':
        ostream.write('bytes: ')
        # bytes is the uppercase, hex-encoded string.
        # it should always be an even number of characters (its hex).
        ostream.write(rutils.bold2(rutils.hex_string(feature[feature['type']])))
    # note that regex is found in `render_statement`
    else:
        raise RuntimeError("unexpected feature type: " + str(feature))

    if 'description' in feature:
        ostream.write(' = ')
        ostream.write(feature['description'])

    render_locations(ostream, match)
    ostream.write('\n')


def render_node(ostream, match, node, indent=0):
    if node['type'] == 'statement':
        render_statement(ostream, match, node['statement'], indent=indent)
    elif node['type'] == 'feature':
        render_feature(ostream, match, node['feature'], indent=indent)
    else:
        raise RuntimeError("unexpected node type: " + str(node))


# display nodes that successfully evaluated against the sample.
MODE_SUCCESS = "success"

# display nodes that did not evaluate to True against the sample.
# this is useful when rendering the logic tree under a `not` node.
MODE_FAILURE = "failure"


def render_match(ostream, match, indent=0, mode=MODE_SUCCESS):
    child_mode = mode
    if mode == MODE_SUCCESS:
        # display only nodes that evaluated successfully.
        if not match["success"]:
            return
        # optional statement with no successful children is empty
        if match["node"].get("statement", {}).get("type") == "optional" and not any(
            map(lambda m: m["success"], match["children"])
        ):
            return
        # not statement, so invert the child mode to show failed evaluations
        if match["node"].get("statement", {}).get("type") == "not":
            child_mode = MODE_FAILURE
    elif mode == MODE_FAILURE:
        # display only nodes that did not evaluate to True
        if match["success"]:
            return
        # optional statement with successful children is not relevant
        if match["node"].get("statement", {}).get("type") == "optional" and any(
            map(lambda m: m["success"], match["children"])
        ):
            return
        # not statement, so invert the child mode to show successful evaluations
        if match["node"].get("statement", {}).get("type") == "not":
            child_mode = MODE_SUCCESS
    else:
        raise RuntimeError("unexpected mode: " + mode)

    render_node(ostream, match, match["node"], indent=indent)

    for child in match["children"]:
        render_match(ostream, child, indent=indent + 1, mode=child_mode)


def render_vverbose(doc):
    ostream = rutils.StringIO()

    for rule in rutils.capability_rules(doc):
        count = len(rule["matches"])
        if count == 1:
            capability = rutils.bold(rule["meta"]["name"])
        else:
            capability = "%s (%d matches)" % (rutils.bold(rule["meta"]["name"]), count)

        ostream.writeln(capability)

        rows = []
        for key in capa.rules.META_KEYS:
            if key == "name" or key not in rule["meta"]:
                continue

            v = rule["meta"][key]
            if isinstance(v, list) and len(v) == 1:
                v = v[0]
            elif isinstance(v, list) and len(v) > 1:
                v = ", ".join(v)
            rows.append((key, v))

        ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))

        if rule["meta"]["scope"] == capa.rules.FILE_SCOPE:
            matches = list(doc[rule["meta"]["name"]]["matches"].values())
            if len(matches) != 1:
                # i think there should only ever be one match per file-scope rule,
                # because we do the file-scope evaluation a single time.
                # but i'm not 100% sure if this is/will always be true.
                # so, lets be explicit about our assumptions and raise an exception if they fail.
                raise RuntimeError("unexpected file scope match count: " + len(matches))
            render_match(ostream, matches[0], indent=0)
        else:
            for location, match in sorted(doc[rule["meta"]["name"]]["matches"].items()):
                ostream.write(rule["meta"]["scope"])
                ostream.write(" @ ")
                ostream.writeln(rutils.hex(location))
                render_match(ostream, match, indent=1)

        ostream.write("\n")

    return ostream.getvalue()
