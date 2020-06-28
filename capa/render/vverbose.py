import tabulate

import capa.rules
import capa.render.utils as rutils


def render_statement(ostream, statement, indent=0):
    ostream.write('  ' * indent)
    if statement['type'] in ('and', 'or', 'optional'):
        ostream.write(statement['type'])
        ostream.writeln(':')
    elif statement['type'] == 'not':
        # we won't have successful results for the children of a not
        # so display a placeholder `...`
        ostream.writeln('not: ...')
    elif statement['type'] == 'some':
        ostream.write(statement['count'] + ' or more')
        ostream.writeln(':')
    elif statement['type'] == 'range':
        ostream.write('range(%d, %d)' % (statement['min'], statement['max']))
        ostream.writeln(':')
    elif statement['type'] == 'subscope':
        ostream.write(statement['subscope'])
        ostream.writeln(':')
    elif statement['type'] == 'regex':
        ostream.writeln('string: /%s/' % (statement['pattern']))
    else:
        raise RuntimeError("unexpected match statement type: " + str(statement))


def render_feature(ostream, match, feature, indent=0):
    ostream.write('  ' * indent)

    if feature['type'] in ('string', 'bytes', 'api', 'number', 'offset', 'mnemonic', 'basic block', 'export', 'import', 'section', 'match'):
        ostream.write(feature['type'])
        ostream.write(': ')
        ostream.write(rutils.bold2(feature[feature['type']]))
    elif feature['type'] == 'characteristic':
        ostream.write('characteristic(%s): %s' % (rutils.bold2(feature['characteristic'][0]), feature['characteristic'][1]))
    else:
        raise RuntimeError('unexpected feature type: ' + str(feature))

    if len(match['locations']) == 1:
        ostream.write(' @ ')
        ostream.write(rutils.hex(list(match['locations'])[0]))
    elif len(match['locations']) > 1:
        ostream.write(' @ ')
        ostream.write(', '.join(map(rutils.hex, sorted(match['locations']))))

    ostream.write('\n')


def render_node(ostream, match, node, indent=0):
    if node['type'] == 'statement':
        render_statement(ostream, node['statement'], indent=indent)
    elif node['type'] == 'feature':
        render_feature(ostream, match, node['feature'], indent=indent)
    else:
        raise RuntimeError('unexpected node type: ' + str(node))


def render_match(ostream, match, indent=0):
    if not match['success']:
        return

    if match['node'].get('statement', {}).get('type') == 'optional' and not any(map(lambda m: m['success'], match['children'])):
        return

    render_node(ostream, match, match['node'], indent=indent)

    for child in match['children']:
        render_match(ostream, child, indent=indent + 1)


def render_vverbose(doc):
    ostream = rutils.StringIO()

    for rule in rutils.capability_rules(doc):
        ostream.writeln(rutils.bold(rule['meta']['name']))

        rows = []
        for key in capa.rules.META_KEYS:
            if key == 'name' or key not in rule['meta']:
                continue

            v = rule['meta'][key]
            if isinstance(v, list) and len(v) == 1:
                v = v[0]
            elif isinstance(v, list) and len(v) > 1:
                v = ', '.join(v)
            rows.append((key, v))

        ostream.writeln(tabulate.tabulate(rows, tablefmt='plain'))

        if rule['meta']['scope'] == capa.rules.FILE_SCOPE:
            render_match(ostream, match, indent=0)
        else:
            for location, match in doc[rule['meta']['name']]['matches'].items():
                ostream.write(rule['meta']['scope'])
                ostream.write(' @ ')
                ostream.writeln(rutils.hex(location))
                render_match(ostream, match, indent=1)

        ostream.write('\n')

    return ostream.getvalue()
