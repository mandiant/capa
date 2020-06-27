import collections

import six
import tabulate
import termcolor


def bold(s):
    """draw attention to the given string"""
    return termcolor.colored(s, 'blue')


def render_capabilities(doc, ostream):
    rows = []
    for (namespace, name, rule) in sorted(map(lambda rule: (rule['meta']['namespace'], rule['meta']['name'], rule), doc.values())):
        if rule['meta'].get('lib'):
            continue
        if rule['meta'].get('capa/subscope'):
            continue

        rows.append((bold(name), namespace))

    ostream.write(tabulate.tabulate(rows, headers=['CAPABILITY', 'NAMESPACE'], tablefmt="psql"))
    ostream.write("\n")


def render_attack(doc, ostream):
    tactics = collections.defaultdict(set)
    for rule in doc.values():
        if rule['meta'].get('lib'):
            continue
        if rule['meta'].get('capa/subscope'):
            continue
        if not rule['meta'].get('att&ck'):
            continue

        for attack in rule['meta']['att&ck']:
            tactic, _, rest = attack.partition('::')
            if '::' in rest:
                technique, _, rest = rest.partition('::')
                subtechnique, _, id = rest.rpartition(' ')
                tactics[tactic].add((technique, subtechnique, id))
            else:
                technique, _, id = rest.rpartition(' ')
                tactics[tactic].add((technique, id))

    for tactic, techniques in sorted(tactics.items()):
        rows = []
        for spec in sorted(techniques):
            if len(spec) == 2:
                technique, id = spec
                rows.append(("%s %s" % (bold(technique), id), ))
            elif len(spec) == 3:
                technique, subtechnique, id = spec
                rows.append(("%s::%s %s" % (bold(technique), subtechnique, id), ))
            else:
                raise RuntimeError("unexpected ATT&CK spec format")
        ostream.write(tabulate.tabulate(rows, headers=['ATT&CK tactic: ' + bold(tactic.upper())], tablefmt="psql"))
        ostream.write("\n")


def render_default(doc):
    ostream = six.StringIO()

    render_attack(doc, ostream)
    ostream.write("\n")
    render_capabilities(doc, ostream)

    return ostream.getvalue()
