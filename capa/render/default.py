import collections

import six
import tabulate

import capa.render.utils as rutils


def render_capabilities(doc, ostream):
    """
    example::

        +-------------------------------------------------------+-------------------------------------------------+
        | CAPABILITY                                            | NAMESPACE                                       |
        |-------------------------------------------------------+-------------------------------------------------|
        | check for OutputDebugString error                     | anti-analysis/anti-debugging/debugger-detection |
        | read and send data from client to server              | c2/file-transfer                                |
        | ...                                                   | ...                                             |
        +-------------------------------------------------------+-------------------------------------------------+
    """
    rows = []
    for rule in rutils.capability_rules(doc):
        rows.append((rutils.bold(rule['meta']['name']), rule['meta']['namespace']))

    ostream.write(tabulate.tabulate(rows, headers=['CAPABILITY', 'NAMESPACE'], tablefmt="psql"))
    ostream.write("\n")


def render_attack(doc, ostream):
    """
    example::

        +----------------------------------------------------------------------+
        | ATT&CK tactic: EXECUTION                                             |
        |----------------------------------------------------------------------|
        | Command and Scripting Interpreter::Windows Command Shell [T1059.003] |
        | Shared Modules [T1129]                                               |
        | ...                                                                  |
        +----------------------------------------------------------------------+
    """
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
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
                rows.append(("%s %s" % (rutils.bold(technique), id), ))
            elif len(spec) == 3:
                technique, subtechnique, id = spec
                rows.append(("%s::%s %s" % (rutils.bold(technique), subtechnique, id), ))
            else:
                raise RuntimeError("unexpected ATT&CK spec format")
        ostream.write(tabulate.tabulate(rows, headers=['ATT&CK tactic: ' + rutils.bold(tactic.upper())], tablefmt="psql"))
        ostream.write("\n")


def render_default(doc):
    ostream = six.StringIO()

    render_attack(doc, ostream)
    ostream.write("\n")
    render_capabilities(doc, ostream)

    return ostream.getvalue()
