import collections

import six
import tabulate

import capa.render.utils as rutils


def width(s, character_count):
    """pad the given string to at least `character_count`"""
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_capabilities(doc, ostream):
    """
    example::

        +-------------------------------------------------------+-------------------------------------------------+
        | CAPABILITY                                            | NAMESPACE                                       |
        |-------------------------------------------------------+-------------------------------------------------|
        | check for OutputDebugString error (2 matches)         | anti-analysis/anti-debugging/debugger-detection |
        | read and send data from client to server              | c2/file-transfer                                |
        | ...                                                   | ...                                             |
        +-------------------------------------------------------+-------------------------------------------------+
    """
    rows = []
    for rule in rutils.capability_rules(doc):
        count = len(rule["matches"])
        if count == 1:
            capability = rutils.bold(rule["meta"]["name"])
        else:
            capability = "%s (%d matches)" % (rutils.bold(rule["meta"]["name"]), count)
        rows.append((capability, rule["meta"]["namespace"]))

    ostream.write(tabulate.tabulate(rows, headers=[width("CAPABILITY", 40), width("NAMESPACE", 40)], tablefmt="psql"))
    ostream.write("\n")


def render_attack(doc, ostream):
    """
    example::

        +------------------------+----------------------------------------------------------------------+
        | ATT&CK Tactic          | ATT&CK Technique                                                     |
        |------------------------+----------------------------------------------------------------------|
        | DEFENSE EVASION        | Obfuscated Files or Information [T1027]                              |
        | DISCOVERY              | Query Registry [T1012]                                               |
        |                        | System Information Discovery [T1082]                                 |
        | EXECUTION              | Command and Scripting Interpreter::Windows Command Shell [T1059.003] |
        |                        | Shared Modules [T1129]                                               |
        | EXFILTRATION           | Exfiltration Over C2 Channel [T1041]                                 |
        | PERSISTENCE            | Create or Modify System Process::Windows Service [T1543.003]         |
        +------------------------+----------------------------------------------------------------------+
    """
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("att&ck"):
            continue

        for attack in rule["meta"]["att&ck"]:
            tactic, _, rest = attack.partition("::")
            if "::" in rest:
                technique, _, rest = rest.partition("::")
                subtechnique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, subtechnique, id))
            else:
                technique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, id))

    rows = []
    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for spec in sorted(techniques):
            if len(spec) == 2:
                technique, id = spec
                inner_rows.append("%s %s" % (rutils.bold(technique), id))
            elif len(spec) == 3:
                technique, subtechnique, id = spec
                inner_rows.append("%s::%s %s" % (rutils.bold(technique), subtechnique, id))
            else:
                raise RuntimeError("unexpected ATT&CK spec format")
        rows.append((rutils.bold(tactic.upper()), "\n".join(inner_rows),))
    ostream.write(
        tabulate.tabulate(rows, headers=[width("ATT&CK Tactic", 20), width("ATT&CK Technique", 60)], tablefmt="psql")
    )
    ostream.write("\n")


def render_default(doc):
    ostream = six.StringIO()

    render_attack(doc, ostream)
    ostream.write("\n")
    render_capabilities(doc, ostream)

    return ostream.getvalue()
