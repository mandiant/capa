# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import collections

import six
import tabulate

import capa.render.utils as rutils

tabulate.PRESERVE_WHITESPACE = True


def width(s, character_count):
    """pad the given string to at least `character_count`"""
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_meta(doc, ostream):
    rows = [
        (width("md5", 22), width(doc["meta"]["sample"]["md5"], 82)),
        ("sha1", doc["meta"]["sample"]["sha1"]),
        ("sha256", doc["meta"]["sample"]["sha256"]),
        ("path", doc["meta"]["sample"]["path"]),
    ]

    ostream.write(tabulate.tabulate(rows, tablefmt="psql"))
    ostream.write("\n")


def find_subrule_matches(doc):
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(node):
        if not node["success"]:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        elif node["node"]["type"] == "statement":
            for child in node["children"]:
                rec(child)

        elif node["node"]["type"] == "feature":
            if node["node"]["feature"]["type"] == "match":
                matches.add(node["node"]["feature"]["match"])

    for rule in rutils.capability_rules(doc):
        for node in rule["matches"].values():
            rec(node)

    return matches


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
    subrule_matches = find_subrule_matches(doc)

    rows = []
    for rule in rutils.capability_rules(doc):
        if rule["meta"]["name"] in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule["matches"])
        if count == 1:
            capability = rutils.bold(rule["meta"]["name"])
        else:
            capability = "%s (%d matches)" % (rutils.bold(rule["meta"]["name"]), count)
        rows.append((capability, rule["meta"]["namespace"]))

    if rows:
        ostream.write(
            tabulate.tabulate(rows, headers=[width("CAPABILITY", 50), width("NAMESPACE", 50)], tablefmt="psql")
        )
        ostream.write("\n")
    else:
        ostream.writeln(rutils.bold("no capabilities found"))


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
        rows.append(
            (
                rutils.bold(tactic.upper()),
                "\n".join(inner_rows),
            )
        )

    if rows:
        ostream.write(
            tabulate.tabulate(
                rows, headers=[width("ATT&CK Tactic", 20), width("ATT&CK Technique", 80)], tablefmt="psql"
            )
        )
        ostream.write("\n")


def render_mbc(doc, ostream):
    """
    example::

        +--------------------------+------------------------------------------------------------+
        | MBC Objective            | MBC Behavior                                               |
        |--------------------------+------------------------------------------------------------|
        | ANTI-BEHAVIORAL ANALYSIS | Virtual Machine Detection::Instruction Testing [B0009.029] |
        | COLLECTION               | Keylogging::Polling [F0002.002]                            |
        | COMMUNICATION            | Interprocess Communication::Create Pipe [C0003.001]        |
        |                          | Interprocess Communication::Write Pipe [C0003.004]         |
        | IMPACT                   | Remote Access::Reverse Shell [B0022.001]                   |
        +--------------------------+------------------------------------------------------------+
    """
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("mbc"):
            continue

        mbcs = rule["meta"]["mbc"]
        if not isinstance(mbcs, list):
            raise ValueError("invalid rule: MBC mapping is not a list")

        for mbc in mbcs:
            objective, _, rest = mbc.partition("::")
            if "::" in rest:
                behavior, _, rest = rest.partition("::")
                method, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, method, id))
            else:
                behavior, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, id))

    rows = []
    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for spec in sorted(behaviors):
            if len(spec) == 2:
                behavior, id = spec
                inner_rows.append("%s %s" % (rutils.bold(behavior), id))
            elif len(spec) == 3:
                behavior, method, id = spec
                inner_rows.append("%s::%s %s" % (rutils.bold(behavior), method, id))
            else:
                raise RuntimeError("unexpected MBC spec format")
        rows.append(
            (
                rutils.bold(objective.upper()),
                "\n".join(inner_rows),
            )
        )

    if rows:
        ostream.write(
            tabulate.tabulate(rows, headers=[width("MBC Objective", 25), width("MBC Behavior", 75)], tablefmt="psql")
        )
        ostream.write("\n")


def render_default(doc):
    ostream = rutils.StringIO()

    render_meta(doc, ostream)
    ostream.write("\n")
    render_attack(doc, ostream)
    ostream.write("\n")
    render_mbc(doc, ostream)
    ostream.write("\n")
    render_capabilities(doc, ostream)

    return ostream.getvalue()
