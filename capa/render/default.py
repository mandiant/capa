# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import collections

import tabulate

import capa.render.utils as rutils
import capa.features.freeze as frz
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.rules import RuleSet
from capa.engine import MatchResults
from capa.render.utils import StringIO

tabulate.PRESERVE_WHITESPACE = True


def width(s: str, character_count: int) -> str:
    """pad the given string to at least `character_count`"""
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_meta(doc: rd.ResultDocument, ostream: StringIO):
    rows = [
        (width("md5", 22), width(doc.meta.sample.md5, 82)),
        ("sha1", doc.meta.sample.sha1),
        ("sha256", doc.meta.sample.sha256),
        ("os", doc.meta.analysis.os),
        ("format", doc.meta.analysis.format),
        ("arch", doc.meta.analysis.arch),
        ("path", doc.meta.sample.path),
    ]

    ostream.write(tabulate.tabulate(rows, tablefmt="psql"))
    ostream.write("\n")


def find_subrule_matches(doc: rd.ResultDocument):
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(match: rd.Match):
        if not match.success:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        elif isinstance(match.node, rd.StatementNode):
            for child in match.children:
                rec(child)

        elif isinstance(match.node, rd.FeatureNode) and isinstance(match.node.feature, frzf.MatchFeature):
            matches.add(match.node.feature.match)

    for rule in rutils.capability_rules(doc):
        for address, match in rule.matches:
            rec(match)

    return matches


def render_capabilities(doc: rd.ResultDocument, ostream: StringIO):
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
        if rule.meta.name in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule.matches)
        if count == 1:
            capability = rutils.bold(rule.meta.name)
        else:
            capability = f"{rutils.bold(rule.meta.name)} ({count} matches)"
        rows.append((capability, rule.meta.namespace))

    if rows:
        ostream.write(
            tabulate.tabulate(rows, headers=[width("CAPABILITY", 50), width("NAMESPACE", 50)], tablefmt="psql")
        )
        ostream.write("\n")
    else:
        ostream.writeln(rutils.bold("no capabilities found"))


def render_attack(doc: rd.ResultDocument, ostream: StringIO):
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
        for attack in rule.meta.attack:
            tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id))

    rows = []
    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for technique, subtechnique, id in sorted(techniques):
            if not subtechnique:
                inner_rows.append(f"{rutils.bold(technique)} {id}")
            else:
                inner_rows.append(f"{rutils.bold(technique)}::{subtechnique} {id}")
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


def render_mbc(doc: rd.ResultDocument, ostream: StringIO):
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
        for mbc in rule.meta.mbc:
            objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id))

    rows = []
    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for behavior, method, id in sorted(behaviors):
            if not method:
                inner_rows.append(f"{rutils.bold(behavior)} [{id}]")
            else:
                inner_rows.append(f"{rutils.bold(behavior)}::{method} [{id}]")
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


def render_default(doc: rd.ResultDocument):
    ostream = rutils.StringIO()

    render_meta(doc, ostream)
    ostream.write("\n")
    render_attack(doc, ostream)
    ostream.write("\n")
    render_mbc(doc, ostream)
    ostream.write("\n")
    render_capabilities(doc, ostream)

    return ostream.getvalue()


def render(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    return render_default(doc)
