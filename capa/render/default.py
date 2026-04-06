# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import io
import collections
import urllib.parse

import rich
import rich.table
import rich.console
from rich.console import Console

import capa.render.utils as rutils
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.rules import RuleSet
from capa.engine import MatchResults


def bold_markup(s) -> str:
    """
    Generate Rich markup in a bold style.

    The resulting string should be passed to a Rich renderable
    and/or printed via Rich or the markup will be visible to the user.
    """
    return f"[cyan]{s}[/cyan]"


def link_markup(s: str, href: str) -> str:
    """
    Generate Rich markup for a clickable hyperlink.
    This works in many modern terminals.
    When it doesn't work, the fallback is just to show the link name (s),
     as if it was not a link.

    The resulting string should be passed to a Rich renderable
    and/or printed via Rich or the markup will be visible to the user.
    """
    return f"[link={href}]{s}[/link]"


def width(s: str, character_count: int) -> str:
    """pad the given string to at least `character_count`"""
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_sample_link(hash: str) -> str:
    url = "https://www.virustotal.com/gui/file/" + hash
    return link_markup(hash, url)


def render_meta(doc: rd.ResultDocument, console: Console):
    rows = [
        ("md5", render_sample_link(doc.meta.sample.md5)),
        ("sha1", render_sample_link(doc.meta.sample.sha1)),
        ("sha256", render_sample_link(doc.meta.sample.sha256)),
        ("analysis", doc.meta.flavor.value),
        ("os", doc.meta.analysis.os),
        ("format", doc.meta.analysis.format),
        ("arch", doc.meta.analysis.arch),
        ("path", doc.meta.sample.path),
    ]

    table = rich.table.Table(show_header=False, min_width=100)
    table.add_column()
    table.add_column()

    for row in rows:
        table.add_row(*row)

    console.print(table)


def find_subrule_matches(doc: rd.ResultDocument):
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set()

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
        for _, match in rule.matches:
            rec(match)

    return matches


def render_rule_name(name: str) -> str:
    url = f"https://mandiant.github.io/capa/rules/{urllib.parse.quote(name)}/"
    return bold_markup(link_markup(name, url))


def render_capabilities(doc: rd.ResultDocument, console: Console):
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
            capability = render_rule_name(rule.meta.name)
        else:
            capability = render_rule_name(rule.meta.name) + f" ({count} matches)"
        rows.append((capability, rule.meta.namespace))

    if rows:
        table = rich.table.Table(min_width=100)
        table.add_column(width("Capability", 20))
        table.add_column("Namespace")

        for row in rows:
            table.add_row(*row)

        console.print(table)
    else:
        console.print(bold_markup("no capabilities found"))


def render_attack_link(id: str) -> str:
    url = f"https://attack.mitre.org/techniques/{id.replace('.', '/')}/"
    return rf"\[{link_markup(id, url)}]"


def render_attack(doc: rd.ResultDocument, console: Console):
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
            tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id.strip("[").strip("]")))

    rows = []
    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for technique, subtechnique, id in sorted(techniques):
            if not subtechnique:
                # example: File and Directory Discovery [T1083]
                inner_rows.append(f"{bold_markup(technique)} {render_attack_link(id)}")
            else:
                # example: Code Discovery::Enumerate PE Sections [T1084.001]
                inner_rows.append(f"{bold_markup(technique)}::{subtechnique} {render_attack_link(id)}")

        tactic = bold_markup(tactic.upper())
        technique = "\n".join(inner_rows)

        rows.append((tactic, technique))

    if rows:
        table = rich.table.Table(min_width=100)
        table.add_column(width("ATT&CK Tactic", 20))
        table.add_column("ATT&CK Technique")

        for row in rows:
            table.add_row(*row)

        console.print(table)


def render_maec(doc: rd.ResultDocument, console: Console):
    """
    example::

        +--------------------------+-----------------------------------------------------------+
        | MAEC Category            | MAEC Value                                                |
        |--------------------------+-----------------------------------------------------------|
        | analysis-conclusion      | malicious                                                 |
        |--------------------------+-----------------------------------------------------------|
        | malware-family           | PlugX                                                     |
        |--------------------------+-----------------------------------------------------------|
        | malware-category         | downloader                                                |
        |                          | launcher                                                  |
        +--------------------------+-----------------------------------------------------------+
    """
    maec_categories = {
        "analysis_conclusion",
        "analysis_conclusion_ov",
        "malware_family",
        "malware_category",
        "malware_category_ov",
    }
    maec_table = collections.defaultdict(set)
    for rule in rutils.maec_rules(doc):
        for maec_category in maec_categories:
            maec_value = getattr(rule.meta.maec, maec_category, None)
            if maec_value:
                maec_table[maec_category].add(maec_value)

    rows = []
    for category in sorted(maec_categories):
        values = maec_table.get(category, set())
        if values:
            rows.append((bold_markup(category.replace("_", "-")), "\n".join(sorted(values))))

    if rows:
        table = rich.table.Table(min_width=100)
        table.add_column(width("MAEC Category", 20))
        table.add_column("MAEC Value")

        for row in rows:
            table.add_row(*row)

        console.print(table)


def render_mbc_link(id: str, objective: str, behavior: str) -> str:
    if id[0] in {"B", "T", "E", "F"}:
        # behavior
        base_url = "https://github.com/MBCProject/mbc-markdown/blob/main"
    elif id[0] == "C":
        # micro-behavior
        base_url = "https://github.com/MBCProject/mbc-markdown/blob/main/micro-behaviors"
    else:
        raise ValueError("unexpected MBC prefix")

    objective_fragment = objective.lower().replace(" ", "-")
    behavior_fragment = behavior.lower().replace(" ", "-")

    url = f"{base_url}/{objective_fragment}/{behavior_fragment}.md"
    return rf"\[{link_markup(id, url)}]"


def render_mbc(doc: rd.ResultDocument, console: Console):
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
            objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id.strip("[").strip("]")))

    rows = []
    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for technique, subtechnique, id in sorted(behaviors):
            if not subtechnique:
                # example: File and Directory Discovery [T1083]
                inner_rows.append(f"{bold_markup(technique)} {render_mbc_link(id, objective, technique)}")
            else:
                # example: Code Discovery::Enumerate PE Sections [T1084.001]
                inner_rows.append(
                    f"{bold_markup(technique)}::{subtechnique} {render_mbc_link(id, objective, technique)}"
                )

        objective = bold_markup(objective.upper())
        technique = "\n".join(inner_rows)

        rows.append((objective, technique))

    if rows:
        table = rich.table.Table(min_width=100)
        table.add_column(width("MBC Objective", 20))
        table.add_column("MBC Behavior")

        for row in rows:
            table.add_row(*row)

        console.print(table)


def render_default(doc: rd.ResultDocument):
    f = io.StringIO()
    console = rich.console.Console()

    render_meta(doc, console)
    render_attack(doc, console)
    render_maec(doc, console)
    render_mbc(doc, console)
    render_capabilities(doc, console)

    return f.getvalue()


def render(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    return render_default(doc)
