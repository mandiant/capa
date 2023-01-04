#!/usr/bin/env python3

import json
import collections
from typing import Any, Dict

import capa.main
import capa.rules
import capa.engine
import capa.features
import capa.render.json
import capa.render.utils as rutils
import capa.render.default
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.engine import *


# == Render dictionary helpers
def render_meta(doc: rd.ResultDocument, result):
    result["md5"] = doc.meta.sample.md5
    result["sha1"] = doc.meta.sample.sha1
    result["sha256"] = doc.meta.sample.sha256
    result["path"] = doc.meta.sample.path


def find_subrule_matches(doc: rd.ResultDocument) -> Set[str]:
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(node: rd.Match):
        if not node.success:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        elif isinstance(node.node, rd.StatementNode):
            for child in node.children:
                rec(child)

        elif isinstance(node.node, rd.FeatureNode):
            if isinstance(node.node.feature, frzf.MatchFeature):
                matches.add(node.node.feature.match)

    for rule in rutils.capability_rules(doc):
        for _, node in rule.matches:
            rec(node)

    return matches


def render_capabilities(doc: rd.ResultDocument, result):
    """
    example::
        {'CAPABILITY': {'accept command line arguments': 'host-interaction/cli',
                'allocate thread local storage (2 matches)': 'host-interaction/process',
                'check for time delay via GetTickCount': 'anti-analysis/anti-debugging/debugger-detection',
                'check if process is running under wine': 'anti-analysis/anti-emulation/wine',
                'contain a resource (.rsrc) section': 'executable/pe/section/rsrc',
                'write file (3 matches)': 'host-interaction/file-system/write'}
        }
    """
    subrule_matches = find_subrule_matches(doc)

    result["CAPABILITY"] = dict()
    for rule in rutils.capability_rules(doc):
        if rule.meta.name in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule.matches)
        if count == 1:
            capability = rule.meta.name
        else:
            capability = "%s (%d matches)" % (rule.meta.name, count)

        result["CAPABILITY"].setdefault(rule.meta.namespace, list())
        result["CAPABILITY"][rule.meta.namespace].append(capability)


def render_attack(doc, result):
    """
    example::
        {'ATT&CK': {'COLLECTION': ['Input Capture::Keylogging [T1056.001]'],
            'DEFENSE EVASION': ['Obfuscated Files or Information [T1027]',
                                'Virtualization/Sandbox Evasion::System Checks '
                                '[T1497.001]'],
            'DISCOVERY': ['File and Directory Discovery [T1083]',
                          'Query Registry [T1012]',
                          'System Information Discovery [T1082]'],
            'EXECUTION': ['Shared Modules [T1129]']}
        }
    """
    result["ATTCK"] = dict()
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.attack:
            continue
        for attack in rule.meta.attack:
            tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id))

    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for (technique, subtechnique, id) in sorted(techniques):
            if subtechnique is None:
                inner_rows.append("%s %s" % (technique, id))
            else:
                inner_rows.append("%s::%s %s" % (technique, subtechnique, id))
        result["ATTCK"].setdefault(tactic.upper(), inner_rows)


def render_mbc(doc, result):
    """
    example::
        {'MBC': {'ANTI-BEHAVIORAL ANALYSIS': ['Debugger Detection::Timing/Delay Check '
                                      'GetTickCount [B0001.032]',
                                      'Emulator Detection [B0004]',
                                      'Virtual Machine Detection::Instruction '
                                      'Testing [B0009.029]',
                                      'Virtual Machine Detection [B0009]'],
         'COLLECTION': ['Keylogging::Polling [F0002.002]'],
         'CRYPTOGRAPHY': ['Encrypt Data::RC4 [C0027.009]',
                          'Generate Pseudo-random Sequence::RC4 PRGA '
                          '[C0021.004]']}
        }
    """
    result["MBC"] = dict()
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.mbc:
            continue

        for mbc in rule.meta.mbc:
            objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id))

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for (behavior, method, id) in sorted(behaviors):
            if method is None:
                inner_rows.append("%s [%s]" % (behavior, id))
            else:
                inner_rows.append("%s::%s [%s]" % (behavior, method, id))
        result["MBC"].setdefault(objective.upper(), inner_rows)


def render_dictionary(doc: rd.ResultDocument) -> Dict[str, Any]:
    result: Dict[str, Any] = dict()
    render_meta(doc, result)
    render_attack(doc, result)
    render_mbc(doc, result)
    render_capabilities(doc, result)

    return result


# ==== render dictionary helpers
def capa_details(rules_path, file_path, output_format="dictionary"):
    # load rules from disk
    rules = capa.rules.RuleSet(capa.main.get_rules([rules_path], disable_progress=True))

    # extract features and find capabilities
    extractor = capa.main.get_extractor(file_path, "auto", capa.main.BACKEND_VIV, [], False, disable_progress=True)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)

    # collect metadata (used only to make rendering more complete)
    meta = capa.main.collect_metadata([], file_path, rules_path, extractor)
    meta["analysis"].update(counts)
    meta["analysis"]["layout"] = capa.main.compute_layout(rules, extractor, capabilities)

    capa_output: Any = False
    if output_format == "dictionary":
        # ...as python dictionary, simplified as textable but in dictionary
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
        capa_output = render_dictionary(doc)
    elif output_format == "json":
        # render results
        # ...as json
        capa_output = json.loads(capa.render.json.render(meta, rules, capabilities))
    elif output_format == "texttable":
        # ...as human readable text table
        capa_output = capa.render.default.render(meta, rules, capabilities)

    return capa_output


if __name__ == "__main__":
    import sys
    import os.path
    import argparse

    RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules")

    parser = argparse.ArgumentParser(description="Extract capabilities from a file")
    parser.add_argument("file", help="file to extract capabilities from")
    parser.add_argument("--rules", help="path to rules directory", default=os.path.abspath(RULES_PATH))
    parser.add_argument(
        "--output", help="output format", choices=["dictionary", "json", "texttable"], default="dictionary"
    )
    args = parser.parse_args()

    print(capa_details(args.rules, args.file, args.output))
    sys.exit(0)
