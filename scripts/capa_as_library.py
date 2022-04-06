#!/usr/bin/env python3

import json
import collections

import capa.main
import capa.rules
import capa.engine
import capa.features
import capa.render.json
import capa.render.utils as rutils
import capa.render.default
import capa.render.result_document
from capa.engine import *

# edit this to set the path for file to analyze and rule directory
RULES_PATH = "/tmp/capa/rules/"

# load rules from disk
rules = capa.rules.RuleSet(capa.main.get_rules([RULES_PATH], disable_progress=True))

# == Render ddictionary helpers
def render_meta(doc, ostream):
    ostream["md5"] = doc["meta"]["sample"]["md5"]
    ostream["sha1"] = doc["meta"]["sample"]["sha1"]
    ostream["sha256"] = doc["meta"]["sample"]["sha256"]
    ostream["path"] = doc["meta"]["sample"]["path"]


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
        {'CAPABILITY': {'accept command line arguments': 'host-interaction/cli',
                'allocate thread local storage (2 matches)': 'host-interaction/process',
                'check for time delay via GetTickCount': 'anti-analysis/anti-debugging/debugger-detection',
                'check if process is running under wine': 'anti-analysis/anti-emulation/wine',
                'contain a resource (.rsrc) section': 'executable/pe/section/rsrc',
                'write file (3 matches)': 'host-interaction/file-system/write'}
        }
    """
    subrule_matches = find_subrule_matches(doc)

    ostream["CAPABILITY"] = dict()
    for rule in rutils.capability_rules(doc):
        if rule["meta"]["name"] in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule["matches"])
        if count == 1:
            capability = rule["meta"]["name"]
        else:
            capability = "%s (%d matches)" % (rule["meta"]["name"], count)

        ostream["CAPABILITY"].setdefault(rule["meta"]["namespace"], list())
        ostream["CAPABILITY"][rule["meta"]["namespace"]].append(capability)


def render_attack(doc, ostream):
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
    ostream["ATTCK"] = dict()
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("att&ck"):
            continue
        for attack in rule["meta"]["att&ck"]:
            tactics[attack["tactic"]].add((attack["technique"], attack.get("subtechnique"), attack["id"]))

    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for (technique, subtechnique, id) in sorted(techniques):
            if subtechnique is None:
                inner_rows.append("%s %s" % (technique, id))
            else:
                inner_rows.append("%s::%s %s" % (technique, subtechnique, id))
        ostream["ATTCK"].setdefault(tactic.upper(), inner_rows)


def render_mbc(doc, ostream):
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
    ostream["MBC"] = dict()
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("mbc"):
            continue

        for mbc in rule["meta"]["mbc"]:
            objectives[mbc["objective"]].add((mbc["behavior"], mbc.get("method"), mbc["id"]))

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for (behavior, method, id) in sorted(behaviors):
            if method is None:
                inner_rows.append("%s [%s]" % (behavior, id))
            else:
                inner_rows.append("%s::%s [%s]" % (behavior, method, id))
        ostream["MBC"].setdefault(objective.upper(), inner_rows)


def render_dictionary(doc):
    ostream = dict()
    render_meta(doc, ostream)
    render_attack(doc, ostream)
    render_mbc(doc, ostream)
    render_capabilities(doc, ostream)

    return ostream


# ==== render dictionary helpers
def capa_details(file_path, output_format="dictionary"):
    # extract features and find capabilities
    extractor = capa.main.get_extractor(file_path, "auto", capa.main.BACKEND_VIV, [], False, disable_progress=True)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)

    # collect metadata (used only to make rendering more complete)
    meta = capa.main.collect_metadata("", file_path, RULES_PATH, extractor)
    meta["analysis"].update(counts)
    meta["analysis"]["layout"] = capa.main.compute_layout(rules, extractor, capabilities)

    capa_output = False
    if output_format == "dictionary":
        # ...as python dictionary, simplified as textable but in dictionary
        doc = capa.render.result_document.convert_capabilities_to_result_document(meta, rules, capabilities)
        capa_output = render_dictionary(doc)
    elif output_format == "json":
        # render results
        # ...as json
        capa_output = json.loads(capa.render.json.render(meta, rules, capabilities))
    elif output_format == "texttable":
        # ...as human readable text table
        capa_output = capa.render.default.render(meta, rules, capabilities)

    return capa_output
