# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import collections

import capa.render.utils as rutils

def render_meta(doc, ostream):

    ostream["md5"] = doc["meta"]["sample"]["md5"]
    ostream["sha1"] = doc["meta"]["sample"]["sha1"]
    ostream["sha256"] = doc["meta"]["sample"]["sha256"]
    ostream["path"] =doc["meta"]["sample"]["path"]

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

        ostream["CAPABILITY"].setdefault(capability, rule["meta"]["namespace"])

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
    ostream["ATT&CK"] = dict()
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

    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for spec in sorted(techniques):
            if len(spec) == 2:
                technique, id = spec
                inner_rows.append("%s %s" % (technique, id))
            elif len(spec) == 3:
                technique, subtechnique, id = spec
                inner_rows.append("%s::%s %s" % (technique, subtechnique, id))
            else:
                raise RuntimeError("unexpected ATT&CK spec format")
        ostream["ATT&CK"].setdefault(tactic.upper(), inner_rows)


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

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for spec in sorted(behaviors):
            if len(spec) == 2:
                behavior, id = spec
                inner_rows.append("%s %s" % (behavior, id))
            elif len(spec) == 3:
                behavior, method, id = spec
                inner_rows.append("%s::%s %s" % (behavior, method, id))
            else:
                raise RuntimeError("unexpected MBC spec format")
        ostream["MBC"].setdefault(objective.upper(), inner_rows)

def render_dictionary(doc):
    ostream = dict()

    render_meta(doc, ostream)
    render_attack(doc, ostream)
    render_mbc(doc, ostream)
    render_capabilities(doc, ostream)

    return ostream
