#!/usr/bin/env python3
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.


import sys
import argparse
import textwrap
from typing import List, Optional
from pathlib import Path

import yaml

from capa.main import collect_rule_file_paths
from capa.rules import Rule
from capa.features.address import NO_ADDRESS

DYNAMIC_FEATURES  = ("api", "string", "substring", "number", "description", "regex", "match", "os")
ENGINE_STATEMENTS = ("and", "or", "optional", "not")
STATIC_SCOPES = ("function", "basic block", "instruction")
DYNAMIC_SCOPES = ("thread",)


def rec_features_list(static, context=False):
    """
    takes in a list of static features, and returns it alongside a list of dynamic-only features
    """
    dynamic = []
    for node in static:
        for key, value in node.items():
            pass
        if isinstance(value, list):
            # is either subscope or ceng
            if key in (*static_scopes, *dynamic_scopes):
                # is subscope
                stat, dyn = rec_scope(key, value, context)
                if not context and dyn:
                    dynamic.append({"or": [stat, dyn]})
                elif context == "d" and dyn:
                    dynamic.append(dyn)
            elif key in engine_words or key.endswith("or more"):
                # is ceng
                stat, dyn = rec_bool(key, value, context)
                if dyn:
                    dynamic.append(dyn)
            else:
                raise ValueError(f"key: {key}, value: {value}")
        if key.startswith("count"):
            key = key.split("(")[1].split(")")[0]
        if key in dynamic_features:
            dynamic.append(node)
    return static, dynamic


def rec_scope(key, value, context=False):
    """
    takes in a static subscope, and returns it alongside its dynamic counterpart.
    """
    if len(value) > 1 or (key == "instruction" and key not in engine_words):
        static, _ = rec_bool("and", value, "s")
        _, dynamic = rec_bool("and", value, "d")
    else:
        static, _ = rec_features_list(value, "s")
        _, dynamic = rec_features_list(value, "d")
    return {key: static}, {"thread": dynamic}


def rec_bool(key, value, context=False):
    """
    takes in a capa logical statement and returns a static and dynamic variation of it.
    """
    stat, dyn = rec_features_list(value, context)
    if key == "and" and len(stat) != len(dyn):
        print(sorted(map(lambda s: s.keys(), dyn)))
        return {key: value}, {}
    if dyn:
        return {key: value}, {key: dyn}
    return {key: value}, {}


def upgrade_rule(content):
    features = content["rule"]["features"]
    print(f"original: {features[0]}\n")
    for key, value in features[0].items():
        pass
    if key in static_scopes:
        print(f"modified: {rec_scope(key, value)[1]}")
    elif key in engine_words:
        print(f"modified: {rec_bool(key, value)[1]}")
    else:
        print(f"modified: {rec_features_list([{key: value}])[1]}")

    print("\n\n")


def main(argv: Optional[List[str]] = None):
    desc = (
        "Upgrade legacy-format rulesets into the new rules format which supports static and dynamic analysis flavors."
    )
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--old-rules-path", default="../rules", help="path to the legacy ruleset")
    parser.add_argument("--new-rules-save-path", default="../upgraded-rules/", help="where to save the upgraded rules")
    args = parser.parse_args(args=argv)

    # check args
    old_rules_path = Path(args.old_rules_path)
    new_rules_save_path = Path(args.new_rules_save_path)
    if old_rules_path == new_rules_save_path:
        print(
            textwrap.dedent(
                """
                WARNING: you've specified the same directory as the old-rules' path and the new rules' save path,
                which will cause this script to overwrite your old rules with the new upgraded ones.
                Are you sure you want proceed with overwritting the old rules [O]verwrite/[E]xit: 
                """
            )
        )
        response = ""
        while response not in ("o", "e"):
            response = input().lower()
            if response == "o":
                print("Old rules' folder will be overwritten.")
            elif response == "e":
                print("The ruleset will not been upgraded.")
                sys.exit(0)
            else:
                print("Please provide a valid answer [O]verwrite/[E]xit: ")

    # Get rules
    rule_file_paths: List[Path] = collect_rule_file_paths([old_rules_path])
    rule_contents = [rule_path.read_bytes() for rule_path in rule_file_paths]

    rules = []  # type: List[Rule]
    for path, content in zip(rule_file_paths, rule_contents):
        content = content.decode("utf-8")
        content = yaml.load(content, Loader=yaml.Loader)
        upgrade_rule(content)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
