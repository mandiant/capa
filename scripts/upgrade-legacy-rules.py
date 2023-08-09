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
from typing import List, Union, Literal, Optional
from pathlib import Path

import yaml
from typing_extensions import TypeAlias

from capa.main import collect_rule_file_paths
from capa.features.address import NO_ADDRESS

DYNAMIC_FEATURES = ("api", "string", "substring", "number", "description", "regex", "match", "os")
DYNAMIC_CHARACTERISTICS = ("embedded-pe",)
ENGINE_STATEMENTS = ("and", "or", "optional", "not")
STATIC_SCOPES = ("function", "basic block", "instruction")
DYNAMIC_SCOPES = ("thread",)

GET_DYNAMIC_EQUIV = {
    "instruction": "call",
    "basic block": "thread",
    "function": "process",
    "file": "file",
}

context: TypeAlias = Union[Literal["static"], Literal["dynamic"]]


def rec_features_list(static: List[dict], context=False):
    """
    takes in a list of static features, and returns it alongside a list of dynamic-only features
    """
    dynamic = []
    for node in static:
        for key, value in node.items():
            pass
        if isinstance(value, list):
            # is either subscope or ceng
            if key in (*STATIC_SCOPES, *DYNAMIC_SCOPES):
                # is subscope
                stat, dyn = rec_scope(key, value)
                if not context and dyn:
                    dynamic.append({"or": [stat, dyn]})
                elif context == "dynamic" and dyn:
                    dynamic.append(dyn)
            elif key in ENGINE_STATEMENTS or key.endswith("or more"):
                # is ceng
                stat, dyn = rec_bool(key, value, context)
                if dyn:
                    dynamic.append(dyn)
            else:
                raise ValueError(f"key: {key}, value: {value}")
        if key.startswith("count"):
            key = key.split("(")[1].split(")")[0]
        if key.startswith("characteristic"):
            if value in DYNAMIC_CHARACTERISTICS:
                dynamic.append(node)
        if key in DYNAMIC_FEATURES:
            dynamic.append(node)
    return static, dynamic


def rec_scope(key, value):
    """
    takes in a static subscope, and returns it alongside its dynamic counterpart.
    """
    if len(value) > 1 or (key == "instruction" and key not in ENGINE_STATEMENTS):
        _, dynamic = rec_features_list([{"and": value}], context="dynamic")
    else:
        _, dynamic = rec_features_list(value, context="dynamic")
    if dynamic:
        return {key: value}, {GET_DYNAMIC_EQUIV[key]: dynamic}
    return {key: value}, {}


def rec_bool(key, value, context=False):
    """
    takes in a capa logical statement and returns a static and dynamic variation of it.
    """
    stat, dyn = rec_features_list(value, context)
    if key == "and" and len(stat) != len(dyn):
        return {key: value}, {}
    if dyn:
        return {key: value}, {key: dyn}
    return {key: value}, {}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True

    def increase_indent(self, flow=False, indentless=False):
        return super(NoAliasDumper, self).increase_indent(flow, indentless)


def update_meta(meta, has_dyn=True):
    new_meta = {}
    for key, value in meta.items():
        if key != "scope":
            if isinstance(value, list):
                new_meta[key] = {"~": value}
            else:
                new_meta[key] = value
            continue
        if has_dyn:
            new_meta["scopes"] = {"static": value, "dynamic": GET_DYNAMIC_EQUIV[value]}
        else:
            new_meta["scopes"] = {"static": value}
    return new_meta


def upgrade_rule(content):
    features = content["rule"]["features"]

    for key, value in features[0].items():
        pass
    stat, dyn = rec_features_list([{key: value}])

    meta = update_meta(content["rule"]["meta"], has_dyn=dyn)
    if dyn:
        features = dyn
    else:
        features = stat

    content["rule"] = {"meta": meta, "features": {"~": features}}

    upgraded_rule = yaml.dump(content, Dumper=NoAliasDumper, sort_keys=False).split("\n")
    upgraded_rule = "\n".join(list(filter(lambda line: "~" not in line, upgraded_rule)))
    print(upgraded_rule)


def main(argv: Optional[List[str]] = None):
    desc = (
        "Upgrade legacy-format rulesets into the new rules format which supports static and dynamic analysis flavors."
    )
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--old-rules-path", default=Path(__file__).parents[1].joinpath("rules"), help="path to the legacy ruleset"
    )
    parser.add_argument(
        "--save-path",
        default=Path(__file__).parents[1].joinpath("upgraded-rules"),
        help="where to save the upgraded rules",
    )
    args = parser.parse_args(args=argv)

    # check args
    old_rules_path = Path(args.old_rules_path)
    new_rules_save_path = Path(args.save_path)

    if old_rules_path == new_rules_save_path:
        print(
            textwrap.dedent(
                """
                WARNING: you've specified the same directory for the old-rules' path and the new rules' save path. 
                This will cause this script to overwrite your old rules with the new upgraded ones. 
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

    for path, content in zip(rule_file_paths, rule_contents):
        content = content.decode("utf-8")
        content = yaml.load(content, Loader=yaml.Loader)
        new_rule = upgrade_rule(content)
        save_path = Path(new_rules_save_path)
        save_path = save_path.joinpath(path.relative_to(old_rules_path))
        save_path.parents[0].mkdir(parents=True, exist_ok=True)
        with save_path.open("w", encoding="utf-8") as f:
            f.write(new_rule)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
