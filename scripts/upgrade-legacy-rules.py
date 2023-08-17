#!/usr/bin/env python3
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.


import re
import sys
import logging
import argparse
import textwrap
from typing import Any, Dict, List, Tuple, Union, Literal, Optional  # noqa: F401
from pathlib import Path

import yaml
from typing_extensions import TypeAlias

from capa.main import collect_rule_file_paths
from capa.rules import Rule

DYNAMIC_FEATURES = ("api", "string", "substring", "number", "description", "regex", "match", "os", "arch")
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

logger = logging.getLogger(__name__)


def rec_features_list(static: List[dict], context=False) -> tuple[List[Dict], List[Dict]]:
    """
    takes in a list of static features, and returns it alongside a list of dynamic-only features
    """
    dynamic = []  # type: List[Dict]
    for node in static:
        for _key, _value in node.items():
            pass
        if isinstance(_value, list):
            # is either subscope or ceng
            if _key in (*STATIC_SCOPES, *DYNAMIC_SCOPES):
                # is subscope
                stat, dyn = rec_scope(_key, _value, context=context)
                if not context:
                    if dyn:
                        dynamic.append({"or": [stat, dyn]})
                    else:
                        dynamic.append(stat)
                elif context == "dynamic" and dyn:
                    dynamic.append(dyn)
            elif _key in ENGINE_STATEMENTS or _key.endswith("or more"):
                # is ceng
                stat, dyn = rec_bool(_key, _value, context=context)
                if not context:
                    if dyn:
                        dynamic.append(dyn)
                elif context == "dynamic" and dyn:
                    dynamic.append(dyn)
            else:
                raise ValueError(f"key: {_key}, value: {_value}")
        if _key == "offset":
            if isinstance(_value, str) and "=" not in _value:
                try:
                    node[_key] = int(node[_key])
                except:
                    node[_key] = int(node[_key], 16)
        if _key.startswith("characteristic"):
            if _value in DYNAMIC_CHARACTERISTICS:
                dynamic.append(node)
        if _key == "string":
            node[_key] = node[_key].replace("\n", "\\n")
        if _key.startswith("count"):
            if isinstance(node[_key], str) and "or more" not in node[_key]:
                try:
                    node[_key] = int(node[_key])
                except:
                    try:
                        node[_key] = int(node[_key], 16)
                    except:
                        pass
            _key = _key.split("(")[1].split(")")[0]
        if _key in DYNAMIC_FEATURES:
            dynamic.append(node)
    return static, dynamic


def rec_scope(key: str, value: List, context=False) -> Tuple[Dict[str, List], Dict[str, Optional[List]]]:
    """
    takes in a static subscope, and returns it alongside its dynamic counterpart.
    """
    if context == "static":
        if key == "instruction":
            stat, _ = rec_features_list([{"and": value}], context=context)
            stat = stat[0]["and"]
        else:
            stat, _ = rec_bool(key, value, context=context)
        return {key: stat}, {}
    elif context == "dynamic":
        if key == "instruction":
            _, dyn = rec_features_list([{"and": value}], context=context)
        else:
            _, dyn = rec_bool(key, value, context=context)
        if dyn:
            return {}, {GET_DYNAMIC_EQUIV[key]: dyn}
        else:
            return {}, {}
    else:
        if key == "instruction":
            stat, _ = rec_features_list([{"and": value}], context="static")
            _, dyn = rec_features_list([{"and": value}], context="dynamic")
            stat = stat[0]["and"]
        else:
            stat, _ = rec_features_list(value, context="static")
            _, dyn = rec_features_list(value, context="dynamic")
        if dyn:
            return {key: stat}, {GET_DYNAMIC_EQUIV[key]: dyn}
        else:
            return {key: stat}, {}


def rec_bool(key, value, context=False) -> Tuple[Dict[str, List], Dict[str, Optional[List]]]:
    """
    takes in a capa logical statement and returns a static and dynamic variation of it.
    """
    stat, dyn = rec_features_list(value, context)
    if context == "static":
        return {key: stat}, {}
    elif context == "dynamic":
        if key == "and" and len(stat) != len(dyn):
            return {key: stat}, {}
        elif key == "or" and len(dyn) == len(list(filter(lambda x: x.get("description"), dyn))):
            return {}, {}
        elif dyn:
            return {}, {key: dyn}
        else:
            return {}, {}
    else:
        if key == "and" and len(stat) != len(dyn):
            return {key: stat}, {}
        elif key == "or" and len(dyn) == len(list(filter(lambda x: x.get("description"), dyn))):
            return {}, {}
        elif key == "or" and len(dyn) != len(stat):
            return {}, {key: dyn + [x for x in stat if x not in dyn]}
        elif dyn:
            return {key: stat}, {key: dyn}
        else:
            return {key: stat}, {}


class NoAliasDumper(yaml.SafeDumper):
    # This is used to get rid of aliases in yaml.dump()'s output
    def ignore_aliases(self, data):
        return True

    def increase_indent(self, flow=False, indentless=False):
        return super(NoAliasDumper, self).increase_indent(flow, indentless)


def update_meta(meta, has_dyn=True) -> Dict[str, Union[List, Dict, str]]:
    """
    Takes in a meta field with the old `scope` keyword,
    and replaces it with the `scopes` keyword while maintaining meta's keys order.
    """
    new_meta = {}  # type: Dict[str, Union[List, Dict, str]]
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


def format_string(s: str):
    s = s.replace("\n", "\\n")
    if s.startswith("'") and s.endswith("'"):
        s = s[1:-1]
    return s.replace("\\", "\\\\")


def upgrade_rule(content) -> str:
    """
    Takes in an old rule and returns its equivalent in the new rule format.
    """
    features = content["rule"]["features"]

    for _key, _value in features[0].items():
        pass
    stat, dyn = rec_features_list([{_key: _value}])

    meta = update_meta(content["rule"]["meta"], has_dyn=dyn)
    if dyn:
        features = dyn
    else:
        features = stat

    content["rule"] = {"meta": meta, "features": {"~": features}}
    upgraded_rule = yaml.dump(content, Dumper=NoAliasDumper, sort_keys=False, width=float("inf")).split("\n")
    upgraded_rule = "\n".join(list(filter(lambda line: "~" not in line, upgraded_rule)))
    upgraded_rule = re.sub(r"number: '(\d+|0[xX][0-9a-fA-F]+)'", r"number: \1", upgraded_rule)
    upgraded_rule = re.sub(
        r"(string|substring|regex): (.*)",
        lambda x: f"{x.group(1)}: "
        + (x.group(2) if ('"' not in x.group(2) and "\\" not in x.group(2)) else f'"{format_string(x.group(2))}"'),
        upgraded_rule,
    )
    print(upgraded_rule)
    if Rule.from_yaml(upgraded_rule):
        return upgraded_rule


def main(argv: Optional[List[str]] = None) -> int:
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
                return 0
            else:
                print("Please provide a valid answer [O]verwrite/[E]xit: ")

    # Get rules
    rule_file_paths: List[Path] = collect_rule_file_paths([old_rules_path])
    rule_contents = [rule_path.read_bytes() for rule_path in rule_file_paths]
    for path, content in zip(rule_file_paths, rule_contents):
        """
        This loop goes through the list of rules and does the following:
        1. Get the current rule's content.
        2. Get its dynamic-format equivalent.
        3. Compute its save path and save it there.
        """
        content = yaml.load(content.decode("utf-8"), Loader=yaml.BaseLoader)
        print(path)
        new_rule = upgrade_rule(content)
        save_path = Path(new_rules_save_path).joinpath(path.relative_to(old_rules_path))
        save_path.parents[0].mkdir(parents=True, exist_ok=True)
        try:
            with save_path.open("w", encoding="utf-8") as f:
                f.write(new_rule)
        except IOError as e:
            logger.error("%s", e)
            return -1
        else:
            logger.error("updated rule: %s", path)

    print(f"Successfully updated {len(rule_file_paths)} rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
