# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import logging
import argparse
from typing import Set
from pathlib import Path

import capa.main
import capa.rules
from capa.features.common import Feature

logger = logging.getLogger("detect_duplicate_features")


def get_features(rule_path: str) -> Set[Feature]:
    """
    Extracts all features from a given rule file.

    Args:
        rule_path (str): The path to the rule file to extract features from.

    Returns:
        set: A set of all feature statements contained within the rule file.
    """
    with Path(rule_path).open("r", encoding="utf-8") as f:
        try:
            new_rule = capa.rules.Rule.from_yaml(f.read())
            return new_rule.extract_all_features()
        except Exception as e:
            logger.error("Error: New rule %s %s %s", rule_path, str(type(e)), str(e))
            sys.exit(-1)


def find_overlapping_rules(new_rule_path, rules_path):
    if not new_rule_path.endswith(".yml"):
        logger.error("FileNotFoundError ! New rule file name doesn't end with .yml")
        sys.exit(-1)

    # Loads features of new rule in a list.
    new_rule_features = get_features(new_rule_path)
    count = 0
    overlapping_rules = []

    # capa.rules.RuleSet stores all rules in given paths
    ruleset = capa.rules.get_rules(rules_path)

    for rule_name, rule in ruleset.rules.items():
        rule_features = rule.extract_all_features()

        if not len(rule_features):
            continue
        count += 1
        # Checks if any features match between existing and new rule.
        if any(feature in rule_features for feature in new_rule_features):
            overlapping_rules.append(rule_name)

    result = {"overlapping_rules": overlapping_rules, "count": count}
    return result


def main():
    parser = argparse.ArgumentParser(description="Find overlapping features in Capa rules.")

    parser.add_argument("rules", type=str, action="append", help="Path to rules")
    parser.add_argument("new_rule", type=str, help="Path to new rule")

    args = parser.parse_args()

    new_rule_path = args.new_rule
    rules_path = [Path(rule) for rule in args.rules]

    result = find_overlapping_rules(new_rule_path, rules_path)

    print("\nNew rule path : %s" % new_rule_path)
    print("Number of rules checked : %s " % result["count"])
    if result["overlapping_rules"]:
        print("Paths to overlapping rules : ")
        for r in result["overlapping_rules"]:
            print("- %s" % r)
    else:
        print("Paths to overlapping rules : None")
    print("Number of rules containing same features : %s" % len(result["overlapping_rules"]))
    print("\n")

    return len(result["overlapping_rules"])


if __name__ == "__main__":
    sys.exit(main())
