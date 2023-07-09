import sys
import logging
import argparse

import capa.main
import capa.rules
import capa.engine as ceng

logger = logging.getLogger("detect_duplicate_features")


def get_child_features(feature: ceng.Statement) -> list:
    """
    Recursively extracts all feature statements from a given rule statement.

    Args:
        feature (capa.engine.Statement): The feature statement to extract features from.

    Returns:
        list: A list of all feature statements contained within the given feature statement.
    """
    children = []

    if isinstance(feature, (ceng.And, ceng.Or, ceng.Some)):
        for child in feature.children:
            children.extend(get_child_features(child))
    elif isinstance(feature, (ceng.Subscope, ceng.Range, ceng.Not)):
        children.extend(get_child_features(feature.child))
    else:
        children.append(feature)
    return children


def get_features(rule_path: str) -> list:
    """
    Extracts all features from a given rule file.

    Args:
        rule_path (str): The path to the rule file to extract features from.

    Returns:
        list: A list of all feature statements contained within the rule file.
    """
    feature_list = []
    with open(rule_path, "r", encoding="utf-8") as f:
        try:
            new_rule = capa.rules.Rule.from_yaml(f.read())
            feature_list = get_child_features(new_rule.statement)
        except Exception as e:
            logger.error("Error: New rule %s %s %s", rule_path, str(type(e)), str(e))
            sys.exit(-1)
    return feature_list


def find_overlapping_rules(new_rule_path, rules_path):
    if not new_rule_path.endswith(".yml"):
        logger.error("FileNotFoundError ! New rule file name doesn't end with .yml")
        sys.exit(-1)

    # Loads features of new rule in a list.
    new_rule_features = get_features(new_rule_path)

    count = 0
    overlapping_rules = []

    # capa.rules.RuleSet stores all rules in given paths
    ruleset = capa.main.get_rules(rules_path)

    for rule_name, rule in ruleset.rules.items():
        rule_features = get_child_features(rule.statement)

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
    rules_path = args.rules

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
