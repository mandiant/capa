import os
import argparse

import capa.rules
import capa.engine as ceng


def get_child_features(feature):
    children = []

    if isinstance(feature, (ceng.And, ceng.Or, ceng.Some)):
        for child in feature.children:
            children.extend(get_child_features(child))
    elif isinstance(feature, (ceng.Subscope, ceng.Range, ceng.Not)):
        children.extend(get_child_features(feature.child))
    else:
        children.append(feature)
    return children


def get_features(rule_path):
    error = ""
    feature_list = []
    with open(rule_path, "r") as f:
        try:
            new_rule = capa.rules.Rule.from_yaml(f.read())
            feature_list = get_child_features(new_rule.statement)
        except Exception as e:
            error = "rule :" + rule_path + " " + str(type(e)) + " " + str(e)
    return feature_list, error


def find_overlapping_rules(new_rule_path, rules_path):
    if not new_rule_path.endswith(".yml"):
        raise FileNotFoundError("FileNotFoundError ! New rule file name doesn't end with yml")

    new_rule_features, error = get_features(new_rule_path)
    if error:
        raise Warning(error)

    errors: list = []
    count = 0
    overlapping_rules = []
    for rules in rules_path:
        for dirpath, dirnames, filenames in os.walk(rules):
            for filename in filenames:
                if filename.endswith(".yml"):
                    rule_path = os.path.join(dirpath, filename)
                    rule_features, error = get_features(rule_path)
                    if error:
                        errors.append(error)
                    if not len(rule_features):
                        continue
                    count += 1
                    if any([feature in rule_features for feature in new_rule_features]):
                        overlapping_rules.append(rule_path)

    result = {"overlapping_rules": overlapping_rules, "count": count, "errors": errors}
    return result


def main():
    parser = argparse.ArgumentParser(description="Find overlapping features in Capa rules.")

    parser.add_argument("rules", type=str, action="append", help="Path to rules")
    parser.add_argument("new_rule", type=str, help="Path to new rule")

    args = parser.parse_args()

    new_rule_path = args.new_rule
    rules_path = args.rules
    try:
        result = find_overlapping_rules(new_rule_path, rules_path)
        print("\nNew rule path : %s" % new_rule_path)
        print("Number of rules checked : %s " % result["count"])
        print("Paths to overlapping rules : ")
        for r in result["overlapping_rules"]:
            print(r)
        print("Number of rules containing same features : %s" % len(result["overlapping_rules"]))
        if result["errors"]:
            print("\nWhile checking following .yml files error occured:")
            for error in result["errors"]:
                print(error)
            print("\n")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
