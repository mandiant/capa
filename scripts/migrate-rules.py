#!/usr/bin/env python
'''
migrate rules and their namespaces.

example:

    $ python scripts/migrate-rules.py migration.csv ./rules ./new-rules
'''
import os
import os.path
import sys
import csv
import logging
import collections

import argparse

import capa.rules


logger = logging.getLogger('migrate-rules')



def read_plan(plan_path):
    with open(plan_path, 'rb') as f:
        return list(csv.DictReader(f, restkey="other", fieldnames=(
            "existing path",
            "existing name",
            "existing rule-category",
            "proposed name",
            "proposed namespace",
            "ATT&CK",
            "MBC",
            "comment1",
        )))


def read_rules(rule_directory):
    rules = {}
    for root, dirs, files in os.walk(rule_directory):
        for file in files:
            path = os.path.join(root, file)
            if not path.endswith('.yml'):
                logger.info('skipping file: %s', path)
                continue

            rule = capa.rules.Rule.from_yaml_file(path)
            rules[rule.name] = rule
    return rules


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description='migrate rules.')
    parser.add_argument('plan', type=str,
                        help='Path to CSV describing migration')
    parser.add_argument('source', type=str,
                        help='Source directory of rules')
    parser.add_argument('destination', type=str,
                        help='Destination directory of rules')
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    plan = read_plan(args.plan)
    logger.info("read %d plan entries", len(plan))

    rules = read_rules(args.source)
    logger.info("read %d rules", len(rules))

    planned_rules = set([row["existing name"] for row in plan])
    missing = [rule for (name, rule) in rules.items() if name not in planned_rules]

    if missing:
        logger.error("plan does not account for %d rules:" % (len(missing)))
        for rule in missing:
            logger.error("  " + rule.name)
        return -1

    for row in plan:
        if not row["existing name"]:
            continue

        rule = rules[row["existing name"]]

        if rule.meta["name"] != row["proposed name"]:
            logger.info("renaming rule '%s' -> '%s'", rule.meta["name"], row["proposed name"])
            rule.meta["name"] = row["proposed name"]
            rule.name = row["proposed name"]

        if "rule-category" in rule.meta:
            logger.info("deleting rule category '%s'", rule.meta["rule-category"])
            del rule.meta["rule-category"]

        rule.meta["namespace"] = row["proposed namespace"]

        if row["ATT&CK"] != 'n/a' and row["ATT&CK"] != "":
            tag = row["ATT&CK"]
            name, _, id = tag.rpartition(" ")
            tag = "%s [%s]" % (name, id)
            rule.meta["att&ck"] = [tag]

        if row["MBC"] != 'n/a' and row["MBC"] != "":
            tag = row["MBC"]
            rule.meta["mbc"] = [tag]

    for rule in rules.values():
        namespace = rule.meta.get("namespace")

        if not namespace:
            logger.info("%s has no proposed namespace, skipping", rule.name)
            continue

        filename = rule.name
        filename = filename.lower()
        filename = filename.replace(" ", "-")
        filename = filename.replace("(", "")
        filename = filename.replace(")", "")
        filename = filename.replace("+", "")
        filename = filename.replace("/", "")
        filename = filename + ".yml"

        try:
            directory = os.path.join(args.destination, namespace)
            os.makedirs(directory)
        except OSError:
            pass
        else:
            logger.info("created namespace: %s", directory)

        path = os.path.join(directory, filename)
        logger.info("writing rule %s", path)

        with open(path, "wb") as f:
            f.write(rule.to_yaml())

    return 0


if __name__ == '__main__':
    sys.exit(main())