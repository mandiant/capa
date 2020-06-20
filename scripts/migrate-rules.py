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

import yaml
import argparse


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

            with open(path, 'rb') as f:
                rule = yaml.safe_load(f.read().decode('utf-8'))

                # we want the meta section to show up before the logic
                # so use an ordereddict
                formatted_rule = {"rule": collections.OrderedDict()}
                formatted_rule["rule"]["meta"] = rule["rule"]["meta"]
                formatted_rule["rule"]["features"] = rule["rule"]["features"]

                rules[rule['rule']['meta']['name']] = formatted_rule
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

    def dict_representer(dumper, data):
        return dumper.represent_dict(data.iteritems())

    yaml.add_representer(collections.OrderedDict, dict_representer)

    for row in plan:
        if not row["existing name"]:
            continue

        rule = rules[row["existing name"]]
        meta = rule["rule"]["meta"]

        if meta["name"] != row["proposed name"]:
            logger.info("renaming rule '%s' -> '%s'", meta["name"], row["proposed name"])
            meta["name"] = row["proposed name"]

        if "rule-category" in meta:
            logger.info("deleting rule category '%s'", meta["rule-category"])
            del meta["rule-category"]

        meta["namespace"] = row["proposed namespace"]

        meta["att&ck"] = [
            row["ATT&CK"]
        ]

        meta["mbc"] = [
            row["MBC"]
        ]

    for rule in rules.values():
        meta = rule["rule"]["meta"]
        namespace = meta.get("namespace")

        if not namespace:
            logger.info("%s has no proposed namespace, skipping", meta["name"])
            continue

        filename = meta["name"]
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
            f.write(yaml.dump(rule).encode("utf-8"))

    return 0


if __name__ == '__main__':
    sys.exit(main())