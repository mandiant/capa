#!/usr/bin/env python
"""
migrate rules and their namespaces.

example:

    $ python scripts/migrate-rules.py migration.csv ./rules ./new-rules

Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import os
import csv
import sys
import logging
import os.path
import argparse
import collections

import capa.rules

logger = logging.getLogger("migrate-rules")


def read_plan(plan_path):
    with open(plan_path, "rb") as f:
        return list(
            csv.DictReader(
                f,
                restkey="other",
                fieldnames=(
                    "existing path",
                    "existing name",
                    "existing rule-category",
                    "proposed name",
                    "proposed namespace",
                    "ATT&CK",
                    "MBC",
                    "comment1",
                ),
            )
        )


def read_rules(rule_directory):
    rules = {}
    for root, dirs, files in os.walk(rule_directory):
        for file in files:
            path = os.path.join(root, file)
            if not path.endswith(".yml"):
                logger.info("skipping file: %s", path)
                continue

            rule = capa.rules.Rule.from_yaml_file(path)
            rules[rule.name] = rule

            if "nursery" in path:
                rule.meta["capa/nursery"] = True
    return rules


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="migrate rules.")
    parser.add_argument("plan", type=str, help="Path to CSV describing migration")
    parser.add_argument("source", type=str, help="Source directory of rules")
    parser.add_argument("destination", type=str, help="Destination directory of rules")
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    plan = read_plan(args.plan)
    logger.info("read %d plan entries", len(plan))

    rules = read_rules(args.source)
    logger.info("read %d rules", len(rules))

    planned_rules = set([row["existing name"] for row in plan])
    unplanned_rules = [rule for (name, rule) in rules.items() if name not in planned_rules]

    if unplanned_rules:
        logger.error("plan does not account for %d rules:" % (len(unplanned_rules)))
        for rule in unplanned_rules:
            logger.error("  " + rule.name)
        return -1

    # pairs of strings (needle, replacement)
    match_translations = []

    for row in plan:
        if not row["existing name"]:
            continue

        rule = rules[row["existing name"]]

        if rule.meta["name"] != row["proposed name"]:
            logger.info("renaming rule '%s' -> '%s'", rule.meta["name"], row["proposed name"])

            # assume the yaml is formatted like `- match: $rule-name`.
            # but since its been linted, this should be ok.
            match_translations.append(("- match: " + rule.meta["name"], "- match: " + row["proposed name"]))

            rule.meta["name"] = row["proposed name"]
            rule.name = row["proposed name"]

        if "rule-category" in rule.meta:
            logger.info("deleting rule category '%s'", rule.meta["rule-category"])
            del rule.meta["rule-category"]

        rule.meta["namespace"] = row["proposed namespace"]

        if row["ATT&CK"] != "n/a" and row["ATT&CK"] != "":
            tag = row["ATT&CK"]
            name, _, id = tag.rpartition(" ")
            tag = "%s [%s]" % (name, id)
            rule.meta["att&ck"] = [tag]

        if row["MBC"] != "n/a" and row["MBC"] != "":
            tag = row["MBC"]
            rule.meta["mbc"] = [tag]

    for rule in rules.values():
        filename = rule.name
        filename = filename.lower()
        filename = filename.replace(" ", "-")
        filename = filename.replace("(", "")
        filename = filename.replace(")", "")
        filename = filename.replace("+", "")
        filename = filename.replace("/", "")
        filename = filename + ".yml"

        try:
            if rule.meta.get("capa/nursery"):
                directory = os.path.join(args.destination, "nursery")
            elif rule.meta.get("lib"):
                directory = os.path.join(args.destination, "lib")
            else:
                directory = os.path.join(args.destination, rule.meta.get("namespace"))
            os.makedirs(directory)
        except OSError:
            pass
        else:
            logger.info("created namespace: %s", directory)

        path = os.path.join(directory, filename)
        logger.info("writing rule %s", path)

        doc = rule.to_yaml().decode("utf-8")
        for (needle, replacement) in match_translations:
            doc = doc.replace(needle, replacement)

        with open(path, "wb") as f:
            f.write(doc.encode("utf-8"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
