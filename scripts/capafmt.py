"""
Reformat the given capa rule into a consistent style.
Use the -i flag to update the rule in-place.

Usage:

   $ python capafmt.py -i foo.yml

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import sys
import logging
import argparse

import capa.rules

logger = logging.getLogger("capafmt")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Capa rule formatter.")
    parser.add_argument("path", type=str, help="Path to rule to format")
    parser.add_argument(
        "-i",
        "--in-place",
        action="store_true",
        dest="in_place",
        help="Format the rule in place, otherwise, write formatted rule to STDOUT",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output but errors")
    parser.add_argument(
        "-c",
        "--check",
        action="store_true",
        help="Don't output (reformatted) rule, only return status. 0 = no changes, 1 = would reformat",
    )
    args = parser.parse_args(args=argv)

    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    logging.basicConfig(level=level)
    logging.getLogger("capafmt").setLevel(level)

    rule = capa.rules.Rule.from_yaml_file(args.path, use_ruamel=True)
    reformatted_rule = rule.to_yaml()

    if args.check:
        if rule.definition == reformatted_rule:
            logger.info("rule is formatted correctly, nice! (%s)", rule.name)
            return 0
        else:
            logger.info("rule requires reformatting (%s)", rule.name)
            if "\r\n" in rule.definition:
                logger.info("please make sure that the file uses LF (\\n) line endings only")
            return 1

    if args.in_place:
        with open(args.path, "wb") as f:
            f.write(reformatted_rule.encode("utf-8"))
    else:
        print(reformatted_rule)

    return 0


if __name__ == "__main__":
    sys.exit(main())
