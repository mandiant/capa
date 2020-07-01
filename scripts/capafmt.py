"""
Reformat the given capa rule into a consistent style.
Use the -i flag to update the rule in-place.

Usage:

   $ python capafmt.py -i foo.yml
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
    args = parser.parse_args(args=argv)

    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    logging.basicConfig(level=level)
    logging.getLogger("capafmt").setLevel(level)

    rule = capa.rules.Rule.from_yaml_file(args.path)
    if args.in_place:
        with open(args.path, "wb") as f:
            f.write(rule.to_yaml().encode("utf-8"))
    else:
        print(rule.to_yaml().rstrip("\n"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
