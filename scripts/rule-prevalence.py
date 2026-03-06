#!/usr/bin/env python
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
rule-prevalence

Run capa rules against a directory of freeze (.frz) files and report
which rules matched and how often. Useful for spotting rules that are
FP-prone (match too broadly) or dead (match nothing).

To generate .frz files from existing samples first run:

    $ capa --format freeze tests/data/mimikatz.exe_ > tests/data/mimikatz.exe_.frz
    $ capa --format freeze tests/data/kernel32.dll_  > tests/data/kernel32.dll_.frz

Then run this script:

    $ python scripts/rule-prevalence.py tests/data/ --rules rules/

example output:

    analyzed 3 file(s) against 1000 rules

    rule name                           hits  files       rate
    ---------------------------------- ------ ---------- ------
    encrypt data using XOR               142  3 / 3      100%
    send HTTP request                      1  1 / 3       33%
    resolve function by hash               0  0 / 3        0%
"""

import sys
import logging
import argparse
import collections
from typing import Iterator
from pathlib import Path

from rich import box
from rich.table import Table
from rich.console import Console

import capa.rules
import capa.rules.cache
import capa.features.freeze
import capa.capabilities.common

logger = logging.getLogger("rule-prevalence")


def find_frz_files(input_path: Path) -> list[Path]:
    """
    recursively find all .frz files under input_path.
    returns a sorted list so output is deterministic across runs.
    """
    return sorted(input_path.rglob("*.frz"))


def load_rules(rules_path: Path) -> capa.rules.RuleSet:
    """
    load capa rules from the given directory.
    """
    logger.debug("loading rules from %s", rules_path)
    return capa.rules.get_rules([rules_path])


def get_matched_rule_names(frz_path: Path, rules: capa.rules.RuleSet) -> Iterator[str]:
    """
    load a single .frz file and run all rules against it.
    yields the name of each rule that matched at least once.
    """
    extractor = capa.features.freeze.load(frz_path.read_bytes())
    capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)
    yield from capabilities.matches.keys()


def compute_prevalence(frz_paths: list[Path], rules: capa.rules.RuleSet) -> dict[str, int]:
    """
    for each .frz file, run all rules and count how many files each rule matched.
    returns a dict: {rule_name: number_of_files_that_matched}
    """
    counts: dict[str, int] = collections.defaultdict(int)

    for frz_path in frz_paths:
        logger.debug("processing %s", frz_path.name)
        try:
            for rule_name in get_matched_rule_names(frz_path, rules):
                counts[rule_name] += 1
        except Exception as e:
            logger.warning("failed to process %s: %s", frz_path.name, e)

    return counts


def render_table(counts: dict[str, int], rules: capa.rules.RuleSet, total: int, quiet: bool) -> None:
    """
    print a rich table of rules sorted by hit rate (highest first).
    rules with >= 50% hit rate are highlighted in red as FP warnings.
    if quiet=True, only show rules that matched at least one file.
    """
    console = Console()
    console.print(f"\nanalyzed [bold]{total}[/bold] file(s) against [bold]{len(rules.rules)}[/bold] rules\n")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("rule name", style="cyan", no_wrap=False, ratio=6)
    table.add_column("hits", justify="right")
    table.add_column("files", justify="right")
    table.add_column("rate", justify="right")

    all_rule_names = sorted(rules.rules.keys(), key=lambda n: -counts.get(n, 0))

    for rule_name in all_rule_names:
        hit_count = counts.get(rule_name, 0)

        if quiet and hit_count == 0:
            continue

        rate = (hit_count / total * 100) if total > 0 else 0
        rate_str = f"{rate:.0f}%"
        row_style = "red" if rate >= 50 else ""

        table.add_row(
            rule_name,
            str(hit_count),
            f"{hit_count} / {total}",
            rate_str,
            style=row_style,
        )

    console.print(table)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="show how often capa rules match across a set of freeze (.frz) files")
    parser.add_argument("input", type=str, help="path to directory containing .frz files")
    parser.add_argument(
        "-r", "--rules", type=str, default=None, help="path to rules directory (uses ./rules if not set)"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="only show rules that matched at least one file")
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"error: input path does not exist: {input_path}", file=sys.stderr)
        return 1

    frz_paths = find_frz_files(input_path)
    if not frz_paths:
        print(f"error: no .frz files found in {input_path}", file=sys.stderr)
        print("hint: generate them with: capa --format freeze <sample> > <sample>.frz", file=sys.stderr)
        return 1

    logger.debug("found %d .frz file(s)", len(frz_paths))

    if args.rules:
        rules_path = Path(args.rules)
    else:
        rules_path = Path(__file__).parent.parent / "rules"

    if not rules_path.exists():
        print(f"error: rules path does not exist: {rules_path}", file=sys.stderr)
        return 1

    rules = load_rules(rules_path)
    counts = compute_prevalence(frz_paths, rules)
    render_table(counts, rules, total=len(frz_paths), quiet=args.quiet)

    return 0


if __name__ == "__main__":
    sys.exit(main())
