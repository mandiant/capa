# Copyright 2021 Google LLC
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
Invoke capa multiple times and record profiling informations.
Use the --number and --repeat options to change the number of iterations.
By default, the script will emit a markdown table with a label pulled from git.

This script requires the additional dependency `humanize`.

usage:

    usage: profile-time.py [--number NUMBER] [--repeat REPEAT] [--label LABEL] sample

    Profile capa performance

    positional arguments:
      sample                path to sample to analyze

    optional arguments:
      --number NUMBER       batch size of profile collection
      --repeat REPEAT       batch count of profile collection
      --label LABEL         description of the profile collection

example:

    $ python profile-time.py ./tests/data/kernel32.dll_.frz --number 1 --repeat 2

    | label                                | count(evaluations)   | avg(time)   | min(time)   | max(time)   |
    |--------------------------------------|----------------------|-------------|-------------|-------------|
    | 18c30e4 main: remove perf debug msgs | 66,561,622           | 132.13s     | 125.14s     | 139.12s     |

      ^^^ --label or git hash
"""
import sys
import timeit
import logging
import argparse
import subprocess

import humanize
from rich import box
from rich.table import Table
from rich.console import Console

import capa.main
import capa.perf
import capa.rules
import capa.engine
import capa.loader
import capa.helpers
import capa.features
import capa.features.common
import capa.features.freeze
import capa.capabilities.common

logger = logging.getLogger("capa.profile")


def subshell(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    label = subshell("git show --pretty=oneline --abbrev-commit | head -n 1").strip()
    is_dirty = subshell("git status | grep 'modified: ' | grep -v 'rules' | grep -v 'tests/data'") != ""

    if is_dirty:
        label += " (dirty)"

    parser = argparse.ArgumentParser(description="Profile capa performance")
    capa.main.install_common_args(parser, wanted={"format", "backend", "os", "input_file", "signatures", "rules"})
    parser.add_argument("--number", type=int, default=3, help="batch size of profile collection")
    parser.add_argument("--repeat", type=int, default=30, help="batch count of profile collection")
    parser.add_argument("--label", type=str, default=label, help="description of the profile collection")
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)
        input_format = capa.main.get_input_format_from_cli(args)
        backend = capa.main.get_backend_from_cli(args, input_format)
        with capa.main.timing("load rules"):
            rules = capa.main.get_rules_from_cli(args)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
    except capa.main.ShouldExitError as e:
        return e.status_code

    with capa.helpers.CapaProgressBar(console=capa.helpers.log_console) as progress:
        total_iterations = args.number * args.repeat
        task = progress.add_task("profiling", total=total_iterations)

        def do_iteration():
            capa.perf.reset()
            capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)

            progress.advance(task)

        samples = timeit.repeat(do_iteration, number=args.number, repeat=args.repeat)

    logger.debug("perf: find capabilities: min: %0.2fs", (min(samples) / float(args.number)))
    logger.debug(
        "perf: find capabilities: avg: %0.2fs",
        (sum(samples) / float(args.repeat) / float(args.number)),
    )
    logger.debug("perf: find capabilities: max: %0.2fs", (max(samples) / float(args.number)))

    for counter, count in capa.perf.counters.most_common():
        logger.debug("perf: counter: %s: %s", counter, count)

    console = Console()

    table1 = Table(box=box.MARKDOWN)
    table1.add_column("feature class")
    table1.add_column("evaluation count")

    for counter, count in capa.perf.counters.most_common():
        table1.add_row(counter, humanize.intcomma(count))

    console.print(table1)
    console.print()

    table2 = Table(box=box.MARKDOWN)
    table2.add_column("label")
    table2.add_column("count(evaluations)", style="magenta")
    table2.add_column("min(time)", style="green")
    table2.add_column("avg(time)", style="yellow")
    table2.add_column("max(time)", style="red")

    table2.add_row(
        args.label,
        # python documentation indicates that min(samples) should be preferred,
        # so lets put that first.
        #
        # https://docs.python.org/3/library/timeit.html#timeit.Timer.repeat
        "{:,}".format(capa.perf.counters["evaluate.feature"]),
        f"{(min(samples) / float(args.number)):.2f}s",
        f"{(sum(samples) / float(args.repeat) / float(args.number)):.2f}s",
        f"{(max(samples) / float(args.number)):.2f}s",
    )

    console.print(table2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
