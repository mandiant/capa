"""
Invoke capa multiple times and record profiling informations.
Use the --number and --repeat options to change the number of iterations.
By default, the script will emit a markdown table with a label pulled from git.

Note: you can run this script against pre-generated .frz files to reduce the startup time.

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

import tqdm
import tabulate

import capa.main
import capa.perf
import capa.rules
import capa.engine
import capa.helpers
import capa.features
import capa.features.common
import capa.features.freeze

logger = logging.getLogger("capa.profile")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    label = subprocess.run(
        "git show --pretty=oneline --abbrev-commit | head -n 1", shell=True, capture_output=True, text=True
    ).stdout.strip()
    is_dirty = (
        subprocess.run(
            "git status | grep 'modified: ' | grep -v 'rules' | grep -v 'tests/data'",
            shell=True,
            capture_output=True,
            text=True,
        ).stdout
        != ""
    )

    if is_dirty:
        label += " (dirty)"

    parser = argparse.ArgumentParser(description="Profile capa performance")
    capa.main.install_common_args(parser, wanted={"format", "sample", "signatures", "rules"})

    parser.add_argument("--number", type=int, default=3, help="batch size of profile collection")
    parser.add_argument("--repeat", type=int, default=30, help="batch count of profile collection")
    parser.add_argument("--label", type=str, default=label, help="description of the profile collection")

    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    try:
        taste = capa.helpers.get_file_taste(args.sample)
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    try:
        with capa.main.timing("load rules"):
            rules = capa.main.get_rules(args.rules)
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    try:
        sig_paths = capa.main.get_signatures(args.signatures)
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    if (args.format == "freeze") or (args.format == "auto" and capa.features.freeze.is_freeze(taste)):
        with open(args.sample, "rb") as f:
            extractor = capa.features.freeze.load(f.read())
    else:
        extractor = capa.main.get_extractor(
            args.sample, args.format, capa.main.BACKEND_VIV, sig_paths, should_save_workspace=False
        )

    with tqdm.tqdm(total=args.number * args.repeat) as pbar:

        def do_iteration():
            capa.perf.reset()
            capa.main.find_capabilities(rules, extractor, disable_progress=True)
            pbar.update(1)

        samples = timeit.repeat(do_iteration, number=args.number, repeat=args.repeat)

    logger.debug("perf: find capabilities: min: %0.2fs" % (min(samples) / float(args.number)))
    logger.debug("perf: find capabilities: avg: %0.2fs" % (sum(samples) / float(args.repeat) / float(args.number)))
    logger.debug("perf: find capabilities: max: %0.2fs" % (max(samples) / float(args.number)))

    for counter, count in capa.perf.counters.most_common():
        logger.debug("perf: counter: {:}: {:,}".format(counter, count))

    print(
        tabulate.tabulate(
            [
                (
                    args.label,
                    "{:,}".format(capa.perf.counters["evaluate.feature"]),
                    # python documentation indicates that min(samples) should be preferred,
                    # so lets put that first.
                    #
                    # https://docs.python.org/3/library/timeit.html#timeit.Timer.repeat
                    "%0.2fs" % (min(samples) / float(args.number)),
                    "%0.2fs" % (sum(samples) / float(args.repeat) / float(args.number)),
                    "%0.2fs" % (max(samples) / float(args.number)),
                )
            ],
            headers=["label", "count(evaluations)", "min(time)", "avg(time)", "max(time)"],
            tablefmt="github",
        )
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
