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


import sys
import json
import time
import logging
import argparse
import contextlib
import statistics
import subprocess
import multiprocessing
from typing import Optional
from pathlib import Path
from collections import Counter
from dataclasses import dataclass
from multiprocessing import Pool

import rich
import rich.box
import rich.table

import capa.main

logger = logging.getLogger("capa.compare-backends")

BACKENDS = ("vivisect", "ida", "binja")


@dataclass
class CapaInvocation:
    path: Path
    backend: str
    duration: float
    returncode: int
    stdout: Optional[str]
    stderr: Optional[str]
    err: Optional[str]


def invoke_capa(file: Path, backend: str) -> CapaInvocation:
    stdout = None
    stderr = None
    err = None
    returncode: int
    try:
        logger.debug("run capa: %s: %s", backend, file.name)
        t1 = time.time()
        child = subprocess.run(
            ["python", "-m", "capa.main", "--json", "--backend=" + backend, str(file)],
            capture_output=True,
            check=True,
            text=True,
            encoding="utf-8",
        )
        returncode = child.returncode
        stdout = child.stdout
        stderr = child.stderr
    except subprocess.CalledProcessError as e:
        returncode = e.returncode
        stdout = e.stdout
        stderr = e.stderr

        logger.debug("%s:%s: error", backend, file.name)
        err = str(e)
    else:
        pass
    finally:
        t2 = time.time()

    return CapaInvocation(
        path=file,
        backend=backend,
        duration=t2 - t1,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        err=err,
    )


def wrapper_invoke_capa(args):
    file, backend = args
    return invoke_capa(file, backend)


def collect(args):
    results_path = args.results_path
    if not results_path.is_file():
        default_doc = {backend: {} for backend in BACKENDS}  # type: ignore
        results_path.write_text(json.dumps(default_doc), encoding="utf-8")

    testfiles = Path(__file__).parent.parent / "tests" / "data"

    for file in sorted(p for p in testfiles.glob("*")):
        # remove leftover analysis files
        # because IDA doesn't cleanup after itself, currently.
        if file.suffix in (".til", ".id0", ".id1", ".id2", ".nam", ".viv"):
            logger.debug("removing: %s", file)
            with contextlib.suppress(IOError):
                file.unlink()

    doc = json.loads(results_path.read_text(encoding="utf-8"))

    plan = []
    for file in sorted(p for p in testfiles.glob("*")):
        if not file.is_file():
            continue

        if file.is_dir():
            continue

        if file.name.startswith("."):
            continue

        if file.suffix not in (".exe_", ".dll_", ".elf_", ""):
            continue

        logger.debug("%s", file.name)
        key = str(file)

        for backend in BACKENDS:
            if (backend, file.name) in {
                ("binja", "0953cc3b77ed2974b09e3a00708f88de931d681e2d0cb64afbaf714610beabe6.exe_")
            }:
                # this file takes 38GB+ and 20hrs+
                # https://github.com/Vector35/binaryninja-api/issues/5951
                continue

            if key in doc[backend]:
                if not args.retry_failures:
                    continue

                if not doc[backend][key]["err"]:
                    # didn't previously fail, don't repeat work
                    continue

                else:
                    # want to retry this previous failure
                    pass

            plan.append((file, backend))

    pool_size = multiprocessing.cpu_count() // 2
    logger.info("work pool size: %d", pool_size)
    with Pool(processes=pool_size) as pool:
        for i, result in enumerate(pool.imap_unordered(wrapper_invoke_capa, plan)):
            doc[result.backend][str(result.path)] = {
                "path": str(result.path),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "err": result.err,
                "duration": result.duration,
            }

            if i % 8 == 0:
                logger.info("syncing output database")
                results_path.write_text(json.dumps(doc))

            logger.info(
                "%.1f\t%s %s %s",
                result.duration,
                "(err)" if result.err else "     ",
                result.backend.ljust(8),
                result.path.name,
            )

    results_path.write_text(json.dumps(doc))
    return


def report(args):
    doc = json.loads(args.results_path.read_text(encoding="utf-8"))

    samples = set()
    for backend in BACKENDS:
        samples.update(doc[backend].keys())

    failures_by_backend: dict[str, set[str]] = {backend: set() for backend in BACKENDS}
    durations_by_backend: dict[str, list[float]] = {backend: [] for backend in BACKENDS}

    console = rich.get_console()
    for key in sorted(samples):
        sample = Path(key).name
        console.print(sample, style="bold")

        seen_rules: Counter[str] = Counter()

        rules_by_backend: dict[str, set[str]] = {backend: set() for backend in BACKENDS}

        for backend in BACKENDS:
            if key not in doc[backend]:
                continue

            entry = doc[backend][key]
            duration = entry["duration"]

            if not entry["err"]:
                matches = json.loads(entry["stdout"])["rules"].keys()
                seen_rules.update(matches)
                rules_by_backend[backend].update(matches)
                durations_by_backend[backend].append(duration)

                console.print(f"  {backend: >8}: {duration: >6.1f}s   {len(matches): >3d} matches")

            else:
                failures_by_backend[backend].add(sample)
                console.print(f"  {backend: >8}: {duration: >6.1f}s   (error)")

        if not seen_rules:
            console.print()
            continue

        t = rich.table.Table(box=rich.box.SIMPLE, header_style="default")
        t.add_column("viv")
        t.add_column("ida")
        t.add_column("bn")
        t.add_column("rule")

        for rule, _ in seen_rules.most_common():
            t.add_row(
                "x" if rule in rules_by_backend["vivisect"] else " ",
                "x" if rule in rules_by_backend["ida"] else " ",
                "x" if rule in rules_by_backend["binja"] else " ",
                rule,
            )

        console.print(t)

    for backend in BACKENDS:
        console.print(f"failures for {backend}:", style="bold")
        for failure in sorted(failures_by_backend[backend]):
            console.print(f"  - {failure}")

        if not failures_by_backend[backend]:
            console.print("  (none)", style="green")
    console.print()

    console.print("durations:", style="bold")
    console.print("  (10-quantiles, in seconds)", style="grey37")
    for backend in BACKENDS:
        q = statistics.quantiles(durations_by_backend[backend], n=10)
        console.print(f"  {backend: <8}: ", end="")
        for i in range(9):
            if i in (4, 8):
                style = "bold"
            else:
                style = "default"
            console.print(f"{q[i]: >6.1f}", style=style, end=" ")
        console.print()
    console.print("                ^-- 10% of samples took less than this                  ^", style="grey37")
    console.print("                    10% of samples took more than this -----------------+", style="grey37")

    console.print()
    for backend in BACKENDS:
        total = sum(durations_by_backend[backend])
        successes = len(durations_by_backend[backend])
        avg = statistics.mean(durations_by_backend[backend])
        console.print(
            f"  {backend: <8}: {total: >7.0f} seconds across {successes: >4d} successful runs, {avg: >4.1f} average"
        )
    console.print()

    console.print("slowest samples:", style="bold")
    for backend in BACKENDS:
        console.print(backend)
        for duration, path in sorted(
            ((d["duration"], Path(d["path"]).name) for d in doc[backend].values()), reverse=True
        )[:5]:
            console.print(f"  - {duration: >6.1f} {path}")

    return


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    default_samples_path = Path(__file__).resolve().parent.parent / "tests" / "data"

    parser = argparse.ArgumentParser(description="Compare analysis backends.")
    capa.main.install_common_args(
        parser,
        wanted=set(),
    )

    subparsers = parser.add_subparsers()
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("results_path", type=Path, help="Path to output JSON file")
    collect_parser.add_argument("--samples", type=Path, default=default_samples_path, help="Path to samples")
    collect_parser.add_argument("--retry-failures", action="store_true", help="Retry previous failures")
    collect_parser.set_defaults(func=collect)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("results_path", type=Path, help="Path to JSON file")
    report_parser.set_defaults(func=report)

    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
