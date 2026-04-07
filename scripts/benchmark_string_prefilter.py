#!/usr/bin/env python3
"""
Benchmark: string-rule pre-filter speedup (#2126)

Measures wall-clock time for find_static_capabilities() with and without
the string pre-filter (prepare_for_file), so we can quantify the speedup
on real binaries with a full rule set.

Usage:
    python scripts/benchmark_string_prefilter.py [--runs N] [binary ...]

If no binary paths are given the script picks a small representative set
from tests/data/.  Each binary is analysed RUNS times in each mode; the
median is reported.  The script uses the vivisect back-end, which needs no
external tools.

Example:
    python scripts/benchmark_string_prefilter.py --runs 3
"""

import sys
import time
import logging
import pathlib
import argparse
import statistics

# Silence capa progress output during benchmarking.
logging.disable(logging.WARNING)

import capa.main
import capa.rules
import capa.rules.cache
import capa.capabilities.static
from capa.features.common import String

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_ruleset() -> capa.rules.RuleSet:
    rules_path = pathlib.Path(__file__).parent.parent / "rules"
    if not rules_path.is_dir():
        print(f"[!] rules/ directory not found at {rules_path}", file=sys.stderr)
        sys.exit(1)
    return capa.rules.get_rules([rules_path], enable_cache=True)


def _make_extractor(binary_path: pathlib.Path):
    """Return a vivisect StaticFeatureExtractor for *binary_path*, or None."""
    try:
        import capa.loader

        extractor = capa.loader.get_extractor(
            binary_path,
            input_format="auto",
            os_="auto",
            backend=capa.main.BACKEND_VIV,
            sigpaths=[],
            should_save_workspace=False,
            disable_progress=True,
        )
        return extractor
    except Exception as exc:
        print(f"    [!] could not load {binary_path.name}: {exc}", file=sys.stderr)
        return None


def _measure_prefilter(ruleset: capa.rules.RuleSet, extractor) -> tuple[int, int, float]:
    """
    Run prepare_for_file() once and return
    (n_file_strings, n_skipped_rules, overhead_seconds).
    Does not disturb the ruleset state.
    """
    file_strings: frozenset[str] = frozenset(
        feat.value for feat, _ in extractor.extract_file_features() if isinstance(feat, String)
    )
    t0 = time.perf_counter()
    ruleset.prepare_for_file(file_strings)
    t1 = time.perf_counter()
    n_skipped = len(ruleset._impossible_string_rule_names)
    ruleset.prepare_for_file(frozenset())  # restore
    return len(file_strings), n_skipped, (t1 - t0)


def _time_find_capabilities(
    ruleset: capa.rules.RuleSet,
    extractor,
    *,
    prefilter: bool,
    n_runs: int,
) -> tuple[float, int]:
    """
    Run find_static_capabilities() n_runs times and return
    (median_seconds, n_functions).
    """
    durations: list[float] = []
    n_funcs = 0

    original_prepare = capa.rules.RuleSet.prepare_for_file

    if not prefilter:
        # Monkey-patch prepare_for_file to be a no-op so the pre-filter never
        # activates, giving us a clean "before" baseline.
        def _noop(self, file_strings):  # type: ignore[misc]
            self._impossible_string_rule_names = set()

        capa.rules.RuleSet.prepare_for_file = _noop  # type: ignore[method-assign]

    try:
        for _ in range(n_runs):
            t0 = time.perf_counter()
            caps = capa.capabilities.static.find_static_capabilities(ruleset, extractor, disable_progress=True)
            t1 = time.perf_counter()
            durations.append(t1 - t0)

            if n_funcs == 0:
                n_funcs = len(caps.feature_counts.functions)
    finally:
        capa.rules.RuleSet.prepare_for_file = original_prepare  # type: ignore[method-assign]

    return statistics.median(durations), n_funcs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_DEFAULT_SAMPLES = [
    # small – packed/minimal strings
    "tests/data/Practical Malware Analysis Lab 01-02.exe_",
    # medium – typical malware
    "tests/data/0a30182ff3a6b67beb0f2cda9d0de678.exe_",
    "tests/data/7fbc17a09cf5320c515fc1c5ba42c8b3.exe_",
    # larger – more functions
    "tests/data/321338196a46b600ea330fc5d98d0699.exe_",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=3, help="median over this many runs (default: 3)")
    parser.add_argument("binaries", nargs="*", metavar="BINARY", help="binary paths to benchmark")
    args = parser.parse_args()

    root = pathlib.Path(__file__).parent.parent
    if args.binaries:
        samples = [pathlib.Path(b) for b in args.binaries]
    else:
        samples = [root / s for s in _DEFAULT_SAMPLES]
        samples = [s for s in samples if s.exists()]

    if not samples:
        print("[!] no sample files found; pass binary paths explicitly", file=sys.stderr)
        sys.exit(1)

    print("Loading rules \u2026", end="", flush=True)
    ruleset = _load_ruleset()

    # Count unique string-dependent rules across all scopes.
    seen: set[str] = set()
    for fi in ruleset._feature_indexes_by_scopes.values():
        seen.update(fi.string_rules.keys())
    n_string_rules = len(seen)
    print(f" {len(ruleset.rules)} rules total, {n_string_rules} string-dependent")
    print()

    col_w = 44
    hdr = (
        f"{'Binary':<{col_w}}  {'Funcs':>6}  {'Strs':>7}  "
        f"{'w/o filter':>10}  {'w/ filter':>10}  "
        f"{'Speedup':>7}  {'Overhead':>8}  {'Net gain':>8}  {'Skipped':>12}"
    )
    print(hdr)
    print("-" * len(hdr))

    for sample in samples:
        name = sample.name
        if len(name) > col_w - 1:
            name = "…" + name[-(col_w - 2) :]

        extractor = _make_extractor(sample)
        if extractor is None:
            continue

        # Measure prepare_for_file overhead and skipped rule count.
        n_file_strings, n_skipped, t_overhead = _measure_prefilter(ruleset, extractor)

        print(f"  {name:<{col_w - 2}}  ", end="", flush=True)

        # "Before": no prefilter
        t_before, n_funcs = _time_find_capabilities(ruleset, extractor, prefilter=False, n_runs=args.runs)

        # "After": with prefilter
        t_after, _ = _time_find_capabilities(ruleset, extractor, prefilter=True, n_runs=args.runs)

        saved = t_before - t_after
        speedup = t_before / t_after if t_after > 0 else float("inf")
        pct_skipped = 100.0 * n_skipped / n_string_rules if n_string_rules else 0.0
        # Net gain = saved matching time minus upfront overhead
        net = saved - t_overhead

        print(
            f"{n_funcs:>6}  {n_file_strings:>7}  {t_before:>9.2f}s  {t_after:>9.2f}s  "
            f"{speedup:>6.2f}x  {t_overhead*1000:>6.0f}ms  {net*1000:>+7.0f}ms  "
            f"{n_skipped:>4}/{n_string_rules} ({pct_skipped:.0f}%)"
        )

    print()
    print("Notes:")
    print(f"  Times are median over {args.runs} run(s); perf_counter precision.")
    print("  'w/o filter' patches prepare_for_file() to a no-op (clean baseline).")
    print("  'Overhead' = wall time of prepare_for_file() alone (one-time cost per binary).")
    print("  'Net gain' = (w/o filter - w/ filter) - Overhead; positive = faster overall.")
    print("  'Skipped' = string rules pruned because patterns are absent from the binary.")
    print("  'Strs'    = distinct String values found in the binary at file scope.")


if __name__ == "__main__":
    main()
