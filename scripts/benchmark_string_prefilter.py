#!/usr/bin/env python3
"""
Benchmark: string-rule pre-filter speedup (#2126)

Measures wall-clock time for find_static_capabilities() with and without
the string pre-filter (prepare_for_file), so we can quantify the speedup
on real binaries with a full rule set.

Usage:
    python scripts/benchmark_string_prefilter.py [--runs N] [binary ...]

If no binary paths are given the script picks a representative set from
tests/data/ spanning small/medium/large binaries.  Each binary is analysed
RUNS times in each mode; the median is reported.  Runs are interleaved
(W/O, W/, W/O, W/, ...) to reduce load-spike bias.

A parity check is performed for every binary: matched rule names and
addresses must be identical with and without the pre-filter.  FAIL means
a correctness regression.

Example:
    python scripts/benchmark_string_prefilter.py --runs 5
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


def _verify_parity(ruleset: capa.rules.RuleSet, extractor) -> tuple[bool, str]:
    """
    Run find_static_capabilities() with and without the pre-filter and
    confirm that the set of matched (rule_name, address) pairs is identical.

    Returns (ok: bool, detail: str).  ok=True means no semantic drift.
    """
    original_prepare = capa.rules.RuleSet.prepare_for_file

    # run WITHOUT pre-filter
    def _noop(self, file_strings):  # type: ignore[misc]
        self._impossible_string_rule_names = set()

    capa.rules.RuleSet.prepare_for_file = _noop  # type: ignore[method-assign]
    try:
        caps_without = capa.capabilities.static.find_static_capabilities(ruleset, extractor, disable_progress=True)
    finally:
        capa.rules.RuleSet.prepare_for_file = original_prepare  # type: ignore[method-assign]

    # Build (rule_name, addr_repr) sets -- exclude subscope rules
    def _rule_addr_set(caps):
        result: set[tuple[str, str]] = set()
        for rule_name, matches in caps.matches.items():
            if ruleset.rules[rule_name].is_subscope_rule():
                continue
            for addr, _ in matches:
                result.add((rule_name, repr(addr)))
        return result

    without_set = _rule_addr_set(caps_without)

    # run WITH pre-filter (normal path)
    caps_with = capa.capabilities.static.find_static_capabilities(ruleset, extractor, disable_progress=True)
    with_set = _rule_addr_set(caps_with)

    if without_set == with_set:
        return True, "PASS"

    extra = with_set - without_set
    missing = without_set - with_set
    parts = []
    if missing:
        rules_missing = {r for r, _ in missing}
        parts.append(f"MISSING {len(missing)} matches in {len(rules_missing)} rules")
    if extra:
        rules_extra = {r for r, _ in extra}
        parts.append(f"EXTRA {len(extra)} matches in {len(rules_extra)} rules")
    return False, "FAIL: " + "; ".join(parts)


def _time_interleaved(
    ruleset: capa.rules.RuleSet,
    extractor,
    n_runs: int,
) -> tuple[float, float, int]:
    """
    Alternate WITHOUT / WITH runs to reduce load-spike variance bias.
    Returns (median_without, median_with, n_functions).
    """
    original_prepare = capa.rules.RuleSet.prepare_for_file

    def _noop(self, file_strings):  # type: ignore[misc]
        self._impossible_string_rule_names = set()

    without_times: list[float] = []
    with_times: list[float] = []
    n_funcs = 0

    for _ in range(n_runs):
        # WITHOUT
        capa.rules.RuleSet.prepare_for_file = _noop  # type: ignore[method-assign]
        try:
            t0 = time.perf_counter()
            caps = capa.capabilities.static.find_static_capabilities(ruleset, extractor, disable_progress=True)
            t1 = time.perf_counter()
        finally:
            capa.rules.RuleSet.prepare_for_file = original_prepare  # type: ignore[method-assign]
        without_times.append(t1 - t0)
        if n_funcs == 0:
            n_funcs = len(caps.feature_counts.functions)

        # WITH
        t0 = time.perf_counter()
        capa.capabilities.static.find_static_capabilities(ruleset, extractor, disable_progress=True)
        t1 = time.perf_counter()
        with_times.append(t1 - t0)

    return statistics.median(without_times), statistics.median(with_times), n_funcs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# 8 binaries spanning: tiny / small / medium-low / medium / medium-high / large.
_DEFAULT_SAMPLES = [
    # tiny -- packed, minimal strings (~3 KB)
    "tests/data/Practical Malware Analysis Lab 01-02.exe_",
    # small -- simple loader (~17 KB)
    "tests/data/4f509bdfe5a2fe4320cdc070eedc0a72e12cc08f43d60a7701305b3d1408102b.exe_",
    # small-medium -- typical downloader (~45 KB)
    "tests/data/7d16efd0078f22c17a4bd78b0f0cc468.exe_",
    # medium-low -- common malware (~120 KB)
    "tests/data/0a30182ff3a6b67beb0f2cda9d0de678.exe_",
    # medium -- string-heavy sample (~180 KB)
    "tests/data/7fbc17a09cf5320c515fc1c5ba42c8b3.exe_",
    # medium-high -- larger malware (~410 KB)
    "tests/data/152d4c9f63efb332ccb134c6953c0104.exe_",
    # large -- complex binary (~486 KB)
    "tests/data/321338196a46b600ea330fc5d98d0699.exe_",
    # extra-large -- many functions (~982 KB)
    "tests/data/82bf6347acf15e5d883715dc289d8a2b.exe_",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=3, help="median over this many runs (default: 3)")
    parser.add_argument(
        "--skip-parity", action="store_true", help="skip the correctness parity check (faster, less safe)"
    )
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

    print("Loading rules ...", end="", flush=True)
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
        f"{'Speedup':>7}  {'Overhead':>8}  {'Net gain':>8}  {'Skipped':>12}  {'Parity':>6}"
    )
    print(hdr)
    print("-" * len(hdr))

    speedups: list[float] = []
    parity_failures: list[str] = []

    for sample in samples:
        name = sample.name
        if len(name) > col_w - 1:
            name = "..." + name[-(col_w - 4) :]

        extractor = _make_extractor(sample)
        if extractor is None:
            continue

        # Measure prepare_for_file overhead and skipped rule count.
        n_file_strings, n_skipped, t_overhead = _measure_prefilter(ruleset, extractor)

        print(f"  {name:<{col_w - 2}}  ", end="", flush=True)

        # Parity check (unless --skip-parity).
        if not args.skip_parity:
            parity_ok, parity_detail = _verify_parity(ruleset, extractor)
            if not parity_ok:
                parity_failures.append(f"{sample.name}: {parity_detail}")
        else:
            parity_ok, parity_detail = True, "SKIP"

        # Interleaved timing (alternates W/O -> W/ each run to reduce bias).
        t_before, t_after, n_funcs = _time_interleaved(ruleset, extractor, args.runs)

        # t_after already includes the prepare_for_file overhead, so the true
        # wall-clock net gain is simply t_before - t_after.
        net = t_before - t_after
        speedup = t_before / t_after if t_after > 0 else float("inf")
        pct_skipped = 100.0 * n_skipped / n_string_rules if n_string_rules else 0.0
        speedups.append(speedup)

        parity_str = parity_detail if parity_detail in ("PASS", "SKIP") else "FAIL"

        print(
            f"{n_funcs:>6}  {n_file_strings:>7}  {t_before:>9.2f}s  {t_after:>9.2f}s  "
            f"{speedup:>6.2f}x  {t_overhead * 1000:>6.0f}ms  {net * 1000:>+7.0f}ms  "
            f"{n_skipped:>4}/{n_string_rules} ({pct_skipped:.0f}%)  {parity_str:>6}"
        )

    print()

    if speedups:
        geomean = 1.0
        for s in speedups:
            geomean *= s
        geomean **= 1.0 / len(speedups)
        print(f"Geometric mean speedup across {len(speedups)} binaries: {geomean:.2f}x")

    if parity_failures:
        print()
        print(f"[!] PARITY FAILURES ({len(parity_failures)}):")
        for msg in parity_failures:
            print(f"    {msg}")
    elif not args.skip_parity:
        print("All parity checks PASSED -- no semantic drift introduced by pre-filter.")

    print()
    print("Notes:")
    print(f"  Times are median over {args.runs} run(s), interleaved W/O -> W/ to reduce load-spike bias.")
    print("  'w/o filter' patches prepare_for_file() to a no-op (clean baseline).")
    print("  'Overhead' = wall time of prepare_for_file() alone (informational).")
    print("  'Net gain' = w/o filter - w/ filter; t_after includes overhead, so this")
    print("               is the true end-to-end wall-clock delta. Positive = faster.")
    print("  'Skipped'  = string rules pruned because patterns are absent from the binary.")
    print("  'Strs'     = distinct String values found in the binary at file scope.")
    print("  'Parity'   = PASS means matched (rule, address) pairs are identical with/without filter.")


if __name__ == "__main__":
    main()
