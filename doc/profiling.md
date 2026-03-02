# Profiling capa

This document describes a developer workflow for profiling capa runtime and memory.

We intentionally do **not** expose a dedicated `capa --profile` flag or `capa profile` subcommand. Profiling is a developer/research workflow and should not affect normal user-facing CLI behavior.

## Existing profiling helpers

- `scripts/profile-time.py` repeats capability matching and reports timing/evaluation counts.
- `scripts/profile-memory.py` runs repeated analyses and reports memory behavior.

These scripts are useful for establishing a baseline before and after a change.

## Profiling with Scalene

Use Scalene directly against the capa module:

```bash
python -m scalene -m capa.main --format freeze --backend vivisect /path/to/sample
```

Or run a profiling helper under Scalene for repeated measurements:

```bash
python -m scalene scripts/profile-time.py --number 3 --repeat 10 /path/to/sample
```

### Suggested workflow

1. Capture a baseline profile on representative samples.
2. Identify hotspots that are stable across runs.
3. Implement behavior-preserving optimizations.
4. Re-run the same profile commands and compare output.

When sharing results in PRs/issues, include:

- command line used,
- sample(s) analyzed,
- before/after timing or memory summaries,
- confirmation that capa output remains unchanged.
