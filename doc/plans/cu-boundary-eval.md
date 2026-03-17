# Compilation Unit Boundary Evaluation

Ground truth data from assemblage: ~500K binaries with PDB-derived source file mappings, ~1000 functions each. This document describes how to turn that data into a repeatable evaluation pipeline for CU boundary detection.

## Ground truth definition

Each function in a binary has a source file path from debug info. Source files are either **impl files** (`.c`, `.cpp`, `.cc`, `.cxx`) or **headers** (`.h`, `.hpp`, extensionless STL headers like `vector`, `xmemory`, etc.). A compilation unit is defined by its impl file — header-sourced functions are template instantiations or inline expansions compiled into whichever CU includes them.

To assign each function to a CU:

1. Sort functions by start address.
2. For each function, if its source is an impl file, that's its CU.
3. Otherwise, forward-fill: inherit the CU of the most recent preceding impl function. If none exists (header functions at the start of the binary), backward-fill from the first impl file.
4. Ground truth boundaries = the set of gap indices where `CU[i] != CU[i-1]`.

This assignment was validated on 10 binaries (21K functions). Every ground truth boundary has an impl file on at least one side — there are zero boundaries where both flanking functions come from headers. Forward-fill produces CU fragmentation ratios of 1.0-1.2x (nearly perfectly contiguous CUs).

## What the data looks like

Source file paths fall into classifiable categories based on filesystem structure. User code lives under `c:\assemblage\builds\HASH\PROJECT\*.cpp` (not under `external/`). Vendored libraries are at `...\PROJECT\external\LIBNAME\*`. MSVC STL headers are under `C:\Program Files\...\MSVC\...\include\` (e.g., `vector`, `xmemory`). CRT sources come from `D:\a\_work\...\vctools\crt\...` or `d:\th\minkernel\crts\...`.

Library identity is derivable from the path prefix. The assemblage build system makes external libraries explicit via the `external/LIBNAME/` convention.

### Template/STL interleaving

Functions from STL headers appear heavily interspersed within CUs. In SmxDecompiler.exe, 72% of functions come from MSVC STL headers, appearing in runs of up to 258 functions within a single CU. These are per-CU template instantiation copies (the same `std::_Verify_range` appears in 4 different CUs), not independent entities.

This means "source file changed" is a terrible boundary signal because it fires on every header-to-impl or header-to-header transition within a CU. On 3DSIFT.exe (heavy Eigen template use), source-file-change achieves only 3% precision. The actual CU boundary rate is low: only 5.9% of all inter-function gaps are real CU boundaries.

### CRT fragmentation

CRT code (from the ucrt static library) shows heavy fragmentation: dozens of tiny 1-3 function CUs interleaved by the linker. These are the hardest boundaries to detect and arguably the least useful to distinguish (separating `delete_scalar.cpp` from `new_array.cpp` has limited practical value). Consider collapsing all CRT functions into a single "CRT" meta-CU for scoring, or reporting CRT and non-CRT scores separately.

### Multi-fragment CUs

Some impl files appear in non-contiguous blocks (e.g., `inflate.c` interrupted by `infback.c`/`inffast.c` in zlib). This is uncommon in application code but frequent in CRT. For boundary scoring, treat each contiguous fragment as its own segment — the metric measures where transitions occur regardless of whether distant segments share a label.

## Metrics

### Primary: Boundary F1

For a predicted set of boundary gap indices vs the ground truth set, compute precision (fraction of predicted boundaries that are real), recall (fraction of real boundaries that are predicted), and F1 (harmonic mean). This directly measures the "where are the seams?" question. It's strict: a boundary predicted one function off from the true position scores as one FP + one FN.

### Secondary: WindowDiff

Standard text segmentation metric, more forgiving of near-misses. Slides a window of size `k` across the sequence and counts positions where the number of boundaries within the window differs between prediction and ground truth. Lower is better. Use `k = avg_segment_length / 2`.

### Library-level metrics

| Problem | Ground truth | Metric |
|---------|-------------|--------|
| CU boundaries | Impl-file assignment (above) | Boundary F1 + WindowDiff |
| Library clustering | Path-derived category (user-code, external:zlib, crt, msvc-stdlib, ...) | Adjusted Rand Index |
| User vs library | Binary classification from category | Per-function accuracy |

These are separate evaluations that can be run independently and solved in order: CU boundaries first, then library grouping, then user/library classification.

## Baseline results

Tested on the 10-binary sample (21K functions, 1238 CU boundaries):

| Heuristic | Precision | Recall | F1 range |
|-----------|-----------|--------|----------|
| No boundaries | - | 0.00 | 0.00 |
| Every source-file change | 0.03-0.79 | 1.00 | 0.06-0.88 |
| Category change | 0.11-0.50 | 0.02-0.28 | 0.04-0.29 |
| Impl-file stream tracking | 1.00 | 1.00 | 1.00 |

The impl-file oracle (skip headers, flag when the .c/.cpp changes) achieves perfect F1. This is the ceiling; it confirms that CU boundaries are exactly the impl-file transitions in the source data. The gap between the naive baselines and this oracle is the space we're trying to close using binary-level features.

## Evaluation pipeline

### Step 1: Ground truth extraction

From debug info, produce a normalized table per binary:

```
binary_hash | func_index | func_start | func_end | cu_id | library_category
```

`cu_id` is the impl file path (or a hash of it). `library_category` is derived from the path prefix. Store as Parquet or SQLite since the CSV format won't scale to 500K binaries.

Pre-compute per-binary boundary sets as arrays of gap indices.

### Step 2: Predictor interface

A predictor takes a binary's function list (start addresses and sizes only, no source info, no debug info) and returns a set of predicted boundary indices. The predictor can use any features extractable from the raw binary: inter-function gap sizes and padding patterns, call graph edge density across each gap, data reference patterns, string attribution, function naming (if symbols present), alignment byte patterns, etc.

### Step 3: Scoring

For each binary, compute boundary F1 between prediction and ground truth. Aggregate across the dataset:

Report both macro-average (mean F1 across binaries, treating each binary equally) and micro-average (pool all gaps, compute F1 once, biased toward larger binaries). Add per-category breakdowns (user code only, CRT only, etc.) to understand where the predictor succeeds and fails.

### Step 4: Iterate

Try different feature combinations and scoring strategies, compare F1. Per mapa-cu-ideas.md, the boundary scorer is the spine of the pipeline and every algorithm becomes a feature generator for gap scoring.

## Design decisions

Boundary F1 was chosen over clustering metrics (ARI, NMI) because those conflate boundary detection with label assignment. We want to decouple the two: find boundaries first, then label segments.

Forward-fill for CU assignment matches how compilation works. The compiler processes the impl file's own functions first, then template instantiations from included headers. Header functions belong to the most recent impl file. The 1.0-1.2x fragmentation ratio validates this model.

Header-to-header transitions are never counted as boundaries because the data shows zero CU boundaries where both flanking functions come from headers. Every CU has at least one impl file as its root. Template instantiations from different headers within the same CU are not separate CUs.
