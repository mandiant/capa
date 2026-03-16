# mapa design

## Architecture

Seven layers, each in its own module under the `mapa/` package:

| Module | Responsibility |
|---|---|
| `mapa/model.py` | Backend-neutral dataclasses: `MapaReport`, `MapaMeta`, `MapaSection`, `MapaLibrary`, `MapaFunction`, `MapaCall`, `MapaCaller`, `MapaString`, `MapaProgramString`, `AssemblageRecord` |
| `mapa/assemblage.py` | Assemblage CSV loading, column validation, SHA-256 filtering, RVA-to-VA conversion, exact-row deduplication |
| `mapa/ida_db.py` | IDA database lifecycle: `resolve_database()`, `open_database_session()`, SHA-256 caching, flock-based concurrency guard |
| `mapa/collector.py` | Populates `MapaReport` from an open `ida_domain.Database`. All IDA queries live here. |
| `mapa/renderer.py` | Rich-based text rendering and plain single-function summary formatting from `MapaReport`. No IDA dependency. |
| `mapa/html_renderer.py` | Self-contained `html-map` rendering from `MapaReport`. No IDA dependency. |
| `mapa/cli.py` | Argument parsing, capa/assemblage loading, output-mode selection, `--open` temp-file/browser handling, orchestration |

`scripts/mapa.py` is a thin entry point that delegates to `mapa.cli.main()`.

The CLI validates output-mode combinations before analysis. For `--output html-map --open`, it renders the HTML once, writes it to a temporary `.html` file via `NamedTemporaryFile(delete=False)`, and opens the browser with `webbrowser.open(file://...)`.

## Database lifecycle

Modeled on `idals.py` from idawilli:

1. If input is `.i64`/`.idb`, use directly.
2. Otherwise, hash the file (MD5 + SHA-256), check `~/.cache/mandiant/mapa/<sha256>.i64`.
3. On cache miss: acquire advisory flock, create database via `Database.open()` with `IdaCommandOptions(auto_analysis=True, new_database=True, output_database=..., load_resources=True)`, wait for `ida_auto.auto_wait()`.
4. On cache hit or after creation: open read-only with `new_database=False, save_on_close=False`.
5. Concurrency guard: poll for `.nam` file disappearance + `fcntl.flock` on `<db>.lock` + TOCTOU re-check.

## Assemblage loading

Assemblage loading is deferred until after mapa opens the IDA database, because the effective sample SHA-256 may come from either the raw input file or the database metadata.

`mapa.assemblage.load_assemblage_records()`:

- reads the CSV with `csv.DictReader`
- requires `hash`, `name`, `start`, `end`, and `source_file`
- filters rows by sample SHA-256, case-insensitively
- converts `start` and `end` RVAs to VAs by adding `db.base_address`
- strips the trailing provenance suffix from `source_file` only at render time, via `AssemblageRecord.source_path`
- deduplicates exact duplicate rows while preserving CSV order for distinct ambiguous matches

The result is `dict[int, list[AssemblageRecord]]`, keyed by function start VA.

## Collector design

The collector builds several indexes before the main function loop:

- import_index: `dict[int, (module, name)]` from `db.imports.get_all_imports()`
- extern_addrs: `set[int]` from functions in XTRN segments
- thunk_targets: `dict[int, int]` via `_resolve_thunk_target()` — follows code refs then data refs, max depth 5, single-target chains only
- resolved_callers/callees: built by walking all non-thunk function flowcharts, resolving call targets through thunk chains, classifying as internal vs API

String extraction follows single data-reference chains from each instruction up to depth 10. The collector returns both the discovered string VA and the raw string value for each hit.

The collector stores string data in two shapes:

- `MapaFunction.strings` for the text report and tooltip summaries. These stay function-local and deduplicate by trimmed display value.
- `MapaReport.program_strings` for `html-map`. These are keyed by string VA, preserve duplicate display values at different addresses, merge tags across repeated references, and track the set of referencing function addresses.

Assemblage data is attached per function during collection. `MapaFunction.assemblage_records` carries zero or more `AssemblageRecord` values for the function start address. The collector does not use Assemblage to rename functions, callers, or callees.

## ida-domain API usage

Primary queries used:

- `db.functions` — iteration, `get_at()`, `get_name()`, `get_flags()`, `get_flowchart()`
- `db.segments.get_all()` — section enumeration
- `db.imports.get_all_modules()`, `get_all_imports()` — library/import enumeration
- `db.xrefs.code_refs_from_ea()`, `data_refs_from_ea()`, `calls_from_ea()` — call/thunk resolution
- `db.instructions.is_call_instruction()`, `get_mnemonic()` — instruction classification
- `db.heads.size()` — instruction byte size
- `FlowChart` with `FlowChartFlags.NOEXT | FlowChartFlags.PREDS` — CFG traversal
- `FunctionFlags.THUNK`, `FunctionFlags.LIB` — function classification

No legacy `ida_*` module calls are used. All queries go through `ida-domain`.

## Rendering

`mapa/renderer.py` prints the text report in function address order. For each function, it prints the IDA-derived header first and then any Assemblage annotations as `assemblage name:` and `assemblage file:` lines. When multiple distinct Assemblage rows map to one function start address, the renderer prints all of them in order.

The text renderer also exposes a plain single-function summary formatter used by `html-map` tooltips. The row order matches text mode: Assemblage lines, xrefs, CFG stats, capa matches, internal calls, APIs, and strings.

For source-file separators, mapa uses the first Assemblage record's normalized source path as the function's primary source path. The text renderer tracks the last seen non-empty primary path across the function list. Missing Assemblage data does not trigger a separator and does not reset that state. When a later function introduces a different primary path, the renderer prints a muted horizontal rule with `[ <path> ]` immediately before that function.

`mapa/html_renderer.py` renders a single self-contained HTML document. It emits a split view: a left function pane and a right string pane, both with independent scrolling. The panes are separated by a draggable vertical divider implemented with a small inline pointer-event handler. The renderer emits one square per function in address order, one program-string row per string VA in address order, tag controls with visible function counts, direction and depth controls for neighborhood traversal, a small legend for heat/seed/dim semantics, right-aligned visible tags in each string row, inline JSON data for function summaries, direct tag memberships, direct string memberships, and caller/callee adjacency, plus a single floating tooltip and a small inline script. That script resolves the active seed source from a hovered or locked function, tag, or string; chooses caller-only, callee-only, or undirected traversal; runs a bounded breadth-first search from each seed; sums geometric-decay contributions using per-seed shortest distance; and renders the result as a heat overlay with a distinct seed outline.

## String tagging

Vendored Quantum Strand string databases live under `mapa/string_tags/data/` in five families: OSS/CRT libraries (gzipped JSONL), expert rules (plain JSONL), Windows API names (gzipped text), global prevalence (gzipped JSONL + binary hash files), and junk-code strings (gzipped JSONL).

The `mapa/string_tags/` package has three modules:
- `model.py` — `StringTagMatch` and `StringTagResult` dataclasses
- `loaders.py` — file-format readers using `msgspec`, `gzip`, `hashlib`, and `importlib.resources`
- `tagger.py` — `StringTagger` class with `tag_string(raw) -> StringTagResult`, plus `load_default_tagger()` which lazily loads and caches all databases process-wide

The collector tags raw strings before `rstrip()` trimming. When two raw strings collapse to the same display value, their tags and match metadata are merged. `MapaString` carries `tags: tuple[str, ...]` and `tag_matches: tuple[StringTagMatch, ...]`.

The text renderer uses a Rich `Text`-based helper to right-align the visible tag column on `string:` rows. The HTML renderer reuses the same visible-tag policy, builds its top tag controls from those visible tags only, shows the distinct-function count for each visible tag, and renders the visible tags right-aligned in each program-string row. The visible tag policy suppresses `#common` when a more-specific tag is also present.
