# MAPA design

## Architecture

Four layers, each in its own module under the `mapa/` package:

| Module | Responsibility |
|---|---|
| `mapa/model.py` | Backend-neutral dataclasses: `MapaReport`, `MapaMeta`, `MapaSection`, `MapaLibrary`, `MapaFunction`, `MapaCall`, `MapaCaller`, `MapaString`, `AssemblageLocation` |
| `mapa/ida_db.py` | IDA database lifecycle: `resolve_database()`, `open_database_session()`, SHA-256 caching, flock-based concurrency guard |
| `mapa/collector.py` | Populates `MapaReport` from an open `ida_domain.Database`. All IDA queries live here. |
| `mapa/renderer.py` | Rich-based text rendering from `MapaReport`. No IDA dependency. |
| `mapa/cli.py` | Argument parsing, capa/assemblage loading, orchestration |

`scripts/mapa.py` is a thin entry point that delegates to `mapa.cli.main()`.

## Database lifecycle

Modeled on `idals.py` from idawilli:

1. If input is `.i64`/`.idb`, use directly.
2. Otherwise, hash the file (MD5 + SHA-256), check `~/.cache/mandiant/mapa/<sha256>.i64`.
3. On cache miss: acquire advisory flock, create database via `Database.open()` with `IdaCommandOptions(auto_analysis=True, new_database=True, output_database=..., load_resources=True)`, wait for `ida_auto.auto_wait()`.
4. On cache hit or after creation: open read-only with `new_database=False, save_on_close=False`.
5. Concurrency guard: poll for `.nam` file disappearance + `fcntl.flock` on `<db>.lock` + TOCTOU re-check.

## Collector design

The collector builds several indexes before the main function loop:

- **import_index**: `dict[int, (module, name)]` from `db.imports.get_all_imports()`
- **extern_addrs**: `set[int]` from functions in XTRN segments
- **thunk_targets**: `dict[int, int]` via `_resolve_thunk_target()` — follows code refs then data refs, max depth 5, single-target chains only
- **resolved_callers/callees**: built by walking all non-thunk function flowcharts, resolving call targets through thunk chains, classifying as internal vs API

String extraction follows single data-reference chains from each instruction up to depth 10, checking `db.strings.get_at()` at each hop.

## ida-domain API usage

Primary queries used:

- `db.functions` — iteration, `get_at()`, `get_name()`, `get_flags()`, `get_flowchart()`
- `db.segments.get_all()` — section enumeration
- `db.imports.get_all_modules()`, `get_all_imports()` — library/import enumeration
- `db.xrefs.code_refs_from_ea()`, `data_refs_from_ea()`, `calls_from_ea()` — call/thunk resolution
- `db.strings.get_at()` — string lookup
- `db.instructions.is_call_instruction()`, `get_mnemonic()` — instruction classification
- `db.heads.size()` — instruction byte size
- `FlowChart` with `FlowChartFlags.NOEXT | FlowChartFlags.PREDS` — CFG traversal
- `FunctionFlags.THUNK`, `FunctionFlags.LIB` — function classification

No legacy `ida_*` module calls are used. All queries go through `ida-domain`.

## String tagging

Vendored Quantum Strand string databases live under `mapa/string_tags/data/` in five families: OSS/CRT libraries (gzipped JSONL), expert rules (plain JSONL), Windows API names (gzipped text), global prevalence (gzipped JSONL + binary hash files), and junk-code strings (gzipped JSONL).

The `mapa/string_tags/` package has three modules:
- `model.py` — `StringTagMatch` and `StringTagResult` dataclasses
- `loaders.py` — file-format readers using `msgspec`, `gzip`, `hashlib`, and `importlib.resources`
- `tagger.py` — `StringTagger` class with `tag_string(raw) -> StringTagResult`, plus `load_default_tagger()` which lazily loads and caches all databases process-wide

The collector tags raw strings before `rstrip()` trimming. When two raw strings collapse to the same display value, their tags and match metadata are merged. `MapaString` carries `tags: tuple[str, ...]` and `tag_matches: tuple[StringTagMatch, ...]`.

The renderer uses a Rich `Text`-based helper to right-align the visible tag column on `string:` rows. The visible tag policy suppresses `#common` when a more-specific tag is also present.
