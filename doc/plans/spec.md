# MAPA specification

MAPA renders a structured text report of a binary's function map: metadata, sections, import libraries, and a per-function breakdown of callers, callees, API calls, strings, CFG stats, and capa rule matches.

## Invocation

```
python scripts/mapa.py <input_file> [--capa <capa.json>] [--assemblage <locations.jsonl>] [--verbose] [--quiet]
```

`input_file` accepts raw binaries (PE, ELF), existing IDA databases (`.i64`, `.idb`), or any file IDA can analyze. For raw files, MAPA automatically creates and caches an analyzed IDA database under the XDG cache root (`$XDG_CACHE_HOME/mandiant/mapa/` or `~/.cache/mandiant/mapa/`) keyed by the file's SHA-256 hash.

## Backend

IDALib only. All analysis uses `ida-domain` as the primary query API. The Lancelot/BinExport2 backend has been removed.

## Report sections

The report renders these sections in order:

1. **meta** — file name, SHA-256, architecture, timestamp
2. **sections** — memory segments with address, permissions (rwx), and size
3. **libraries** — import modules
4. **functions** — per-function detail in address order

### Functions section

Each function renders as either `thunk <name> @ <address>` or `function <name> @ <address>` followed by:

- `xref:` — callers with direction arrow and function-order delta
- `B/E/I:` — basic blocks / CFG edges / instructions (total bytes)
- `capa:` — matched capa rule names
- `calls:` — internal non-library callees with direction and delta
- `api:` — import/external/library callees
- `string:` — referenced strings (deduplicated, whitespace-trimmed), with optional right-aligned database tags

Thunk functions show only the header, no body.

When Assemblage data is provided, adjacent functions are grouped by source file path, and function names are overridden with Assemblage names.

## Deliberate interface changes from the Lancelot/BinExport2 version

- The `modules` section has been removed. BinExport2's module concept has no IDA equivalent.

## Decisions

- **2026-03-16**: Lumina disabled during database creation via `IdaCommandOptions(plugin_options="lumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0")`, matching capa's `loader.py`. The `plugin_options` field maps to IDA's `-O` switch; embedding `-O` in the value for the second option works because `build_args()` concatenates it verbatim. Resource loading enabled via `load_resources=True` (maps to `-R`).
- **2026-03-16**: Cache directory is `$XDG_CACHE_HOME/mandiant/mapa/` (or `~/.cache/mandiant/mapa/`). Separate from idals cache.
- **2026-03-16**: `meta.ts` is `datetime.now(UTC).isoformat()` — no longer sourced from BinExport2.
- **2026-03-16**: Thunk chain depth limit is 5 (matches capa's `THUNK_CHAIN_DEPTH_DELTA`).
- **2026-03-16**: CFG stats use `FlowChartFlags.NOEXT | FlowChartFlags.PREDS` to match capa's block enumeration semantics.
- **2026-03-16**: String extraction follows single data-reference chains up to depth 10, matching capa's `find_data_reference_from_insn`.
- **2026-03-16**: String rows may carry right-aligned database tags derived from vendored Quantum Strand string databases. Tags include `#<library>` (e.g. `#zlib`, `#openssl`), `#msvc`, `#capa`, `#winapi`, `#common`, and `#code-junk`. Visible tag policy: `#common` is hidden when a more-specific tag is present; `#code-junk` is always shown. Tags are matched against the raw (untrimmed) string value. The underlying model preserves all match metadata even when the renderer suppresses a visible tag.
