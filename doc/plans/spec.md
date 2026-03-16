# mapa specification

mapa renders either a structured text report or a self-contained HTML map of a binary's function map: metadata, sections, import libraries, and a per-function breakdown of callers, callees, API calls, strings, CFG stats, capa rule matches, and optional Assemblage ground truth.

## Invocation

```
python scripts/mapa.py <input_file> [--capa <capa.json>] [--assemblage <functions.csv>] [--output {text,html-map}] [--open] [--verbose] [--quiet]
```

`input_file` accepts raw binaries (PE, ELF), existing IDA databases (`.i64`, `.idb`), or any file IDA can analyze. For raw files, mapa automatically creates and caches an analyzed IDA database under the XDG cache root (`$XDG_CACHE_HOME/mandiant/mapa/` or `~/.cache/mandiant/mapa/`) keyed by the file's SHA-256 hash.

## Backend

IDALib only. All analysis uses `ida-domain` as the primary query API. The Lancelot/BinExport2 backend has been removed.

## Output modes

`text` is the default. It renders the existing structured terminal report to stdout.

`html-map` renders a single standalone HTML document to stdout. The page inlines all HTML, CSS, JavaScript, and data. It has a compact metadata summary and tag control strip at the top, then a split view below. The left pane contains the function grid and the right pane contains the program-string list.

The two panes scroll independently. A draggable vertical divider lets the user resize the panes horizontally. Function squares stay in function-address order and still use the naive left-to-right wrapping layout, but they now wrap within the current width of the left pane rather than the full page width.

Function squares are fixed small blocks laid out left-to-right and wrapped responsively within the left pane. Hovering a tag highlights matching functions by border color and dims non-matches. Clicking a tag locks or unlocks that tag selection. Hovering a string row highlights matching functions by fill color and dims non-matches. Clicking a string row locks or unlocks that string selection. When both a tag and a string are active, a function stays emphasized if it matches either one.

The tag strip is sorted by descending distinct-function count, then tag name, and each control shows that count. The page also shows a small legend describing border, fill, and dim states. The string list shows each string's virtual address explicitly, preserves duplicate display values at different addresses, and shows visible tags right-aligned in each row. Function hover shows a tooltip containing the same single-function mapa summary content as text mode. Top-level tag controls use only string tags. Capa rule names are not included there.

`--open` is only valid with `--output html-map`. In that mode, mapa writes the HTML to a temporary `.html` file, opens the user's local web browser on the corresponding `file://` URL, and does not write the HTML document to stdout.

The visible-tag policy is the same in both modes: hide `#common` when a more-specific tag is present, but keep it visible when it is the only tag.

## Report sections

The text report renders these sections in order:

1. meta — file name, SHA-256, architecture, timestamp
2. sections — memory segments with address, permissions (rwx), and size
3. libraries — import modules
4. functions — per-function detail in address order

### Functions section

Each function renders as either `thunk <name> @ <address>` or `function <name> @ <address>` followed by:

- source-file separator — a horizontal rule inserted before a function when its primary Assemblage source path differs from the last seen non-empty source path
- `assemblage name:` — source function name from Assemblage, when available
- `assemblage file:` — source file path from Assemblage, when available
- `xref:` — callers with direction arrow and function-order delta
- `B/E/I:` — basic blocks / CFG edges / instructions (total bytes)
- `capa:` — matched capa rule names
- `calls:` — internal non-library callees with direction and delta
- `api:` — import/external/library callees
- `string:` — referenced strings (deduplicated, whitespace-trimmed), with optional right-aligned database tags

Thunk functions show only the header plus any Assemblage lines.

### Assemblage overlay

When `--assemblage` is provided, mapa reads a CSV file and requires these columns: `hash`, `name`, `start`, `end`, and `source_file`.

Assemblage matching works like this:

- mapa resolves the sample SHA-256 from the input file or the opened IDA database.
- mapa keeps only CSV rows whose `hash` matches that SHA-256, case-insensitively.
- mapa treats `start` and `end` as RVAs and adds the IDA database base address to map them to function VAs.
- mapa does not rename functions, callers, or callees from Assemblage data. The displayed function header stays IDA-derived.
- mapa strips the trailing provenance suffix from `source_file` before rendering, for example `C:\src\foo.c (MD5: ...)` renders as `C:\src\foo.c`.
- Exact duplicate CSV rows are deduplicated. If multiple distinct Assemblage rows map to the same function address, mapa renders all of them in CSV order.
- For source-file separators, mapa uses the first Assemblage record's normalized `source_file` path as the function's primary source path.
- Missing Assemblage data does not start or end a source-file run. It does not trigger a separator and does not reset the last seen non-empty source path.
- When a later function has a different primary source path from the last seen non-empty source path, mapa inserts a separator immediately before that function.

## Deliberate interface changes from the Lancelot/BinExport2 version

- The `modules` section has been removed. BinExport2's module concept has no IDA equivalent.

## Decisions

- 2026-03-16: Lumina disabled during database creation via `IdaCommandOptions(plugin_options="lumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0")`, matching capa's `loader.py`. The `plugin_options` field maps to IDA's `-O` switch; embedding `-O` in the value for the second option works because `build_args()` concatenates it verbatim. Resource loading enabled via `load_resources=True` (maps to `-R`).
- 2026-03-16: Cache directory is `$XDG_CACHE_HOME/mandiant/mapa/` (or `~/.cache/mandiant/mapa/`). Separate from idals cache.
- 2026-03-16: `meta.ts` is `datetime.now(UTC).isoformat()` — no longer sourced from BinExport2.
- 2026-03-16: Thunk chain depth limit is 5 (matches capa's `THUNK_CHAIN_DEPTH_DELTA`).
- 2026-03-16: CFG stats use `FlowChartFlags.NOEXT | FlowChartFlags.PREDS` to match capa's block enumeration semantics.
- 2026-03-16: String extraction follows single data-reference chains up to depth 10, matching capa's `find_data_reference_from_insn`.
- 2026-03-16: String rows may carry right-aligned database tags derived from vendored Quantum Strand string databases. Tags include `#<library>` (e.g. `#zlib`, `#openssl`), `#msvc`, `#capa`, `#winapi`, `#common`, and `#code-junk`. Visible tag policy: `#common` is hidden when a more-specific tag is present; `#code-junk` is always shown. Tags are matched against the raw (untrimmed) string value. The underlying model preserves all match metadata even when the renderer suppresses a visible tag.
- 2026-03-16: Assemblage input is a CSV keyed by sample SHA-256. mapa matches rows by `hash`, converts `start`/`end` RVAs to VAs using the database base address, annotates functions with `assemblage name:` and `assemblage file:` lines, and does not override IDA-derived function names.
- 2026-03-16: `--output html-map` uses only string tags in the top control strip, sorts them by descending distinct-function count then name, shows those counts in the controls, applies union semantics when both a tag and string selection are active, and lists program strings by string VA with explicit addresses.
- 2026-03-16: `--output html-map` uses a split view with independently scrolling function and string panes, a draggable vertical divider, and right-aligned visible tags in each string row.
- 2026-03-16: `--open` is valid only with `--output html-map`. It writes the HTML report to a temporary `.html` file and opens the local browser on that file instead of writing the HTML to stdout.
