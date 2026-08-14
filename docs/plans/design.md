# code-oriented-capa: Design

## Architecture

The script has three phases:

```
[1. Analysis] → [2. Inversion] → [3. Rendering]
```

### Phase 1: Analysis

Either run capa with the idalib backend against the input binary, or load a
pre-computed ResultDocument from JSON. In both cases the output is a
`rd.ResultDocument`.

The database is resolved and opened first in either case, since disassembly and
pseudocode come from IDA regardless of where the results came from. With
`--json` the extractor goes unused, but the open database is what feeds the
rendering phase.

When running analysis:
1. `resolve_database()` then `open_database_session()` open the database, and
   `get_ida_extractor()` wraps it in an `IdaFeatureExtractor`
2. `capa.capabilities.common.find_capabilities()` to run matching
3. `capa.loader.collect_metadata()` + `compute_layout()` for metadata
4. `rd.ResultDocument.from_capa()` to build the result document

`collect_metadata()` receives the original input path, so hashes and file
metadata describe the sample itself.

### Phase 2: Inversion

Walk the ResultDocument to build a per-function annotation map, then
reorganize into rule-first order.

**Data structures:**

```python
@dataclass
class Annotation:
    address: int                    # instruction VA
    feature_type: str               # "api", "number", "mnemonic", etc.
    feature_value: str              # "kernel32.CreatePipe", "0x101", etc.
    description: str                # "STARTF_USESTDHANDLES | ..."
    rule_name: str                  # top-level rule this contributes to
    rule_namespace: str | None
    attack_ids: list[str]           # ["T1059.003"]

@dataclass
class RuleSummary:
    name: str
    namespace: str | None
    attack_ids: list[str]
    mbc_ids: list[str]

@dataclass
class FunctionAnnotations:
    address: int
    name: str                       # from IDA
    annotations: list[Annotation]   # sorted by address
    rules: list[RuleSummary]        # all rules matching this function
    file_scope_features: list[FileScopeFeature]

@dataclass
class DisasmLine:
    address: int
    text: str                       # plain text (tags removed)
    tagged_text: str                # IDA-tagged text for syntax highlighting
```

**Inversion algorithm:**

For each rule in `capability_rules(doc)`:
  For each `(match_addr, match)` in rule.matches:
    Recursively walk the Match tree, collecting leaf FeatureNode addresses.
    For each leaf with locations, create Annotation objects.
    Map each annotation's address → parent function (using the layout's
    function/BB hierarchy).
    Also collect file-scope features (import, export, section, function-name)
    into separate FileScopeFeature objects.

Group annotations by function address. Sort functions by VA.

**Rule-first reorganization:**

Inversion also returns the rule list in ResultDocument order (the order
`capability_rules(doc)` yields them). `render_all` iterates rules in this
document order, then functions within each rule by VA. For each (rule,
function) pair, it filters annotations to only those from that rule.

### Phase 3: Rendering

Buffered rendering with connecting spine and adaptive layout.

**Iteration order:** For each rule → for each matching function (by VA):

1. **Build separate buffers**: Render header metadata, disassembly, and
   pseudocode into three independent `BufferedLine` lists. Each line is
   tagged with a spine role (`rule_header`, `annotation_label`, `normal`).

2. **Choose layout**: Measure the max plain-text width of each buffer.
   If pseudocode is available and `left_width + 3 + right_width` fits
   within the terminal width, use side-by-side layout. Otherwise use
   vertical layout.

3. **Compose**:
   - **Side-by-side**: `render_side_by_side()` merges header + left + right
     with a center spine. The header spans above both columns, the spine
     runs vertically between them. Left annotation labels connect to the
     spine with `─┤`/`─┘`. Right-side annotations are independent.
   - **Vertical**: Concatenate header + disasm + pseudo into one buffer,
     then `add_spine()` appends a right-margin spine.

4. **Print**: Output all buffered lines.

**Per-block content:**

1. **Block heading** (printed before buffer): rule name in bold bright_yellow
   underline, "found in" dim, function name in bold bright_yellow.

2. **Rule underline + connector** (two buffered lines): a `┬───` underline
   row (kind="normal") matching the rule name width, then a `└` connector
   row (kind="rule_header") that `add_spine` extends with `─` to the spine
   column `┐`.

3. **Function signature**: prototype from `idc.get_type()`, shown when
   available.

4. **Disassembly section** (bright blue subheading):
   - Fetch lines via `idautils.Heads()` + `ida_lines.generate_disasm_line()`
   - Fetch both tagged (syntax colors) and plain (for underline matching) text
   - Get BB boundaries via `ida_gdl.FlowChart(func)`
   - Compute BB-aligned windows with threshold check
   - For each window: render code lines (syntax-highlighted or dimmed),
     underline carets, annotation labels (spine_role="annotation_label")
   - Between windows: `... N lines omitted ...`

5. **Pseudocode section** (bright blue subheading): Same approach via
   `ida_hexrays.decompile()`, `cfunc.get_boundaries()` for address mapping.

### IDA syntax highlighting

Both disassembly and pseudocode lines from IDA contain embedded color tags:
- `\x01` (TAG_ON) + color_byte = push style onto stack
- `\x02` (TAG_OFF) + color_byte = pop style from stack
- `\x03` (TAG_ESC) + byte = escaped literal character
- `\x04` (TAG_INV) = invisible marker (skipped)
- `\x28` (TAG_ADDR) after TAG_ON or TAG_OFF = hidden address data (always
  16 chars with idalib, even for 32-bit binaries, since IDA 9.0+ uses
  64-bit internal addressing)

`render_tagged_line()` uses a style stack to handle nested tags and
translates IDA color constants to Rich styles via `IDA_THEME` (40+ color
mappings). Key mappings:
- COLOR_INSN → bold bright_blue (mnemonics)
- COLOR_NUMBER/DNUM → bright_red (immediates)
- COLOR_REG → cyan (registers)
- COLOR_KEYWORD → magenta bold (ptr, offset, etc.)
- COLOR_REGCMT/RPTCMT/AUTOCMT → bright_black italic (comments)
- COLOR_STRING/CHAR → green (string literals)
- COLOR_LIBNAME/IMPNAME → bright_cyan (API names)
- COLOR_DATNAME/DNAME/CREF/DREF → yellow (data/code references)

For annotated lines, full-brightness styles are used. For dimmed context
lines, all styles are overridden with "dim". Pseudocode lines use the same
tag parser and theme, since IDA's decompiler output uses the same tagging.

### Basic block-aligned windows

`compute_windows()` takes optional `bb_ranges: list[tuple[int, int]]` from
`ida_gdl.FlowChart()`. When present:

1. For each annotated address, find its containing BB
2. Expand the window to include the entire BB
3. Apply context lines around the expanded range
4. Merge overlapping windows
5. If total shown > 50% of function, show everything

When IDA reports no basic blocks for an address (e.g. it isn't inside a
recognized function), this falls back to simple ±context expansion.

### Rendering primitives

Using Rich library for terminal output:

- **Gutter**: right-aligned address column, width computed dynamically
  from the maximum address (supports both 32-bit and 64-bit)
- **Syntax-highlighted lines**: IDA color tags → Rich styles
- **Dimmed lines**: `dim` style for context
- **Underline carets**: `┬───` pointing to matched operands, `└──` labels.
  When multiple annotations target the same source line, a single combined
  underline row is rendered with all `─` segments, then label rows peel off
  right-to-left using `│` pipe connectors (rustc-style). This ensures all
  underlines sit directly under their target tokens. Rightmost labels
  appear first (closest to the source) so pipes never cross.
  In side-by-side mode, right-column annotations are mirrored: `┬` at the
  right end of the underline, labels flow left-to-right from the spine
  through the label text to `┘` at the underline position. Labels are
  position-aware: each computes `label_start = max(0, connector_abs -
  total_label)` so the `── label_text┘` block is placed with `┘` at
  exactly the `┬` column. The label extends left into the gutter area
  (filled with `─`). Labels peel off leftmost-first (opposite of the left
  side) so that unconsumed pipe positions are always to the RIGHT of `┘`,
  rendered as trailing `│` characters. This prevents label text from
  crossing pipe descenders. When the label is wider than the available
  space (label_start clamps to 0), `┘` is placed after the label text as
  a fallback.
- **Spine**: yellow connectors — `│` trunk (dim yellow), `┐` top, `┤` branch,
  `┘` end. Annotation connectors and underline carets also yellow. In
  side-by-side mode, the spine runs between columns from the rule_header to
  the last annotation label on either side. Left annotations connect with
  `─┤`/`─┘`, right annotations with `├`/`└`. When both sides have
  annotations on the same row, `┼` or `┴` is used. No divider is drawn
  outside the spine range.
- **Omission markers**: `... N lines omitted ...` in dim italic

### Feature-to-annotation mapping

The match tree walk extracts leaf features. For each leaf:

- `FeatureNode` with `APIFeature` → annotation type "api"
- `FeatureNode` with `NumberFeature` → "number"
- `FeatureNode` with `StringFeature` → "string"
- `FeatureNode` with `MnemonicFeature` → "mnemonic"
- `FeatureNode` with `OffsetFeature` → "offset"
- `FeatureNode` with `OperandNumberFeature` → "operand[N].number"
- `FeatureNode` with `OperandOffsetFeature` → "operand[N].offset"
- `FeatureNode` with `BytesFeature` → "bytes"
- `FeatureNode` with `CharacteristicFeature` → "characteristic: <value>"
- `FeatureNode` with `MatchFeature` → skipped (sub-rule features collected via recursion)
- `FeatureNode` with `RegexFeature`/`SubstringFeature` → uses captures
- `RangeStatement` → "count(<feature>): N"

File-scope features (import, export, section, function-name) are collected
during match tree walking into `FileScopeFeature` objects and rendered in
the block header area.

### idalib lifecycle

idalib is a hard requirement: `main()` checks `idalib.is_idalib_installed()`
and exits non-zero if it is missing.

The database routines live together at the top of the script, ported from
`idals` (see its design doc §4.3, §4.4, §4.12):

```
db_path = resolve_database(args.input_file)      # cache hit, or analyze once
with open_database_session(db_path):
    extractor = get_ida_extractor()
    # with --json:  load the result document from disk
    # otherwise:    run capa with the extractor
    # ... render disassembly + pseudocode using IDA APIs ...
```

`resolve_database()` returns an `.i64`/`.idb` input unchanged. Anything else is
analyzed into `CACHE_DIR / f"{sha256}.i64"` via
`idapro.open_database(run_auto_analysis=True, args='-c -o"<cache>" ...')` plus
`ida_auto.auto_wait()`, closed with `save=True`. The analysis args disable the
primary and secondary Lumina servers (which sometimes overwrite good names
from debug info) and pass `-R` to load resources, matching what
`capa.loader.get_extractor()` does for `BACKEND_IDA`.

`open_database_session()` is a context manager that opens the resolved
database without re-running analysis and always closes it with `save=False`.
It yields nothing: IDA's global module state is the handle, and
`get_ida_extractor()` constructs the `IdaFeatureExtractor` over it. Closing
matters because if the database is left open (uncaught exception,
`BrokenPipeError` from piping output into `head`, ...), IDA leaves the unpacked
database files `.id0`, `.id1`, `.nam`, and `.til` behind.

Both routines run inside `database_access_guard()`, a three-phase advisory
guard against concurrent access:
1. Poll until the `.nam` companion file disappears — its presence means some
   other process (including an IDA GUI session) has the database unpacked.
2. Acquire an exclusive `fcntl.flock` on `<db>.lock`, polling with
   `LOCK_EX | LOCK_NB` so the wait can time out.
3. Re-check `.nam` now that the lock is held, as a TOCTOU defence.

Timeouts are 5s for opening a database and 120s for the analysis path
(auto-analysis of a large binary can take a while). On cache-miss the guard
wraps a double-checked existence test, so a run that waited on the lock uses
the database another run just produced instead of redoing the work.

Lock files are never cleaned up; stale ones are harmless because `flock` is
fd-based, so the lock dies with the file descriptor. `fcntl` is Unix-only —
where it is unavailable only phase 1 of the guard applies.

Between `resolve_database()` returning and `open_database_session()` acquiring
its own guard the database is briefly unguarded. That gap is safe: the
database is packed into a single `.i64` at that point, and the unpacked state
only exists while a session is open.

Single-threaded. One database per process.

### Pseudocode address mapping

To map instruction addresses to pseudocode line numbers:
1. `cfunc = ida_hexrays.decompile(func_ea)`
2. `boundaries = cfunc.get_boundaries()` — a `boundaries_t` (map from
   `cinsn_t*` to `rangeset_t`)
3. Iterate `boundaries.items()` (NOT index-based — it's a C++ map)
4. For each `(citem, rangeset)`, call `cfunc.find_item_coords(citem)`
   to get `(col, line_no)`
5. Extract EA ranges from the rangeset
6. Build reverse map: `line_no → set[addr]`
