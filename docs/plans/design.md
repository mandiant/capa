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

When running analysis:
1. `capa.features.extractors.ida.idalib.load_idalib()` to initialize
2. `idapro.open_database(path)` + `ida_auto.auto_wait()` to open the binary
3. Construct `IdaFeatureExtractor()` directly (not via `get_extractor`)
4. `capa.capabilities.common.find_capabilities()` to run matching
5. `rd.ResultDocument.from_capa()` to build the result document

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

Two-pass buffered rendering with connecting spine.

**Iteration order:** For each rule → for each matching function (by VA):

1. **Build buffer**: Render all content lines into `BufferedLine` objects,
   each tagged with a spine role (`rule_header`, `annotation_label`, `normal`).

2. **Add spine**: Compute spine column from max line width. For each buffered
   line between the rule header and last annotation label, append the
   appropriate spine character (┐, │, ┤, ┘) at the spine column.

3. **Print**: Output all buffered lines.

**Per-block content:**

1. **Function box header**: `╔══ name @ 0xADDR ═══...═══╗`

2. **Rule header** (spine_role="rule_header"):
   Rule name, namespace, ATT&CK/MBC IDs.

3. **Disassembly section**:
   - Fetch lines via `idautils.Heads()` + `ida_lines.generate_disasm_line()`
   - Fetch both tagged (syntax colors) and plain (for underline matching) text
   - Get BB boundaries via `ida_gdl.FlowChart(func)`
   - Compute BB-aligned windows with threshold check
   - For each window: render code lines (syntax-highlighted or dimmed),
     underline carets, annotation labels (spine_role="annotation_label")
   - Between windows: `... N lines omitted ...`

4. **Pseudocode section**: Same approach via `ida_hexrays.decompile()`,
   `cfunc.get_boundaries()` for address mapping.

5. **Function footer**: `╚═══...═══╝`

### IDA syntax highlighting

Both disassembly and pseudocode lines from IDA contain embedded color tags:
- `\x01` (TAG_ON) + color_byte = push style onto stack
- `\x02` (TAG_OFF) + color_byte = pop style from stack
- `\x03` (TAG_ESC) + byte = escaped literal character
- `\x04` (TAG_INV) = invisible marker (skipped)
- `\x28` (TAG_ADDR) after TAG_ON = hidden address data (8 or 16 bytes)

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

Without BB info (placeholder mode), falls back to simple ±context expansion.

### Rendering primitives

Using Rich library for terminal output:

- **Gutter**: right-aligned address column, width computed dynamically
  from the maximum address (supports both 32-bit and 64-bit)
- **Syntax-highlighted lines**: IDA color tags → Rich styles
- **Dimmed lines**: `dim` style for context
- **Underline carets**: `─` pointing to matched operands, `╰──` labels.
  When multiple annotations target the same source line, a single combined
  underline row is rendered with all `─` segments, then label rows peel off
  right-to-left using `│` pipe connectors (rustc-style). This ensures all
  underlines sit directly under their target tokens. Rightmost labels
  appear first (closest to the source) so pipes never cross.
- **Spine**: vertical `│` trunk, `┐` top, `┤` branch, `┘` end
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

When running live analysis (no `--json`):
```
load_idalib()
idapro.open_database(path, run_auto_analysis=True)
ida_auto.auto_wait()
extractor = IdaFeatureExtractor()   # direct construction, not via get_extractor
# ... run capa, build result document ...
# ... render disassembly + pseudocode using IDA APIs ...
idapro.close_database(save=False)
```

When using `--json` with a binary:
```
load_idalib()                       # optional, may not be available
idapro.open_database(path, ...)     # opens for disassembly/pseudocode only
# ... load result document from JSON ...
# ... render using IDA APIs ...
idapro.close_database(save=False)
```

Note: `capa.loader.get_extractor(BACKEND_IDA)` is NOT used because it
passes `-R` to `open_database` which can hang on some binaries. Instead,
the database is opened directly and `IdaFeatureExtractor()` is constructed
manually.

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
