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
2. `idapro.open_database(path)` + `idaapi.auto_wait()` to open the binary
3. `capa.loader.get_extractor()` with BACKEND_IDALIB
4. `capa.capabilities.common.find_capabilities()` to run matching
5. `rd.ResultDocument.from_capa()` to build the result document

### Phase 2: Inversion

Walk the ResultDocument to build a per-function annotation map.

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
class FunctionAnnotations:
    address: int
    name: str                       # from IDA
    annotations: list[Annotation]   # sorted by address
    rules: list[RuleSummary]        # all rules matching this function
```

**Inversion algorithm:**

For each rule in `capability_rules(doc)`:
  For each `(match_addr, match)` in rule.matches:
    Recursively walk the Match tree, collecting leaf FeatureNode addresses.
    For each leaf with locations, create Annotation objects.
    Map each annotation's address → parent function (using the layout's
    function/BB hierarchy, plus `ida_funcs.get_func()` as fallback).

Group annotations by function address. Sort functions by VA.

### Phase 3: Rendering

For each function (ordered by VA):

1. **Fetch disassembly**: iterate `idautils.Heads(func.start_ea, func.end_ea)`,
   call `ida_lines.generate_disasm_line(ea, GENDSM_REMOVE_TAGS)` for clean text,
   and the tagged version for syntax-highlighted rendering.

2. **Compute windows**: find all annotated addresses, expand each by ±context
   lines, merge overlapping windows. Mark lines as: annotated, context, or omitted.

3. **Render disassembly block**:
   - Function header with rule legend
   - For each window: render lines with address gutter, dimmed context,
     highlighted annotated lines, right-side annotations, underline carets
   - Between windows: `... N lines omitted ...`

4. **Fetch pseudocode** (if decompiler available):
   `ida_hexrays.decompile(func_ea)` → `cfunc.get_pseudocode()` for lines,
   `cfunc.get_boundaries()` to map EAs to pseudocode line numbers.
   Build a reverse map: for each annotated EA, find the pseudocode line(s).

5. **Render pseudocode block**: same window/annotation approach but on
   pseudocode lines instead of disassembly lines.

### Rendering primitives

Using Rich library for terminal output:

- **Gutter**: right-aligned address column in dim style, width computed
  dynamically from the maximum address in each function (supports 64-bit)
- **Dimmed lines**: `[dim]` style for context
- **Highlighted lines**: full color syntax highlighting
- **Annotations**: right-aligned in colored text, prefixed with rule tag
- **Underline carets**: `^^^^` or `───┬───` pointing to specific columns
  in the line above, with a `╰── description` continuation line
- **Rule tags**: single letters A-Z in distinct colors (cycling through
  a colorblind-friendly palette)
- **Omission markers**: `... N lines omitted ...` in dim italic

### Color palette

For rule tags, cycle through 12 colors (chosen for distinctness and
colorblind safety): cyan, yellow, magenta, green, red, blue, plus bright
variants of each.

### Rule tag assignment

Single-character tags A-Z, a-z, 0-9 (62 unique). When more than 62 rules
exist, overflow tags use two characters (AA, AB, AC...). Colors cycle
independently of symbols.

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
- `FeatureNode` with `MatchFeature` → "match: <rule-name>"
- `FeatureNode` with `RegexFeature`/`SubstringFeature` → uses captures
- `RangeStatement` → "count(<feature>): N"

File-scope features (import, export, section, function-name) are collected
during match tree walking into `FileScopeFeature` objects and rendered in
the function header area (below the rule legend, tagged with the
contributing rule's symbol).

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
6. Build reverse map: `addr → set[line_no]`
