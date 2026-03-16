# MAPA IDA/IDALib port plan

Goal: preserve the current `scripts/mapa.py` report while replacing the Lancelot/BinExport2 backend with IDALib. Use the `ida-domain` API for normal analysis where it cleanly maps to the needed data. Reuse the existing capa IDA backend as the semantic reference for imports, thunks, string resolution, function naming, and database bootstrap.

This revision adds concrete guidance from capa's existing IDA backend.

## Sources used

Primary sources:
- `scripts/mapa.py`
- https://github.com/HexRaysSA/ida-claude-plugins/blob/main/plugins/ida-plugin-development/skills/ida-domain-api/SKILL.md
- `capa/features/extractors/ida/idalib.py`
- `capa/features/extractors/ida/extractor.py`
- `capa/features/extractors/ida/helpers.py`
- `capa/features/extractors/ida/file.py`
- `capa/features/extractors/ida/function.py`
- `capa/features/extractors/ida/insn.py`
- `capa/features/extractors/ida/basicblock.py`
- `capa/ida/helpers.py`
- `capa/loader.py`
- `tests/fixtures.py`
- `tests/test_idalib_features.py`
- `capa/features/common.py`
- `idals.py` from https://github.com/williballenthin/idawilli/tree/master/idals

Domain API references:
- Overview: https://ida-domain.docs.hex-rays.com/llms.txt
- Getting started: https://ida-domain.docs.hex-rays.com/getting_started/index.md
- Examples: https://ida-domain.docs.hex-rays.com/examples/index.md
- Database: https://ida-domain.docs.hex-rays.com/ref/database/index.md
- Functions: https://ida-domain.docs.hex-rays.com/ref/functions/index.md
- Flowchart: https://ida-domain.docs.hex-rays.com/ref/flowchart/index.md
- Instructions: https://ida-domain.docs.hex-rays.com/ref/instructions/index.md
- Xrefs: https://ida-domain.docs.hex-rays.com/ref/xrefs/index.md
- Strings: https://ida-domain.docs.hex-rays.com/ref/strings/index.md
- Segments: https://ida-domain.docs.hex-rays.com/ref/segments/index.md
- Names: https://ida-domain.docs.hex-rays.com/ref/names/index.md
- Entries: https://ida-domain.docs.hex-rays.com/ref/entries/index.md

## Key correction after reviewing capa

The current `capa/features/extractors/ida/` backend is IDALib-capable, but it is not written against `ida-domain` today. It uses the classic IDA Python surface: `idapro`, `idaapi`, `idautils`, `idc`, `ida_bytes`, `ida_funcs`, `ida_segment`, and related modules.

That means the correct migration strategy is not "invent a fresh IDA collector from scratch". The correct strategy is:
- use capa's existing IDA backend as the behavioral spec and a source of proven heuristics
- implement the new collector against `ida-domain` wherever the needed API exists cleanly
- treat the existing legacy helpers as reference material, not as the default implementation path
- only introduce lower-level `ida_*` calls if the implementer can point to a concrete `ida-domain` gap and document it

This is especially important for:
- IDALib database bootstrap
- import and extern enumeration
- thunk-chain resolution
- string/data-reference chasing
- alternative function names from comments
- known IDA version caveats

## Current MAPA output that must remain stable

The current script renders these sections, in this order:
- `meta`
- `modules`
- `sections`
- `libraries`
- `functions`

Accepted intentional change for the port: remove `modules` entirely.

Inside `functions`, it currently:
- iterates functions in address order
- prints `thunk ...` for thunk functions
- prints `function ...` for normal functions
- inserts source-file separators when the primary Assemblage source path changes, ignoring gaps with missing Assemblage data
- annotates functions with Assemblage source name and file when available
- forwards callers through thunk targets so callers of a thunk appear on the real target
- prints `B/E/I` as basic blocks / CFG edges / instructions plus total instruction bytes
- prints capa rule names attached to the function
- prints `calls:` for internal non-library callees
- prints `api:` for import/external/library callees
- prints `string:` for referenced strings

That output contract should stay stable unless a deliberate change is accepted and documented.

## What capa already gives you

There are three reusable assets.

The first is a proven `ida-domain` database-resolution and session-opening path in `../idawilli/idals/idals.py`. That code already does the part MAPA needs most: accept either a raw sample or an existing `.i64` / `.idb`, hash raw inputs, cache analyzed databases by SHA-256, and guard concurrent access.

The second is capa's proven IDALib bootstrap path:
- `capa/features/extractors/ida/idalib.py`
- `capa/loader.py`
- `tests/fixtures.py`

The third is capa's proven semantic definition of the data MAPA cares about:
- function enumeration: `capa/features/extractors/ida/extractor.py`
- segments, imports, externs: `capa/features/extractors/ida/file.py`, `helpers.py`
- callers and function names: `capa/features/extractors/ida/function.py`
- API calls, call targets, strings, mnemonics, offsets: `capa/features/extractors/ida/insn.py`
- CFG/basic blocks: `capa/features/extractors/ida/basicblock.py`, `helpers.py`
- hashes, architecture, imagebase, file-type helpers: `capa/ida/helpers.py`

The practical split is simple. Use `idals.py` as the model for database resolution, caching, and guarded open/close. Use capa's IDA backend as the model for analysis semantics and parity behavior. Use `ida-domain` as the primary query surface inside the collector. Do not depend on Lancelot anywhere in the new implementation.

## Important behavioral facts from capa's backend

1. IDALib bootstrap in capa is not a bare `Database.open(...)` call.
   - It uses `capa.features.extractors.ida.idalib.has_idalib()` and `load_idalib()`.
   - It then calls `idapro.open_database(..., run_auto_analysis=True, args="-Olumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0 -R")`.
   - It disables console chatter with `idapro.enable_console_messages(False)`.
   - It waits for analysis completion with `ida_auto.auto_wait()`.

2. Capa explicitly disables Lumina during IDALib analysis.
   - Reason documented in `capa/loader.py`: Lumina can inject bad names or overwrite debug-info names.
   - MAPA should do the same unless there is a deliberate decision to trust Lumina.

3. Capa requests resource loading with `-R`.
   - This matters for some file-scope extraction.
   - `tests/test_idalib_features.py` notes that IDA 9.0 had resource-loading limitations under IDALib.

4. The existing `IdaFeatureExtractor.get_functions()` is not a direct drop-in for MAPA.
   - It calls `helpers.get_functions(skip_thunks=True, skip_libs=True)`.
   - MAPA must render thunk functions, so MAPA needs its own full function inventory.

5. Capa already encodes the thunk semantics MAPA needs.
   - `THUNK_CHAIN_DEPTH_DELTA` is defined in `capa/features/common.py` as `5`.
   - `capa/features/extractors/ida/insn.py:check_for_api_call()` follows code refs, then data refs, through thunk chains to resolve imports/externs.
   - `capa/features/extractors/binexport2/__init__.py:BinExport2Analysis._compute_thunks()` shows the intended "single-target thunk chain" rule: only resolve through chains with exactly one callee per thunk hop.

6. Capa already encodes MAPA-relevant string semantics.
   - `helpers.find_data_reference_from_insn(insn, max_depth=10)` follows single data-reference chains.
   - `helpers.find_string_at(ea)` looks for C strings and works around an IDA Unicode-decoding quirk.
   - `insn.extract_insn_string_features()` and `extract_insn_bytes_features()` use that behavior.

7. Capa already has the import and extern logic MAPA needs.
   - `helpers.get_file_imports()` enumerates import modules and normalizes names.
   - `helpers.get_file_externs()` enumerates functions from `SEG_XTRN` segments.
   - `file.extract_file_import_names()` shows how capa treats name-vs-ordinal imports.

8. Capa already has alternative-name logic.
   - `helpers.get_function_alternative_names()` parses comments that look like `Alternative name is 'foo'`.
   - `function.extract_function_alternative_names()` exposes them as `FunctionName` features.

9. Capa already has the CFG behavior MAPA should match.
   - `helpers.get_function_blocks()` uses `idaapi.FlowChart(f, flags=(idaapi.FC_PREDS | idaapi.FC_NOEXT))`.
   - The `NOEXT` part matters: it avoids useless external blocks contaminating B/E/I counts.

10. The test suite documents real version caveats.
    - IDA 9.0 and 9.1 had some ELF symbol issues.
    - IDA 9.0 under IDALib had resource-loading limitations.
    - MAPA validation should account for those when comparing outputs.

## Database resolution and caching pattern to copy from idals

`../idawilli/idals/idals.py` is the best starting point for the "raw file or existing database" problem. It already solves the user-visible behavior MAPA needs.

Its pattern is:
- if the input suffix is `.i64` or `.idb`, use that database directly
- otherwise compute hashes for the raw file with `compute_file_hashes()` and use the SHA-256 as the cache key
- store the generated database in a common cache directory, currently `~/.cache/hex-rays/idals/<sha256>.i64`
- serialize access with `database_access_guard()`
- detect an already-open or unpacked database by watching for the companion `.nam` file
- use an advisory `flock` on `<db>.lock` to avoid concurrent writers
- after acquiring the lock, re-check `.nam` to close the TOCTOU hole
- on a cache miss, analyze the raw sample with `Database.open(..., IdaCommandOptions(auto_analysis=True, new_database=True, output_database=..., load_resources=True), save_on_close=True)`
- after the cached database exists, open it read-only with `open_database_session(..., auto_analysis=False)` and `save_on_close=False`

MAPA should adopt that pattern with only minor changes:
- use the same SHA-256-keyed cache strategy
- keep the same locking protocol
- put the cache in a MAPA-specific directory, or intentionally share the idals directory if reuse is desired
- expose the cache location as a small helper or constant so it can be documented and tested
- reuse the computed SHA-256 for the `meta` section instead of hashing the sample twice

There is one deliberate integration check to make here. `idals.py` uses `ida-domain`'s `Database.open(...)`, while capa's bootstrap path uses `idapro.open_database(...)` and disables Lumina explicitly. For MAPA, prefer the `idals.py` open-and-cache pattern because it already handles the database lifecycle correctly. Then verify whether the `ida-domain` open path offers an equivalent way to suppress Lumina. If it does, use it. If it does not, decide whether that matters for MAPA output or whether database creation should fall back to capa's `idapro.open_database(...)` path while cached-session opens keep the `idals.py` pattern.

## Recommended architecture

Do not port `scripts/mapa.py` by replacing each Lancelot query inline. Split it into four layers:
- CLI and argument parsing
- IDA bootstrap and environment setup
- report collection
- rendering

Use backend-neutral dataclasses for the report model:
- `MapaReport`
- `MapaMeta`
- `MapaSection`
- `MapaLibrary`
- `MapaFunction`
- `MapaCall`
- `MapaString`
- `AssemblageRecord`

The collector should have one primary data-access layer: `ida-domain` for functions, flowcharts, instructions, strings, names, segments, xrefs, and database lifecycle. Existing capa helpers remain useful as semantic references and regression oracles.

## Best practical strategy

The implementation target is an IDALib-only collector with `ida-domain` as the primary API surface.

Concretely:
- use `ida-domain` for function inventory, instruction iteration, CFG stats, name lookup, segment listing, xref walking, and cached database open/create
- use the existing capa IDA code to understand the intended semantics for imports, externs, thunk resolution, data-reference chasing, and alternative names
- if the implementer discovers a real `ida-domain` gap, document the gap explicitly before introducing lower-level `ida_*` calls

That gives the next implementer a clear target: no Lancelot, no default hybrid backend, and no legacy helper dependency unless a concrete gap forces it.

## Concrete mapping from MAPA fields to capa/backend logic

| MAPA field/behavior | First source to consult | Recommended implementation |
|---|---|---|
| IDALib discovery | `capa/features/extractors/ida/idalib.py` | Reuse `has_idalib()` / `load_idalib()` logic if MAPA needs to bootstrap `idapro` availability itself. |
| resolve/open DB | `../idawilli/idals/idals.py` | Use `resolve_database()` and `open_database_session()` as the primary pattern. |
| cache key and cache DB path | `../idawilli/idals/idals.py` | Hash raw inputs once and key cached databases by SHA-256. |
| Lumina suppression policy | `capa/loader.py`, `tests/fixtures.py` | Carry forward capa's disable-Lumina behavior if the chosen open path supports it. |
| sample hashes | `../idawilli/idals/idals.py`, `capa/ida/helpers.py`, `extractor.py` | Reuse the SHA-256 computed for cache lookup; prefer IDA-provided hashes when opening an existing database. |
| image base | `capa/ida/helpers.py` | Prefer IDA imagebase helper; use Domain API only if it exposes the same value clearly. |
| sections | `helpers.get_segments()`, `file.extract_file_section_names()` | Use `db.segments`; match capa's header-segment filtering rules if needed. |
| import modules/functions | `helpers.get_file_imports()` | Implement with `ida-domain` if the needed import data is exposed cleanly; otherwise use this helper as the semantic reference for normalization. |
| externs | `helpers.get_file_externs()` | Match this behavior with `ida-domain` if possible; if not, document the missing API and then fall back deliberately. |
| function inventory | `extractor.py`, `helpers.get_functions()` | Do not use extractor's default function list because it skips thunks/libs. Build a MAPA-specific inventory with `ida-domain`. |
| callers | `function.extract_function_calls_to()` | Reproduce the same behavior with domain xrefs and compare against this helper during validation. |
| call targets | `insn.extract_function_calls_from()` | Reproduce the same behavior with domain xrefs and compare against this helper during validation. |
| API calls | `insn.extract_insn_api_features()` | Match the import/extern/thunk resolution semantics exposed by this function. |
| string refs | `helpers.find_data_reference_from_insn()`, `find_string_at()` | Match the same single-ref-chain behavior and max depth `10`. |
| function names | `function.extract_function_name()`, alternative-name helpers | Use normal name, demangled name, alternative names, and render Assemblage annotations separately without renaming the IDA function. |
| B/E/I stats | `helpers.get_function_blocks()` | Match `PREDS | NOEXT` semantics; use domain flowchart if possible. |
| function ordering | current `scripts/mapa.py` | Keep address order for deltas and rendering stability. |

## Step-by-step implementation plan

### 1. Freeze the current MAPA output

Before editing code, save golden outputs from the current `scripts/mapa.py` for:
- a sample with normal internal calls and imports
- a sample with thunk-heavy call patterns
- a sample with capa and Assemblage overlays

These are the parity targets.

### 2. Add `resolve_database()` and `open_database_session()` helpers

Base these directly on `../idawilli/idals/idals.py`.

`resolve_database()` should:
- accept either a raw sample or an existing `.i64` / `.idb`
- return existing databases unchanged
- hash raw inputs once and use SHA-256 as the cache key
- place cached databases under the XDG cache root in `mandiant/mapa/`, i.e. `$XDG_CACHE_HOME/mandiant/mapa/` when set, else `~/.cache/mandiant/mapa/`
- guard cache creation with the same `.nam` + `flock` protocol from `database_access_guard()`
- analyze cache misses with `Database.open(..., IdaCommandOptions(auto_analysis=True, new_database=True, output_database=..., load_resources=True), save_on_close=True)`
- keep cache creation transparent in normal mode and only log cache details in verbose/debug mode

`open_database_session()` should:
- use the same guard before opening the database
- open cached or user-supplied databases with `new_database=False`
- default to `save_on_close=False`
- optionally run `ida_auto.auto_wait()` when `auto_analysis=True`

This should become MAPA's primary database lifecycle.

Then add one capa-derived check on top: if the chosen open path can suppress Lumina, do so. If the `ida-domain` path cannot, verify whether that difference affects naming enough to justify a fallback to capa's `idapro.open_database(...)` path during cache creation.

### 3. Introduce a backend-neutral report model

Before touching the collector logic, split `scripts/mapa.py` into:
- CLI
- collector
- renderer
- input-overlay parsing for capa JSON and Assemblage CSV

Keep the renderer stable. The collector should return value objects only.

### 4. Build a MAPA-specific function inventory

Do not use `IdaFeatureExtractor.get_functions()` as-is, because it skips thunks and library functions.

Instead:
- enumerate all functions in address order with `ida-domain` if possible
- keep flags for `is_thunk`, `is_library`, and `is_external`
- retain enough metadata to render thunks, skip imports from the function list, and compute deltas

For parity, compare your inventory against:
- `helpers.get_functions(skip_thunks=False, skip_libs=False)`
- IDA function flags such as `FUNC_THUNK` and `FUNC_LIB`

### 5. Recreate import and extern logic using capa's semantics

For the `libraries` section and for `api:` classification, start from the behavior encoded in:
- `helpers.get_file_imports()`
- `helpers.get_file_externs()`

That behavior already handles:
- PE imports with `__imp_` prefixes
- ELF imports with `@@version` suffixes
- ordinal imports
- extern functions in `SEG_XTRN`

The implementation target remains `ida-domain`. The next implementer should reproduce this behavior there if the API surface is available. If a real gap appears, document the gap before introducing any fallback.

### 6. Implement thunk resolution with capa's exact semantics

Build one cached helper, for example `resolve_thunk_target(ea)`, and use it everywhere.

Behavior should match capa's existing semantics:
- maximum thunk-chain depth: `THUNK_CHAIN_DEPTH_DELTA == 5`
- follow code refs first, then data refs if needed
- only resolve through single-target chains
- stop on cycles, zero-target, or multi-target cases
- allow the final resolved target to be an import or extern

Use two existing code paths as references:
- `capa/features/extractors/ida/insn.py:check_for_api_call()`
- `capa/features/extractors/binexport2/__init__.py:BinExport2Analysis._compute_thunks()`

This helper must drive:
- caller forwarding
- `calls:` lines
- `api:` lines
- capa match attachment when a match lands in a thunk

### 7. Use capa features as references, not as the collector

Do not build MAPA by instantiating `IdaFeatureExtractor()` and aggregating capa features into the final report. That would create a hidden second backend and blur the migration target.

Instead, query IDA directly through `ida-domain` and use the capa feature-extraction code as a reference when the intended semantics are unclear. The implementer should compare specific results against:
- `Characteristic("calls to")`
- `Characteristic("calls from")`
- `API`
- `String`
- `FunctionName`
- `Mnemonic`

This keeps the delivered collector IDALib-only while still giving the implementer a precise oracle for parity checks.

### 8. Recreate callers and callees

Use a precomputed normalized call graph. Do not compute callers ad hoc during rendering.

For each non-import function:
- walk its instructions
- identify call or jump-to-import patterns using the same logic as `extract_insn_api_features()`
- resolve thunk chains
- classify the resolved target as internal or API/import/extern
- record caller and callee relationships on resolved targets

For parity, verify against these capa semantics:
- function callers: `function.extract_function_calls_to()`
- outgoing calls: `insn.extract_function_calls_from()`
- API calls: `insn.extract_insn_api_features()`

Important detail: the existing helper treats both `call` and `jmp` as API-bearing instructions in some thunk/import cases. Do not assume `call` only.

### 9. Recreate B/E/I with capa's CFG semantics

For each rendered function:
- basic blocks: count basic blocks using the equivalent of `helpers.get_function_blocks()`
- edges: sum successors across those blocks
- instructions: count instructions across those blocks
- bytes: sum instruction sizes

The important parity rule is the CFG construction mode:
- match `idaapi.FlowChart(f, flags=(idaapi.FC_PREDS | idaapi.FC_NOEXT))`

If the Domain API flowchart differs, use it only if it can match the no-external-block behavior. Otherwise use a tiny legacy helper for block enumeration and keep everything else in the Domain API.

### 10. Recreate string extraction with capa's data-ref chasing

Do not just test `db.strings.get_at(xref.to_ea)` and stop. That will miss the semantics capa already uses.

Start from capa's behavior:
- follow a single data-reference chain from the instruction, up to depth `10`
- if the final target is a string, emit it
- otherwise it may be bytes, not a string

For MAPA specifically:
- only render strings, not raw bytes
- deduplicate by rendered string value, matching the current script
- trim trailing whitespace the same way the current script does

Reference implementation:
- `helpers.find_data_reference_from_insn()`
- `helpers.find_string_at()`
- `insn.extract_insn_string_features()`

### 11. Reuse capa's name and alternative-name semantics

For the function display name, use this order:
- demangled name
- IDA function name
- alternative names from comments if they help and the main name is poor
- final fallback such as `sub_{ea:x}`

Render Assemblage source name and source file as annotations beneath the function header. Do not mutate the database just to apply Assemblage data.

Reference points:
- `function.extract_function_name()`
- `helpers.get_function_alternative_names()`

### 12. Reattach capa matches by containing function

Keep the current capa JSON input format, but simplify the mapping logic.

Recommended algorithm:
- parse the capa JSON as today
- for each absolute match address, ask IDA for the containing function
- if that function is a thunk, resolve it through the thunk resolver
- attach the rule name to the resolved function start EA
- warn when no containing function exists

This is simpler than the current BinExport-specific mapping and aligns better with IDA's data model.

### 13. Rebuild top-level sections using capa-backed semantics

For `meta`:
- sample name: input path or IDA metadata
- hashes: prefer IDA-provided hash helpers in `capa/ida/helpers.py`
- architecture: reuse the logic in `capa/features/extractors/ida/global_.py`
- timestamp: define explicitly, because BinExport's old field is gone

For `sections`:
- use `ida-domain` segments if possible
- match capa's `skip_header_segments` behavior if needed

For `libraries`:
- use `helpers.get_file_imports()` and group/display import modules accordingly

For `modules`:
- remove the section entirely as an intentional interface change
- document the removal in the spec so future ports do not try to reintroduce BinExport-specific `module` semantics accidentally

### 14. Add tests using capa's existing IDALib pattern

Pure tests should cover:
- Assemblage parsing and RVA-to-VA mapping
- thunk-chain resolution
- import/extern normalization
- string de-duplication and trimming
- final rendering from a prebuilt `MapaReport`

Integration tests should reuse the same lifecycle MAPA will use in production:
- resolve the input to an existing or cached database
- open it through the guarded session helper
- collect the MAPA report
- compare key functions and sections against golden outputs

Use `tests/test_idalib_features.py` as the reference for version-specific skips and expectations, and use `../idawilli/idals/idals.py` as the reference for database resolution and guarded open/close behavior.

### 15. Validate parity and document deliberate differences

Compare the new output against the frozen Lancelot output on the supplied samples.

Verify specifically:
- function ordering
- thunk rendering
- thunk-forwarded callers
- internal vs API call classification
- libraries/imports section contents
- string extraction
- B/E/I counts
- Assemblage annotations and source-file separators
- capa attachment

Document every known delta. The likely ones are:
- function discovery differences between IDA and Lancelot
- the intentional removal of the `modules` section
- symbol differences across IDA versions, especially ELF on older 9.x
- resource-dependent differences on older IDALib versions

## Minimal implementation checklist

A good order of work is:
1. freeze current MAPA outputs
2. add backend-neutral report dataclasses
3. add `resolve_database()` and `open_database_session()` helpers modeled on `idals.py`
4. implement the XDG cache path and quiet-by-default cache creation behavior
5. build a full MAPA function inventory that includes thunks
6. port sections and metadata
7. implement import/extern classification to match capa semantics
8. implement the thunk resolver using capa's existing semantics
9. build normalized caller/callee/API indexes
10. port B/E/I using `PREDS | NOEXT`-equivalent CFG traversal
11. port string extraction using capa's data-ref-chain semantics
12. port Assemblage overlay handling
13. port capa JSON address-to-function attachment
14. remove the `modules` section and document the interface change
15. compare outputs against golden references
16. document any proven `ida-domain` gaps and any intentional differences in spec/design during implementation

## Resolved decisions for the implementation handoff

Record these in `spec.md` or `design.md` during implementation so the behavior stays stable.

- accepted inputs: raw binary and existing IDA databases
- cached databases live under the XDG cache root in `mandiant/mapa/`
- MAPA may create and persist cached IDA databases automatically
- cache creation stays quiet in normal mode and only surfaces in verbose/debug logging
- Lumina stays disabled for now
- `meta.ts` becomes `datetime.now()`
- remove the `modules` section from the report
- the implementation target is IDALib only and all Lancelot dependencies should be removed
- assume `ida-domain` is sufficient unless the implementer can demonstrate a specific missing API; any lower-level fallback must be justified and documented
