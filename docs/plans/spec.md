# code-oriented-capa: Behavioral Specification

## Purpose

`code-oriented-capa.py` is a standalone script that renders capa rule matches
directly onto disassembly and pseudocode listings, producing terminal-friendly
annotated output. It inverts capa's default rule-centric view ("rule X matched
at addresses A, B, C") into a code-centric view showing the contributing
instructions annotated on the disassembly and pseudocode of matching functions.

## Invocation

```
python scripts/code-oriented-capa.py <binary> [options]
```

### Required arguments

- `<binary>` — path to the input file (PE, ELF, shellcode). Analyzed via idalib.
  An existing `.i64`/`.idb` database is also accepted and is opened directly
  instead of being re-analyzed.

### Options

- `--rules PATH` — path to capa rules directory (default: bundled rules)
- `-t, --tag TAG` — filter on rule meta field values (see Decisions).
- `--json PATH` — path to a pre-computed capa JSON result document. When
  provided, skips capa analysis and loads results directly. idalib is still
  used for disassembly/pseudocode retrieval.
- `--no-color` — disable ANSI color output
- `--context N` — number of context lines around contributing instructions
  (default: 3). Lines within this window are shown but dimmed.
- `--no-pseudocode` — skip pseudocode rendering (disassembly only)
- `--functions ADDR[,ADDR,...]` — only render the specified functions (hex)
- `--verbose` — enable debug logging to stderr

### Database cache

Binaries are analyzed once and the resulting database is cached at
`~/.cache/hex-rays/code-oriented-capa/<sha256-of-input>.i64`, so repeated runs
against the same file skip auto-analysis. A cache hit is reported under
`--verbose`. The cache key is the SHA-256 of the file contents, so renamed or
moved copies of the same sample share a database. Cached databases are opened
read-only and never saved back, so annotations made in IDA are not disturbed
and the script's own analysis does not accumulate state.

Concurrent runs against the same database are serialised rather than allowed
to corrupt it: a run that finds the database open elsewhere waits, then fails
with a message naming the blocker if it is still busy (5s when opening an
existing database, 120s when waiting to analyze). This also detects an IDA GUI
session holding the database.

## Output Structure

Output goes to stdout. Logging and status spinners go to stderr.

### Iteration order: rule-first

The output iterates **rules first**, then functions within each rule. Each
output block shows exactly one rule's annotations on one function. The same
function may appear in multiple blocks if it matches multiple rules. This
avoids the complexity of multi-rule tagging and makes each block
self-contained and easy to read.

Within a rule, functions are ordered by ascending virtual address.

### Per-block output

Each block has:

1. **Block heading** — bold bright yellow rule name, dim "found in",
   bold bright yellow function name and address.
2. **Rule underline + connector** — two lines of yellow box-drawing characters
   (same style as disassembly token underlines): a `┬───` underline under the
   rule name, then a `└───...───┐` connector flowing right to the spine column.
   This is the top of the connecting spine.
3. **Function signature** — function prototype from IDA's type system (via
   `idc.get_type()`), shown when available.
4. **File-scope features** — any import/export/section/function-name features
   from this rule that contributed to the match.
5. **Function comment** — IDA function comment if available.
6. **Disassembly listing** (bright blue subheading) with annotations:
   - Syntax-highlighted lines (via IDA's color tags) for annotated lines
   - Dimmed lines for context
   - Gaps between windows show `... N lines omitted ...`
   - Operand-level underline carets pointing to matched operands
   - Annotation labels showing feature type, value, and description
   - When multiple features target the same line, a single combined
     underline row with pipe stacking (rustc-style): pipes descend from
     each underline, labels peel off right-to-left so pipes never cross
7. **Connecting spine** — vertical ASCII art on the right margin connecting
   each annotation label back to the rule header, forming a visual tree.
8. **Pseudocode listing** (bright blue subheading, when decompiler available)
   with same annotation style, mapped via address-to-pseudocode-line.

### Connecting spine

A vertical spine connects annotation labels to the rule name at the top of
the block. This makes it visually clear which rule each feature contributes
to.

**Vertical layout** (narrow terminal, or no pseudocode): the spine runs on
the right margin:

```
 rule name found in sub_10001060 @ 0x10001060
 ┬────────
 └───────────────────────────────────────────────────────────────────────────┐
                                                                             │
     disassembly                                                             │
                                                                             │
 0x1000107E │ call   ds:WSAStartup                                          │
            │        ┬─────────                                              │
            │        └── api: WSAStartup ───────────────────────────────────┤
 0x1000108C │ push   6; protocol                                            │
            │        ┬                                                       │
            │        └── number: 0x6 = IPPROTO_TCP ─────────────────────────┤
 0x10001092 │ call   ds:socket                                              │
            │        ┬─────                                                  │
            │        └── api: socket ───────────────────────────────────────┘
```

**Side-by-side layout** (wide terminal with pseudocode available): the spine
runs down the center as a column divider between disassembly and pseudocode:

```
 rule name found in sub_10001060 @ 0x10001060
 ┬────────
 └──────────────────────────────────────────────────────────┐
                                                            │
     disassembly                                            │  pseudocode
                                                            │
 0x1000107E │ call   ds:WSAStartup                         │     3 │ WSAStartup(0x202, &wsadata);
            │        ┬─────────                             │       │ ─────────┬
            │        └── api: WSAStartup ──────────────────┤── api: WSAStartup┘
 0x1000108C │ push   6                                     │     4 │ fd = socket(AF_INET, SOCK_STREAM, 6);
            │        ┬                                      │       │        ─────┬ ┬  ┬  ┬
            │        └── number: 0x6 = IPPROTO_TCP ────────┼────────────── api: socket┘ │  │  │
 0x10001090 │ push   1                                     ├──── number: 0x2 = AF_INET┘  │  │
            │        ┬                                      ├───── number: 0x1 = SOCK_STREAM┘  │
            │        └── number: 0x1 = SOCK_STREAM ────────┼──────── number: 0x6 = IPPROTO_TCP┘
 0x10001092 │ call   ds:socket                             │     5 │ ...
            │        ┬─────                                 │
            │        └── api: socket ──────────────────────┘
                                                            │
```

Left-side annotation labels connect to the center spine with `─┤` (or `─┘`
for the last). Right-side annotation labels are mirrored: `── label┘` with
the label text shifted left into the gutter area so `┘` aligns with `┬` in
the underline above. Labels peel off leftmost-first (opposite of the left
side) so that unconsumed pipes descend to the right of each `┘` as trailing
`│` characters, preventing crossing. Below the spine range, the column
divider continues as a dim `│`.

The layout is chosen per match block: if the combined width of both columns
plus the spine fits in the terminal width, side-by-side is used. Otherwise it
falls back to vertical.

All spine and annotation connectors are yellow. Characters:
`┐` at top, `│` for trunk, `┤` for intermediate, `┘` for last annotation.

### Basic block-aligned windows

The windowing system respects basic block boundaries. If an annotated address
falls within a basic block, the entire basic block is included in the display
window. Truncation only occurs between basic blocks, never mid-block. This
preserves the control flow context around contributing instructions.

If more than 50% of a function's instructions would already be shown after
windowing, the entire function is displayed instead. This avoids excessive
`... N lines omitted ...` gaps when most of the function is relevant.

### Syntax highlighting

Disassembly lines are syntax-highlighted using IDA's color tag system.
Mnemonics, registers, numbers, addresses, keywords, and comments each get
distinct colors. Annotated lines use bright colors; context lines use dimmed
versions.

### Feature rendering

Each feature type has a specific rendering style:

| Feature | Annotation text | Underline target |
|---------|----------------|-----------------|
| `api` | `api: kernel32.CreatePipe` | the call mnemonic + operand |
| `number` | `number: 0x101 = STARTF_USESTDHANDLES\|STARTF_USESHOWWINDOW` | the immediate operand |
| `string` | `string: "cmd.exe"` | the lea/mov operand referencing the string |
| `mnemonic` | `mnemonic: xor` | the mnemonic column |
| `offset` | `offset: 0x10` | the displacement operand |
| `bytes` | `bytes: aa bb cc dd` | the data reference |
| `characteristic: nzxor` | `characteristic: nzxor` | the xor instruction |
| `characteristic: tight loop` | `characteristic: tight loop` | the back-edge jump |
| `characteristic: indirect call` | `characteristic: indirect call` | the call operand |
| `regex`/`substring` | the matched capture string | the string reference |

### Degradation

- Without color: box-drawing and text labels remain readable
- Without decompiler: pseudocode section is skipped with a note; layout
  is always vertical (no side-by-side without pseudocode)
- Narrow terminal: falls back to vertical layout automatically

## Decisions

- **Terminal text only.** No HTML, JSON, SARIF, or structured output formats.
- **idalib is required.** The script always opens the input file in IDA, both
  for live analysis and for `--json` rendering. Without disassembly there is
  nothing to annotate, so there is no degraded mode; `import idapro` raises
  ImportError when idalib is not installed. An earlier version synthesized
  placeholder disassembly from the matched features, which produced misleading
  output (made-up instructions), so it was removed.
- **The database is always closed.** Rendering runs inside a context manager
  that calls `idapro.close_database(save=False)`, so an interrupted or failed
  run does not leave unpacked database files (`.id0`, `.id1`, `.nam`, `.til`)
  next to the input file.
- **Databases are cached and access-guarded.** Analysis is the slowest part of
  a run and its result is reusable, so it is cached by input hash. The
  guarding exists because the cache makes collisions likely: two runs on the
  same sample, or a run against a database already open in the IDA GUI, would
  otherwise race on the unpacked database files. Waiting-then-failing is
  preferred over analyzing to a private temporary database, which would
  silently double the work. This mirrors `idals`, which solved the same
  problem; the cache directories are kept separate because the two tools
  analyze with different options.
- **Rule-first iteration.** Each block is one rule × one function. This
  eliminates the complexity of multi-rule tagging (the old [A]/[B]/[C] system)
  and makes each block independently readable. The same function may appear
  multiple times if it matches multiple rules.
- **Connecting spine replaces rule tags.** Instead of inline letter tags,
  a vertical ASCII art spine visually connects annotations to the rule header.
- **BB-aligned windows.** Never truncate within a basic block. Show complete
  BBs, with truncation only between blocks.
- **Threshold-based full display.** If >50% of a function's instructions
  would be shown, display the entire function instead of using windows.
- **No rule-tree rendering.** We don't reconstruct the and/or/not logic tree
  in the output. The focus is on which instructions contribute to which
  behaviors, not on the rule structure.
- **Ordered by VA within each rule.** Functions within a rule are sorted by
  address. Rules are ordered by first appearance in the ResultDocument.
- **Tag semantics inherited from capa.** `-t/--tag` means the same thing as in
  `capa.main`: the ruleset is filtered with `RuleSet.filter_rules_by_meta`, so a
  tag matches any string-valued or list-of-string meta field (name, namespace,
  authors, `att&ck`, `mbc`, references, examples, description, plus flat
  `maec/*` keys) by substring, and every surviving rule brings its transitive
  dependencies along. A tag that matches nothing is a user-input error: it
  prints `error: no rules matched tag: <tag>` and exits 1. A tag that selects
  real rules but produces no matches prints `No rule matches for tag "<tag>".`
  and exits 0, consistent with the no-matches path.
- **Tag has no effect under `--json`.** Filtering happens before matching, on
  the live-analysis path only. A pre-computed result document already contains
  whatever rules the original run matched, so `--tag` with `--json` just logs a
  warning and renders the document unchanged.
- **Adaptive side-by-side layout.** When pseudocode is available and the
  terminal is wide enough, disassembly and pseudocode are laid out in
  side-by-side columns with the spine as the center divider. This increases
  information density on wide terminals. The decision is per-block based on
  measured content widths. Narrow terminals get vertical layout automatically.
