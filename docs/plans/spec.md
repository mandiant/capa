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

### Options

- `--rules PATH` — path to capa rules directory (default: bundled rules)
- `--json PATH` — path to a pre-computed capa JSON result document. When
  provided, skips capa analysis and loads results directly. idalib is still
  used for disassembly/pseudocode retrieval.
- `--no-color` — disable ANSI color output
- `--context N` — number of context lines around contributing instructions
  (default: 3). Lines within this window are shown but dimmed.
- `--no-pseudocode` — skip pseudocode rendering (disassembly only)
- `--functions ADDR[,ADDR,...]` — only render the specified functions (hex)
- `--verbose` — enable debug logging to stderr

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

A vertical spine on the right side of the output connects annotation labels
to the rule name at the top of the block. This makes it visually clear which
rule each feature contributes to:

```
 rule name found in sub_10001060 @ 0x10001060
 ┬────────
 └───────────────────────────────────────────────────────────────────────────┐
                                                                             │
     disassembly                                                             │
                                                                             │
 0x10001074 │ lea    ecx, [esp+1208h+WSAData]                               │
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

All spine and annotation connectors are yellow. The `┬───` underline and
`└───┐` connector visually link the rule name to the spine. Characters:
`┐` at top, `│` for trunk, `┤` for intermediate, `┘` for last annotation.

### Basic block-aligned windows

When IDA is available, the windowing system respects basic block boundaries.
If an annotated address falls within a basic block, the entire basic block is
included in the display window. Truncation only occurs between basic blocks,
never mid-block. This preserves the control flow context around contributing
instructions.

If more than 50% of a function's instructions would already be shown after
windowing, the entire function is displayed instead. This avoids excessive
`... N lines omitted ...` gaps when most of the function is relevant.

### Syntax highlighting

When IDA is available, disassembly lines are syntax-highlighted using IDA's
color tag system. Mnemonics, registers, numbers, addresses, keywords, and
comments each get distinct colors. Annotated lines use bright colors; context
lines use dimmed versions.

Without IDA (placeholder mode), plain monochrome text is used.

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
- Without decompiler: pseudocode section is skipped with a note
- Without idalib: placeholder disassembly (synthetic lines from features)

## Decisions

- **Terminal text only.** No HTML, JSON, SARIF, or structured output formats.
- **idalib is required for full output.** Placeholder mode provides basic
  output when idalib is not available, but loses disassembly, pseudocode,
  syntax highlighting, and BB alignment.
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
