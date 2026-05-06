# code-oriented-capa: Behavioral Specification

## Purpose

`code-oriented-capa.py` is a standalone script that renders capa rule matches
directly onto disassembly and pseudocode listings, producing terminal-friendly
annotated output. It inverts capa's default rule-centric view ("rule X matched
at addresses A, B, C") into a code-centric view ("function at address F has
these behavioral annotations on its instructions").

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
- `--functions ADDR[,ADDR,...]` — only render the specified functions
- `--verbose` — enable debug logging to stderr

## Output Structure

Output goes to stdout. Logging and status spinners go to stderr.

### Per-function output

Functions are rendered in ascending virtual address order. Only functions with
at least one rule match are shown.

Each function block has:

1. **Function header** — address, name (from IDA), rule match summary
2. **Rule legend** — when multiple rules match, each gets a symbol (A, B, C...)
   and a color. The legend maps symbols to rule names, namespaces, ATT&CK IDs,
   and MBC IDs. File-scope features (import, export, section, function-name)
   that contribute to matched rules are listed below the legend.
3. **Disassembly listing** with annotations:
   - Contributing instructions are rendered with full syntax highlighting
   - Non-contributing instructions within the context window are dimmed
   - Gaps between windows show `... N lines omitted ...`
   - Each contributing instruction has a right-side annotation showing:
     feature type, value, description, and contributing rule symbol
   - When an operand is specifically relevant (e.g., a number match on an
     immediate operand), an underline caret points to that operand
4. **Pseudocode listing** (when decompiler is available) with annotations:
   - Same annotation style as disassembly, mapped via address-to-pseudocode-line
   - Underlines on specific tokens (API calls, constants, strings)

### Multi-rule handling

When multiple rules match the same function:
- Each rule gets a unique tag (A-Z, a-z, 0-9, then AA, AB...) and a distinct color
- The legend at the function header lists all rules with their tags
- Annotations on instructions include the tag so the reader can identify
  which rule each feature contributes to
- Instructions contributing to multiple rules show multiple tags

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
| `characteristic: nzxor` | `nzxor` | the xor instruction |
| `characteristic: tight loop` | `tight loop` | the back-edge jump |
| `characteristic: indirect call` | `indirect call` | the call operand |
| `match: <rule>` | `match: <rule-name>` | (no underline — it's a logical reference) |
| `regex`/`substring` | the matched capture string | the string reference |

### Degradation

- Without color: symbols and text labels remain readable
- Without decompiler: pseudocode section is skipped with a note
- Without idalib: error message, cannot proceed (idalib is required)

## Decisions

- **Terminal text only.** No HTML, JSON, SARIF, or structured output formats.
  The goal is a human-readable annotated listing.
- **idalib is required.** The script depends on IDA Pro's idalib for both
  analysis (capa backend) and disassembly/pseudocode rendering.
- **No rule-tree rendering.** We don't reconstruct the and/or/not logic tree
  in the output. The focus is on which instructions contribute to which
  behaviors, not on the rule structure.
- **Context windows, not full listings.** Large functions are abbreviated to
  show only the regions around contributing instructions.
- **Ordered by VA.** Functions are output in address order, not grouped by
  rule or namespace.
