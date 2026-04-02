1. Purpose

These fixtures provide small, data-driven matcher tests. Each test pairs:
- a rule fragment,
- a synthetic feature listing,
- and the exact matches that capa should report.

They are for matcher behavior, not end-to-end binary analysis.

2. Where the tests live and how they run

2a. Fixture files live under `tests/fixtures/matcher/`.

2b. Static tests go under `tests/fixtures/matcher/static/`.

2c. Dynamic tests go under `tests/fixtures/matcher/dynamic/`.

2d. The pytest entrypoint is `tests/test_match_fixtures.py`.

2e. The loader and DSL parser live in `tests/match_fixtures.py`.

2f. Files are loaded in lexicographic path order. Tests inside a file are loaded in YAML order.

2g. Run the suite with:

```sh
pytest -q tests/test_match_fixtures.py
```

2h. Run a subset with:

```sh
pytest -q tests/test_match_fixtures.py -k <term>
```

3. Canonical file format

Use a top-level YAML list. Each list element is one test case.

Example:

```yaml
- name: scope-boundary
  description: function scope aggregates across basic blocks
  rules:
    - meta:
        name: function-cross-basic-block
        description: should match when function scope aggregates features from different basic blocks
        scopes:
          static: function
      features:
        - and:
            - mnemonic: mov
            - mnemonic: add
  features: |
    func: 0x401000
     bb: 0x401000: basic block
      insn: 0x401000: mnemonic(mov)
     bb: 0x401010: basic block
      insn: 0x401010: mnemonic(add)
  expect:
    matches:
      function-cross-basic-block:
        - 0x401000
```

4. Per-test fields

4a. `name`
A stable human-readable identifier. Pytest ids include this value.

4b. `description`
A short explanation of the behavior under test.

4c. `base address`
Optional. Used only for static tests. Defaults to `0` if omitted.

4d. `rules`
A list of rule fragments in normal capa rule syntax. These are wrapped and passed through `capa.rules.Rule.from_dict()`.

4e. `features`
A block string or list of strings containing the show-features-like DSL described below.

4f. `expect.matches`
Maps authored rule names to the exact match locations that should be returned.

4g. `options.span size`
Optional. If present, patches `capa.capabilities.dynamic.SPAN_SIZE` for that one test.

5. Flavor and scope defaults

5a. Fixture flavor is inferred from the file location.
A fixture under `tests/fixtures/matcher/static/` is static. A fixture under `tests/fixtures/matcher/dynamic/` is dynamic.

5b. The per-test `flavor` field is optional.
It is usually omitted. If present, it must agree with the file location.

5c. Rule scope fragments may omit the unsupported side.
For example:
- static fixtures may specify only `scopes.static`
- dynamic fixtures may specify only `scopes.dynamic`

The loader fills in the missing side with `unsupported`.

6. Match semantics

6a. Expectations are exact.
The test asserts the exact authored rule names that matched and the exact list of locations for each rule.

6b. Generated subscope helper rules are ignored.
Only authored rules are compared in `expect.matches`.

6c. Match order matters.
This is especially relevant for dynamic span-of-calls behavior.

7. Feature DSL

The DSL is intentionally close to `scripts/show-features.py`. Each line describes one feature or one scope header.

7a. Static scope lines

Accepted line prefixes:
- `global:`
- `file:`
- `func:`
- `bb:`
- `insn:`

Examples:

```text
global: global: os(windows)
file: 0x402345: characteristic(embedded pe)
func: 0x401000
func: 0x401000: string(hello world)
bb: 0x401000: basic block
bb: 0x401000: characteristic(tight loop)
insn: 0x401000: mnemonic(mov)
insn: 0x401000: offset(0x402000) -> 0x402000
insn: 0x401000: 0x401002: number(0x10)
insn: 0x401000: string(key: value)
```

Notes:
- `func: <addr>` is a function header. It sets the current function.
- `bb:` lines attach to the current function and also set the current basic block.
- `insn:` lines attach to the current basic block.
- `insn:` accepts either `insn: <insn-addr>: <feature>` or `insn: <func-addr>: <insn-addr>: <feature>`.
- `insn:` feature text may itself contain `: `, such as `string(key: value)`.
- `-> <addr>` overrides the feature location. Without it, the location defaults to the current scope address.
- `file:` lines require an explicit address and do not support `->`.

7b. Dynamic scope lines

Accepted line prefixes:
- `global:`
- `file:`
- `proc:`
- `thread:`
- `call:`

Examples:

```text
proc: sample.exe (ppid=2456, pid=3052)
proc: sample.exe: string(config)
thread: 3064
thread: 3064: string(worker)
call: 11: api(LdrGetProcedureAddress)
call: 11: string(AddVectoredExceptionHandler)
call: 11: string(kernel32.dll) -> process{pid:3052,tid:3064,call:11}
```

Notes:
- `proc: <name> (ppid=<n>, pid=<n>)` is a process header. It sets the current process.
- `thread: <tid>` is a thread header. It sets the current thread.
- `call:` lines attach to the current thread.
- `proc: <name>: <feature>` attaches a process-scope feature to the current process. The name must match the current process header.
- `thread: <tid>: <feature>` attaches a thread-scope feature and also sets the current thread.
- `-> <addr>` overrides the feature location. Without it, the location defaults to the current scope address.
- Dynamic fixture call IDs must be unique within a test.

7c. Supported feature atoms

Currently the parser supports these atoms:
- `basic block`
- `api(...)`
- `arch(...)`
- `bytes(...)`
- `characteristic(...)`
- `class(...)`
- `export(...)`
- `format(...)`
- `function-name(...)`
- `function name(...)`
- `import(...)`
- `match(...)`
- `mnemonic(...)`
- `namespace(...)`
- `number(...)`
- `offset(...)`
- `os(...)`
- `section(...)`
- `string(...)`
- `substring(...)`
- `operand[n].number(...)`
- `operand[n].offset(...)`
- `property(...)`
- `property/read(...)`
- `property/write(...)`

Examples:

```text
mnemonic(mov)
number(0x10)
number(0x1e)
string(hello world)
bytes(41 42 43)
operand[0].number(0x10)
property/read(System.IO.FileInfo::Length)
```

8. Supported address syntax

The parser accepts both rendered string forms and tagged YAML arrays.

8a. String forms include:
- `0x401000`
- `base address+0x100`
- `file+0x20`
- `token(0x1234)`
- `token(0x1234)+0x10`
- `global`
- `process{pid:3052}`
- `process{pid:3052,tid:3064}`
- `process{pid:3052,tid:3064,call:11}`
- the same process/thread/call forms with `ppid:` included

8b. Tagged YAML arrays include:
- `[absolute, 0x401000]`
- `[relative, 0x100]`
- `[file, 0x20]`
- `[token, 0x1234]`
- `[token offset, 0x1234, 0x10]`
- `[process, 2456, 3052]`
- `[thread, 2456, 3052, 3064]`
- `[call, 2456, 3052, 3064, 11]`
- `[no address]`

9. Expected match location shorthand

9a. Static tests usually use normal addresses in `expect.matches`, such as `0x401000`.

9b. Dynamic tests may also use full dynamic addresses, such as `[call, 2456, 3052, 3064, 11]`.

9c. Dynamic tests may use a bare integer call ID in `expect.matches` when that call ID is unique within the test.

Example:

```yaml
expect:
  matches:
    span-resolve-add-veh:
      - 11
```

This resolves to the unique dynamic call address with call ID `11`.

10. Adding a new test case

10a. Pick the right fixture file under `tests/fixtures/matcher/`, or add a new file if the new cases form a clear group.

10b. Append a new test entry to the top-level YAML list. Keep related tests together.

10c. Add a short top-level `description` that states the matcher behavior being asserted.

10d. Add concise rule `meta.description` fields when they help explain the role of each rule in the test.

10e. Keep the rule fragment minimal. Include only the features needed for the behavior under test.

10f. Write the synthetic feature listing in the DSL. Prefer the same wording and feature rendering that `show-features.py` emits.

10g. Add `expect.matches` with the exact authored rule names and locations.

10h. Run:

```sh
pytest -q tests/test_match_fixtures.py -k <new-test-name>
```

11. When to add parser support

11a. If a new test only needs existing atoms and line prefixes, do not change Python code. Just add YAML.

11b. If a new test needs a feature atom that the parser does not understand, update `_parse_feature()` in `tests/match_fixtures.py`.

11c. If a new test needs a new scope line form, update `StaticFeatureParser` or `DynamicFeatureParser` in `tests/match_fixtures.py`.

11d. If you extend the DSL, also update this document and add at least one fixture that exercises the new syntax.
