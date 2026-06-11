Data-driven matcher tests. Each test pairs a rule fragment, a synthetic feature listing, and the exact matches that capa should report. These test the matcher itself, not end-to-end binary analysis.

Fixture files live under `static/` and `dynamic/` directories, organized by theme (e.g. `logic.yml`, `scopes.yml`, `strings.yml`). Flavor is inferred from the directory. The pytest entrypoint and DSL parser both live in `tests/test_match_fixtures.py`.

```sh
pytest -q tests/test_match_fixtures.py
pytest -q tests/test_match_fixtures.py -k <term>
```

## Fixture file format

Each file is a YAML list. Each element is one test case.

```yaml
- name: and-both-present
  description: and requires all children to match
  rules:
    - name: and-match
      description: should match because the function contains both mov and number 0x10
      scopes:
        static: function
      features:
        - and:
            - mnemonic: mov
            - number: 0x10
  features: |
    func: 0x402000
     bb: 0x402000: basic block
      insn: 0x402000: mnemonic(mov)
      insn: 0x402000: number(0x10)
  expect:
    matches:
      and-match:
        - 0x402000
```

The `name` field is a stable human-readable identifier that appears in pytest ids. The `description` explains the behavior under test. Rules are specified under `rules` with `name`, `scopes`, and `features` at the top level (no `meta:` wrapper needed); the loader fills in the missing scope side with `unsupported`. The `features` field is a block string or list of strings in the DSL described below. Expected results go in `expect.matches`, mapping rule names to exact match locations.

Optional fields: `base address` (static only, defaults to `0`) and `options.span size` (patches `SPAN_SIZE` for that test).

Keep tests small and focused: each test case should have its own minimal feature set. Prefer many small individual tests over grouped rules sharing features.

## Feature DSL

Line prefixes for static tests: `global:`, `file:`, `func:`, `bb:`, `insn:`.
Line prefixes for dynamic tests: `global:`, `file:`, `proc:`, `thread:`, `call:`.

Static examples:
```
global: global: os(windows)
file: 0x402345: characteristic(embedded pe)
func: 0x401000
func: 0x401000: string(hello world)
bb: 0x401000: basic block
insn: 0x401000: mnemonic(mov)
insn: 0x401000: offset(0x402000) -> 0x402000
insn: 0x401000: string(key: value)
```

Dynamic examples:
```
proc: sample.exe (pid=3052)
thread: 3064
call: 11: api(LdrGetProcedureAddress)
call: 11: string(AddVectoredExceptionHandler)
```

`-> <addr>` overrides the feature location. Feature text may contain `: `. Dynamic call IDs must be unique within a test and can be used as shorthand in `expect.matches`.

## Address syntax

String forms: `0x401000`, `base address+0x100`, `file+0x20`, `token(0x1234)`, `token(0x1234)+0x10`, `global`, `process{pid:3052}`, `process{pid:3052,tid:3064}`, `process{pid:3052,tid:3064,call:11}` (with optional `ppid:`).

Dynamic tests may use a bare integer call ID in `expect.matches` when that call ID is unique within the test.
