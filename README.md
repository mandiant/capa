# capa
[![Build Status](https://drone.oneteamed.net/api/badges/FLARE/capa/status.svg)](https://drone.oneteamed.net/FLARE/capa)

capa detects capabilities in executable files.
You run it against a .exe or .dll and it tells you what it thinks the program can do.
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.

```
λ capa.exe suspicious.exe -q

objectives:
  communication
  data manipulation
  machine access control

behaviors:
  communication-via-http
  encrypt data
  load code functionality

techniques:
  send-http-request
  encrypt data using rc4
  load pe

```

# download

Download capa from the [Releases](/releases) page or get the nightly builds here:
- Windows 64bit: TODO
- Windows 32bit: TODO
- Linux: TODO
- OSX: TODO


# contents

- [installation](#installation)
- [example](#example)
- [rule format](#rule-format)
  - [meta block](#meta-block)
  - [features block](#features-block)
- [extracted features](#extracted-features)
  - [function features](#function-features)
    - [api](#api)
    - [number](#number)
    - [string](#string)
    - [bytes](#bytes)
    - [offset](#offset)
    - [mnemonic](#mnemonic)
    - [characteristics](#characteristics)
  - [file features](#file-features)
    - [string](#file-string)
    - [export](#export)
    - [import](#import)
    - [section](#section)
  - [counting](#counting)
  - [matching prior rule matches](#matching-prior-rule-matches)
- [limitations](#Limitations)

# installation

See [doc/installation.md](doc/installation.md) for information on how to setup the project, including how to use it as a Python library.

For more information about how to use capa, including running it as an IDA script/plugin see [doc/usage.md](doc/usage.md).

# example

Here we run capa against an unknown binary (`level32.exe`),
and the tool reports that the program can decode data via XOR,
references data in its resource section, writes to a file, and spawns a new process.
Taken together, this makes us think that `level32.exe` could be a dropper.
Therefore, our next analysis step might be to run `level32.exe` in a sandbox and try to recover the payload.

```
λ capa.exe level32.exe -q
disposition: malicious
category: dropper

objectives:
  data manipulation
  machine access control

behaviors:
  encrypt data
  load code functionality

techniques:
  encrypt data using rc4
  load pe

anomalies:
  embedded PE file
```

By passing the `-vv` flag (for Very Verbose), capa reports exactly where it found evidence of these capabilities.
This is useful for at least two reasons:

  - it helps explain why we should trust the results, and enables us to verify the conclusions
  - it shows where within the binary an experienced analyst might study with IDA Pro

```
λ capa.exe level32.exe -q -vv
rule load PE file:
  - function 0x401c58:
      or:
        and:
          mnemonic(cmp):
            - virtual address: 0x401c58
            - virtual address: 0x401c68
            - virtual address: 0x401c74
            - virtual address: 0x401c7f
            - virtual address: 0x401c8a
          or:
            number(0x4550):
              - virtual address: 0x401c68
          or:
            number(0x5a4d):
              - virtual address: 0x401c58
...
```


# rule format

capa uses a collection of rules to identify capabilities within a program.
These rules are easy to write, even for those new to reverse engineering.
By authoring rules, you can extend the capabilities that capa recognizes.
In some regards, capa rules are a mixture of the OpenIOC, Yara, and YAML formats.

Here's an example rule used by capa:

```
───────┬────────────────────────────────────────────────────────
       │ File: rules/calculate-crc32.yml
───────┼────────────────────────────────────────────────────────
   1   │ rule:
   2   │   meta:
   3   │     name: calculate CRC32
   4   |     rule-category: data-manipulation/hash-data/hash-data-using-crc32
   5   │     author: moritz.raabe@fireeye.com
   6   │     scope: function
   7   │     examples:
   8   │       - 2D3EDC218A90F03089CC01715A9F047F:0x403CBD
   9   │   features:
  10   │     - and:
  11   │       - mnemonic: shr
  12   │       - number: 0xEDB88320
  13   │       - number: 8
  14   │       - characteristic(nzxor): True
───────┴────────────────────────────────────────────────────────
```

Rules are yaml files that follow a certain schema.

The top level element is a dictionary named `rule` with two required children dictionaries:
`meta` and `features`.


## meta block

The meta block contains metadata that identifies the rule, categorizes into behaviors, 
and provides references to additional documentation.
Here are the common fields:

  - `name` is required. This string should uniquely identify the rule.

  - `rule-category` is required when a rule describes a behavior (as opposed to matching a role or disposition).
The rule category specifies an objective, behavior, and technique matched by this rule,
using a format like `$objective/$behavior/$technique`.
An objective is a high level goal of a program, such as "communication".
A behavior is something that a program may do, such as "communication via socket".
A technique is a way of implementing some behavior, such as "send-data".

  - `maec/malware-category` is required when the rule describes a role, such as `dropper` or `backdoor`.

  - `maec/analysis-conclusion` is required when the rule describes a disposition, such as `benign` or `malicious`.

  - `scope` indicates to which feature set this rule applies.
    It can takes the following values:
    - **`basic block`:** limits matches to a basic block.
      It is used to achieve locality in rules (for example for parameters of a function).
    - **`function`:** identify functions.
      It doesn't support child functions (see [doc/limitations.md](doc/limitations.md#wrapper-functions-and-matches-in-child-functions)).
      It is the default.
    - **`file`:** matches file format aspects.
    - **`program`:** *matches the matches* of `function` and `file` scopes.
      Not yet implemented.

  - `author` specifies the name or handle of the rule author.

  - `examples` is a list of references to samples that should match the capability.
When the rule scope is `function`, then the reference should be `<sample hash>:<function va>`.

  - `reference` lists related information in a book, article, blog post, etc.

Other fields are allowed but not defined in this specification. `description` is probably a good one.


## features block

This section declares logical statements about the features that must exist for the rule to match.

There are five structural expressions that may be nested:
  - `and` - all of the children expressions must match
  - `or` - match at least one of the children
  - `not` - match when the child expression does not
  - `N or more` - match at least `N` or more of the children
    - `optional` is an alias for `0 or more`, which is useful for documenting related features. See [write-file.yml](/rules/machine-access-control/file-manipulation/write-file.yml) for an example.
  
For example, consider the following rule:

```
   9   │     - and:
  10   │       - mnemonic: shr
  11   │       - number: 0xEDB88320
  12   │       - number: 8
  13   │       - characteristic(nzxor): True
```

For this to match, the function must:
  - contain an `shr` instruction, and
  - reference the immediate constant `0xEDB88320`, which some may recognize as related to the CRC32 checksum, and
  - reference the number `8`, and
  - have an unusual feature, in this case, contain a non-zeroing XOR instruction
If only one of these features is found in a function, the rule will not match.


# extracted features

## function features

capa extracts features from the disassembly of a function, such as which API functions are called.
The tool also reasons about the code structure to guess at function-level constructs.
These are the features supported at the function-scope:

  - [api](#api)
  - [number](#number)
  - [string](#string)
  - [bytes](#bytes)
  - [offset](#offset)
  - [mnemonic](#mnemonic)
  - [characteristics](#characteristics)

### api
A call to a named function, probably an import,
though possibly a local function (like `malloc`) extracted via FLIRT.

The parameter is a string describing the function name, specified like `module.functionname` or `functionname`.

Example:

    api: kernel32.CreateFileA
    api: CreateFileA

### number
A number used by the logic of the program.
This should not be a stack or structure offset.
For example, a crypto constant.

The parameter is a number; if prefixed with `0x` then in hex format, otherwise, decimal format.

To associate context with a number, e.g. for constant definitions, append an equal sign and the respective name to
the number definition. This helps with documenting rules and provides context in capa's output.

Examples:

    number: 16
    number: 0x10
    number: 0x40 = PAGE_EXECUTE_READWRITE

TODO: signed vs unsigned.

### string
A string referenced by the logic of the program.
This is probably a pointer to an ASCII or Unicode string.
This could also be an obfuscated string, for example a stack string.

The parameter is a string describing the string.
This can be the verbatim value, or a regex matching the string.
Regexes should be surrounded with `/` characters. 
By default, capa uses case-sensitive matching and assumes leading and trailing wildcards.
To perform case-insensitive matching append an `i`. To anchor the regex at the start or end of a string, use `^` and/or `$`.

Examples:

    string: This program cannot be run in DOS mode.
    string: Firefox 64.0
    string: /SELECT.*FROM.*WHERE/
    string: /Hardware\\Description\\System\\CentralProcessor/i
    
Note that regex matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

### bytes
A sequence of bytes referenced by the logic of the program. 
The provided sequence must match from the beginning of the referenced bytes and be no more than `0x100` bytes.
The parameter is a sequence of hexadecimal bytes followed by an optional description.
 

The example below illustrates byte matching given a COM CLSID pushed onto the stack prior to `CoCreateInstance`.

Disassembly:

    push    offset iid_004118d4_IShellLinkA ; riid
    push    1               ; dwClsContext
    push    0               ; pUnkOuter
    push    offset clsid_004118c4_ShellLink ; rclsid
    call    ds:CoCreateInstance

Example rule elements:

    bytes: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = CLSID_ShellLink
    bytes: EE 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = IID_IShellLink

### offset
A structure offset referenced by the logic of the program.
This should not be a stack offset.

The parameter is a number; if prefixed with `0x` then in hex format, otherwise, decimal format.

Examples:

    offset: 0xC
    offset: 0x14

### mnemonic

An instruction mnemonic found in the given function.

The parameter is a string containing the mnemonic.

Examples:

    mnemonic: xor
    mnemonic: shl
    
    
### characteristics

Characteristics are features that are extracted by the analysis engine.
They are one-off features that seem interesting to the authors.

For example, the `characteristic(nzxor)` feature describes non-zeroing XOR instructions.
captdet does not support instruction pattern matching,
 so a select set of interesting instructions are pulled out as characteristics.

| characteristic                             | scope                 | description |
|--------------------------------------------|-----------------------|-------------|
| `characteristic(embedded pe): true`        | file                  | (XOR encoded) embedded PE files. |
| `characteristic(switch): true`             | function              | Function contains a switch or jump table. |
| `characteristic(loop): true`               | function              | Function contains a loop. |
| `characteristic(recursive call): true`     | function              | Function is recursive. |
| `characteristic(calls from): true`         | function              | There are unique calls from this function. Best used like: `count(characteristic(calls from)): 3 or more` |
| `characteristic(calls to): true`           | function              | There are unique calls to this function. Best used like: `count(characteristic(calls to)): 3 or more` |
| `characteristic(nzxor): true`              | basic block, function | Non-zeroing XOR instruction |
| `characteristic(peb access): true`         | basic block, function | Access to the process environment block (PEB), e.g. via fs:[30h], gs:[60h], or `NtCurrentPeb` |
| `characteristic(fs access): true`          | basic block, function | Access to memory via the `fs` segment. |
| `characteristic(gs access): true`          | basic block, function | Access to memory via the `gs` segment. |
| `characteristic(cross section flow): true` | basic block, function | Function contains a call/jump to a different section. This is commonly seen in unpacking stubs. |
| `characteristic(tight loop): true`         | basic block           | A tight loop where a basic block branches to itself. |
| `characteristic(indirect call): true`      | basic block, function | Indirect call instruction; for example, `call edx` or `call qword ptr [rsp+78h]`. |

## file features

capa extracts features from the file data.
File features stem from the file structure, i.e. PE structure or the raw file data.
These are the features supported at the file-scope:

  - [string](#file-string)
  - [export](#export)
  - [import](#import)
  - [section](#section)

### file string
An ASCII or UTF-16 LE string present in the file.

The parameter is a string describing the string.
This can be the verbatim value, or a regex matching the string.
Regexes should be surrounded with `/` characters. By default, capa uses case-sensitive matching.
To perform case-insensitive matching append an `i`.

Examples:

    string: Z:\Dev\dropper\dropper.pdb
    string: [ENTER]
    string: /.*VBox.*/
    string: /.*Software\Microsoft\Windows\CurrentVersion\Run.*/i

Note that regex matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

### export

The name of a routine exported from a shared library.

Examples:

    export: InstallA

### import

The name of a routine imported from a shared library.

Examples:

    import: kernel32.WinExec
    import: WinExec           # wildcard module name
    import: kernel32.#22      # by ordinal

### section

The name of a section in a structured file.

Examples:

    section: .rsrc

## counting

Many rules will inspect the feature set for a select combination of features;
however, some rules may consider the number of times a feature was seen in a feature set.

These rules can be expressed like:

    count(characteristic(nzxor)): 2           # exactly match count==2
    count(characteristic(nzxor)): 2 or more   # at least two matches
    count(characteristic(nzxor)): 2 or fewer  # at most two matches
    count(characteristic(nzxor)): (2, 10)     # match any value in the range 2<=count<=10

    count(mnemonic(mov)): 3
    count(basic block): 4

## matching prior rule matches

capa rules can specify logic for matching on other rule matches.
This allows a rule author to refactor common capability patterns into their own reusable components.
You can specify a rule match expression like so:

    - and:
      - match: file creation
      - match: process creation

Rules are uniquely identified by their `rule.meta.name` property;
this is the value that should appear on the right hand side of the `match` expression.

capa will refuse to run if a rule dependency is not present during matching.

Common rule patterns, such as the various ways to implement "writes to a file", can be refactored into "library rules". 
These are rules with `rule.meta.lib: True`.
By default, library rules will not be output to the user as a rule match, 
but can be matched by other rules.
When no active rules depend on a library rule, these the library rules will not be evaluated - maintaining performance.

# limitations

To learn more about capa's current limitations see [here](doc/limitations.md).
