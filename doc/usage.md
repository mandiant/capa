# capa usage

See `capa -h` for all supported arguments and usage examples.

## Ways to consume capa output

| Option | Description | Typical use |
|--------|-------------|-------------|
| **CLI** | `capa` on the command line | Scripting, CI/CD, one-off analysis |
| [**IDA Pro**](https://github.com/mandiant/capa/tree/master/capa/ida/plugin) | capa Explorer plugin inside IDA | Interactive analysis with jump-to-address |
| [**Ghidra**](https://github.com/mandiant/capa/tree/master/capa/ghidra/plugin) | capa Explorer plugin inside Ghidra | Interactive analysis with Ghidra integration |
| [**CAPE**](https://www.mandiant.com/resources/blog/dynamic-capa-executable-behavior-cape-sandbox) | capa run on sandbox report (e.g. CAPE, VMRay ZIP or VMRay flog.txt) | Dynamic analysis of sandbox output |
| [**Web (capa Explorer)**](https://mandiant.github.io/capa/explorer/) | Web UI (upload JSON or load from URL) | Sharing results, viewing from VirusTotal or similar |

## Default vs verbose output

By default, capa shows only *top-level* rule matches: capabilities that are not already implied by another displayed rule. For example, if a rule "persist via Run registry key" matches and it *contains* a match for "set registry value", the default output lists only "persist via Run registry key". This keeps the default output short while still reflecting all detected capabilities at the top level. Use **`-v`** to see all rule matches, including nested ones. Use **`-vv`** for an even more detailed view that shows how each rule matched.

## VMRay: flog.txt vs full analysis archive

When analysing VMRay output you can give capa either the full analysis **ZIP archive** or just the **flog.txt** function-log file.
Choose based on what you have access to and what features you need.

| | **flog.txt** (free, "Download Function Log") | **Full VMRay ZIP archive** |
|-|-|-|
| **How to obtain** | VMRay Threat Feed → Full Report → *Download Function Log* | Purchased subscription; *Download Analysis Archive* |
| **File size** | Small text file | Large encrypted ZIP |
| **Dynamic API calls** | ✓ | ✓ |
| **String arguments** | ✓ (parsed from text) | ✓ (from structured XML) |
| **Numeric arguments** | ✓ (parsed from text) | ✓ (from structured XML) |
| **Static imports / exports** | ✗ | ✓ |
| **PE/ELF section names** | ✗ | ✓ |
| **Embedded file strings** | ✗ | ✓ |
| **Base address** | ✗ | ✓ |
| **Argument names** | ✓ (text-format `name=value`) | ✓ (structured XML) |

**When to use flog.txt:** You only have access to VMRay Threat Feed without a full subscription, or you want a quick first pass using only the freely-available function log.

**When to use the full archive:** You need static features (imports, exports, strings, section names) in addition to dynamic behaviour, or you want the highest-fidelity argument data.

```
# flog.txt — free, limited to dynamic API calls
capa path/to/flog.txt

# Full VMRay archive — requires subscription, richer features
capa path/to/analysis_archive.zip
```

## tips and tricks

### only run selected rules
Use the `-t` option to run rules with the given metadata value (see the rule fields `rule.meta.*`).
For example, `capa -t william.ballenthin@mandiant.com` runs rules that reference Willi's email address (probably as the author), or
`capa -t communication` runs rules with the namespace `communication`.

### only analyze selected functions
Use the `--restrict-to-functions` option to extract capabilities from only a selected set of functions. This is useful for analyzing 
large functions and figuring out their capabilities and their address of occurrence; for example: PEB access, RC4 encryption, etc.

To use this, you can copy the virtual addresses from your favorite disassembler and pass them to capa as follows:
`capa sample.exe --restrict-to-functions 0x4019C0,0x401CD0`. If you add the `-v` option then capa will extract the interesting parts of a function for you.

### only analyze selected processes
Use the `--restrict-to-processes` option to extract capabilities from only a selected set of processes. This is useful for filtering the noise 
generated from analyzing non-malicious processes that can be reported by some sandboxes, as well as reduce the execution time 
by not analyzing such processes in the first place.

To use this, you can pick the PIDs of the processes you are interested in from the sandbox-generated process tree (or from the sandbox-reported malware PID) 
and pass that to capa as follows: `capa report.log --restrict-to-processes 3888,3214,4299`. If you add the `-v` option then capa will tell you 
which threads perform what actions (encrypt/decrypt data, initiate a connection, etc.).

### IDA Pro plugin: capa explorer
Please check out the [capa explorer documentation](/capa/ida/plugin/README.md).

### save time by reusing .viv files
Set the environment variable `CAPA_SAVE_WORKSPACE` to instruct the underlying analysis engine to 
cache its intermediate results to the file system. For example, vivisect will create `.viv` files.
Subsequently, capa may run faster when reprocessing the same input file.
This is particularly useful during rule development as you repeatedly test a rule against a known sample.
