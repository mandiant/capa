# Capa Explorer – Ghidra Extension (MVP)

This directory contains an experimental Ghidra extension that integrates
[capa](https://github.com/mandiant/capa) directly into Ghidra as a native plugin.

The goal of this extension is to provide a workflow similar to the IDA Pro
capa explorer plugin, while fully leveraging Ghidra’s analysis database.

---

## Status

Experimental / MVP

This implementation is intentionally minimal and focuses on validating:

- Ghidra extension packaging
- Java <–-> Python integration using PyGhidra
- Reuse of the existing Ghidra analysis database
- Execution of capa from the Ghidra UI

Full capa functionality (rules, feature extractors, result views) will be added
incrementally after architectural review.

---

## Key design principles

### PyGhidra-based integration

This extension uses PyGhidra as the execution bridge between Java and Python.

- Python executes inside the Ghidra JVM
- No external Python subprocesses are spawned
- No binaries are reloaded or reanalyzed

This ensures capa operates directly on the already-analyzed Program object.

---

### Reuse of existing Ghidra analysis

The extension passes the active Ghidra program directly to Python:

```python
program = currentProgram