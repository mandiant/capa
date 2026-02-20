# Capa Explorer – Ghidra Extension (MVP)

Experimental Ghidra extension that integrates  
[capa](https://github.com/mandiant/capa) into Ghidra as a native plugin.

The goal is to run capa directly on Ghidra’s analysis database and display
results inside the UI.

---

## Status

**MVP / Experimental**

The current implementation validates the integration architecture and workflow.  
Full capa rule evaluation and richer UI will be added incrementally.

---

## How it works

1. User runs **Tools → Capa → Run Analysis**
2. The plugin invokes a Python script using **GhidraScriptService**
3. The script runs inside **PyGhidra** (no subprocesses)
4. Results are written to a **JSON cache file**
5. The plugin loads the cache and displays results in the **Capa Explorer** panel

---

## Key Design Decisions

- Uses **PyGhidra** for in-process Python execution  
- Uses **GhidraScriptService** (non-deprecated API)  
- Reuses the already-loaded `Program` (no reanalysis)  
- Exchanges data via a **cache file** instead of stdout  
- Results persist across Ghidra sessions  

---

## Current Features

- Run analysis from the Ghidra menu  
- Optional cache reload vs re-run  
- Background execution with progress  
- Basic result viewer panel  
