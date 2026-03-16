# Vendored Quantum Strand string databases

Upstream: `../quantumstrand/` (https://github.com/mandiant/flare-floss, Quantum Strand branch)
Upstream commit: `73eb1541e896c065fc694ba7b01067f56871631b`

## Copied data files

- `data/oss/*.jsonl.gz` — open-source library string databases
- `data/crt/msvc_v143.jsonl.gz` — MSVC CRT string database
- `data/expert/capa.jsonl` — expert tagging rules (plain JSONL, not gzipped)
- `data/winapi/apis.txt.gz` — Windows API function names
- `data/winapi/dlls.txt.gz` — Windows DLL names
- `data/gp/gp.jsonl.gz` — global prevalence strings
- `data/gp/cwindb-native.jsonl.gz` — CWinDB native prevalence strings
- `data/gp/cwindb-dotnet.jsonl.gz` — CWinDB .NET prevalence strings
- `data/gp/junk-code.jsonl.gz` — junk/compiler-generated code strings
- `data/gp/xaa-hashes.bin` — truncated MD5 hash set (8 bytes per entry)
- `data/gp/yaa-hashes.bin` — truncated MD5 hash set (8 bytes per entry)

## Code

The loader, tagger, and model code in this package are mapa-local rewrites
inspired by upstream modules `floss/qs/db/oss.py`, `expert.py`, `gp.py`,
`winapi.py`, and the tagging logic in `floss/qs/main.py`. No upstream code
was copied verbatim.
