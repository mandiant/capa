# capa analysis using Ghidra

capa supports using Ghidra (via [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)) as a feature extraction backend. This enables you to run capa against binaries using Ghidra's analysis engine.

```bash
$ capa -b ghidra Practical\ Malware\ Analysis\ Lab\ 01-01.exe_
┌──────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ md5      │ bb7425b82141a1c0f7d60e5106676bb1                                                                     │
│ sha1     │                                                                                                      │
│ sha256   │ 58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47                                     │
│ analysis │ static                                                                                               │
│ os       │ windows                                                                                              │
│ format   │ pe                                                                                                   │
│ arch     │ i386                                                                                                 │
│ path     │ ~/Documents/capa/tests/data/Practical Malware Analysis Lab 01-01.exe_                                │
└──────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────┘
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ATT&CK Tactic                      ┃ ATT&CK Technique                                            ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ DISCOVERY                          │ File and Directory Discovery [T1083]                        │
└────────────────────────────────────┴─────────────────────────────────────────────────────────────┘
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ MBC Objective                      ┃ MBC Behavior                                                ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ DISCOVERY                          │ File and Directory Discovery [E1083]                        │
│ FILE SYSTEM                        │ Copy File [C0045]                                           │
│                                    │ Read File [C0051]                                           │
│ PROCESS                            │ Terminate Process [C0018]                                   │
└────────────────────────────────────┴─────────────────────────────────────────────────────────────┘
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Capability                                     ┃ Namespace                                       ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ copy file                                      │ host-interaction/file-system/copy               │
│ enumerate files recursively                    │ host-interaction/file-system/files/list         │
│ read file via mapping (2 matches)              │ host-interaction/file-system/read               │
│ terminate process (2 matches)                  │ host-interaction/process/terminate              │
│ resolve function by parsing PE exports         │ load-code/pe                                    │
└────────────────────────────────────────────────┴─────────────────────────────────────────────────┘
```

## getting started

### requirements

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) >= 12.0 must be installed and available via the `GHIDRA_INSTALL_DIR` environment variable.

#### standalone binary (recommended)

The capa [standalone binary](https://github.com/mandiant/capa/releases) is the preferred way to run capa with the Ghidra backend.
Although the binary does not bundle the Java environment or Ghidra itself, it will dynamically load them at runtime.

#### python package

You can also use the Ghidra backend with the capa Python package by installing `flare-capa` with the `ghidra` extra.

```bash
$ pip install "flare-capa[ghidra]"
```

### usage

To use the Ghidra backend, specify it with the `-b` or `--backend` flag:

```bash
$ capa -b ghidra /path/to/sample
```

capa will:
1.  Initialize a headless Ghidra instance.
2.  Create a temporary project.
3.  Import and analyze the sample.
4.  Extract features and match rules.
5.  Clean up the temporary project.

**Note:** The first time you run this, it may take a few moments to initialize the Ghidra environment.
