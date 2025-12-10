<div align="center">
    <img src="../../doc/img/ghidra_backend_logo.png" width=240 height=125>
</div>

# capa + Ghidra

[capa](https://github.com/mandiant/capa) is the FLARE team’s open-source tool that detects capabilities in executable files. [Ghidra](https://github.com/NationalSecurityAgency/ghidra) is an open-source software reverse engineering framework. capa + Ghidra brings capa’s detection capabilities to Ghidra using [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra).

## Prerequisites

- Ghidra >= 12.0 must be installed and available to PyGhidra (e.g. set `GHIDRA_INSTALL_DIR` environment variable)

## Usage

```bash
$ capa -b ghidra /path/to/sample
```
