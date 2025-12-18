<div align="center">
    <img src="https://github.com/mandiant/capa/blob/master/doc/img/ghidra_backend_logo.png" width=240 height=125>
</div>

# capa explorer for Ghidra

capa explorer for Ghidra brings capa’s detection capabilities directly to Ghidra’s user interface helping speed up your reverse engineering tasks by identifying what parts of a program suggest interesting behavior, such as setting a registry value. You can execute (via [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)) the script [capa_explorer.py](https://raw.githubusercontent.com/mandiant/capa/master/capa/ghidra/plugin/capa_explorer.py) using Ghidra’s Script Manager window to run capa’s analysis and view the results in Ghidra.

## ui integration
[capa_explorer.py](https://raw.githubusercontent.com/mandiant/capa/master/capa/ghidra/capa_explorer.py) renders capa results in Ghidra's UI to help you quickly navigate them. This includes adding matched functions to Ghidra’s Symbol Tree and Bookmarks windows and adding comments to functions that indicate matched capabilities and features. You can execute this script using Ghidra’s Script Manager window.

### symbol tree window
Matched functions are added to Ghidra's Symbol Tree window under a custom namespace that maps to the capabilities' [capa namespace](https://github.com/mandiant/capa-rules/blob/master/doc/format.md#rule-namespace).
<div align="center">
    <img src="https://github.com/mandiant/capa/assets/66766340/eeae33f4-99d4-42dc-a5e8-4c1b8c661492" width=300>
</div>

### comments

Comments are added at the beginning of matched functions indicating matched capabilities and inline comments are added to functions indicating matched features. You can view these comments in Ghidra’s Disassembly Listing and Decompile windows.
<div align="center">
    <img src="https://github.com/mandiant/capa/assets/66766340/bb2b4170-7fd4-45fc-8c7b-ff8f2e2f101b" width=1000>
</div>

### bookmarks

Bookmarks are added to functions that matched a capability that is mapped to a MITRE ATT&CK and/or Malware Behavior Catalog (MBC) technique. You can view these bookmarks in Ghidra's Bookmarks window.
<div align="center">
    <img src="https://github.com/mandiant/capa/assets/66766340/7f9a66a9-7be7-4223-91c6-4b8fc4651336" width=825>
</div>

# getting started

## requirements

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) >= 12.0 must be installed.
- [flare-capa](https://pypi.org/project/flare-capa/) >= 10.0 must be installed (virtual environment recommended) with the `ghidra` extra (e.g., `pip install "flare-capa[ghidra]"`).
- [capa rules](https://github.com/mandiant/capa-rules) must be downloaded for the version of capa you are using.

## execution

### 1. run Ghidra with PyGhidra
You must start Ghidra using the `pyghidraRun` script provided in the support directory of your Ghidra installation to ensure the Python environment is correctly loaded. You should execute `pyghidraRun` from within the Python environment that you used to install capa.

```bash
<ghidra_install>/support/pyghidraRun
```

### 2. run capa_explorer.py
1. Open your Ghidra project and CodeBrowser.
2. Open the Script Manager.
3. Add [capa_explorer.py](https://raw.githubusercontent.com/mandiant/capa/master/capa/ghidra/plugin/capa_explorer.py) to the script directories.
4. Filter for capa and run the script.
5. When prompted, select the directory containing the downloaded capa rules.
