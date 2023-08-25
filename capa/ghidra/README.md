<div align="center">
    <img src="/doc/img/ghidra_backend_logo.png" width=300 height=175>
</div>

The Ghidra feature extractor is an application of the FLARE team's open-source project, Ghidrathon, to integrate capa with Ghidra. capa is a framework that uses a well-defined collection of rules to identify capabilities in a program. You can run capa against a PE file, ELF file, or shellcode and it tells you what it thinks the program can do. For example, it might suggest that the program is a backdoor, can install services, or relies on HTTP to communicate. The Ghidra feature extractor can be used to run capa analysis on your Ghidra databases without needing access to the original binary file.

## Installation & Usage:
**Dependencies:**
| Dependency | Version | Source |
|------------|---------|--------|
| capa | `>= 6.1.0` | `<url for capa release>`
| Ghidrathon | `>= 3.0.0` | https://github.com/mandiant/Ghidrathon |
> **note:** Please follow the Ghidrathon installation guide to ensure all additional dependency requirements are met and that it is properly configured to work with Ghidra

Once Ghidrathon is configured and ready-to-go, you may now invoke capa from within Ghidra in three different ways. Each method suits different use cases of capa, and they include the `headlessAnalyzer`, `Scripting Console`, and `Script Manger`.

### headlessAnalyzer

To invoke capa headlessly (i.e. without the Ghidra user interface), we must call the `analyzeHeadless` script provided in your `$GHIDRA_INSTALL_DIR` and point it towards capa's `main.py`. One thing to note is that capa runs as a `PostScript`, as in post-analysis script, so we need to provide `analyzeHeadless` with the path and script to run against our project.

The syntax is as so:
```bash
./$GHIDRA_INSTALL_DIR/support/analyzeHeadless /path/to/gpr_dir/ gpr_name -process sample_name.exe_ -ScriptPath /path/to/capa_install/capa -PostScript main.py
```
> **note:** You may add the `$GHIDRA_INSTALL_DIR/support` to your `$PATH` in order to call `analyzeHeadless` as a standalone program.

If you do not have an existing ghidra project, you may also create one with the headlessAnalyzer via the `-Import` flag. Post scripts may also be ran in the same invocation.

The syntax to both import a new file and run capa against it is:
```bash
./$GHIDRA_INSTALL_DIR/support/analyzeHeadless /path/to/gpr_dir/ gpr_name -Import /path/to/sample_name.exe_ -ScriptPath /path/to/capa_install/capa -PostScript main.py
```
> **note:** The `/path/to/gpr_dir/` must exist before importing a new project into it.

A successful headlessAnalyzer run should look like:

<img src="/doc/img/ghidrathon_headless.gif">

### Script Console

