<div align="center">
    <img src="/doc/img/ghidra_backend_logo.png" width=300 height=175>
</div>

The Ghidra feature extractor is an application of the FLARE team's open-source project, Ghidrathon, to integrate capa with Ghidra using Python 3. capa is a framework that uses a well-defined collection of rules to identify capabilities in a program. You can run capa against a PE file, ELF file, or shellcode and it tells you what it thinks the program can do. For example, it might suggest that the program is a backdoor, can install services, or relies on HTTP to communicate. The Ghidra feature extractor can be used to run capa analysis on your Ghidra databases without needing access to the original binary file.

## Getting Started

### Installation

| Dependency | Version | Source |
|------------|---------|--------|
| Ghidrathon | `>= 3.0.0` | https://github.com/mandiant/Ghidrathon |
| Python | `>= 3.8` | https://www.python.org/downloads |
| Ghidra | `>= 10.2` | https://ghidra-sre.org |

In order to run capa using the Ghidra feature extractor, you must install capa as a library and obtain the official capa rules that match the version you have installed. You can do this by completing the following steps using the Python 3 interpreter that you have configured for your Ghidrathon installation:

1. Install capa and its dependencies from PyPI:
```bash
$ pip install flare-capa
```

2. Download and extract the [official capa rules](https://github.com/mandiant/capa-rules/releases) that match the version you have installed
   1. Use the following command to view the version of capa you have installed:
```bash
$ pip show flare-capa
OR
$ capa --version
```

3. Copy `capa_ghidra.py`, found [here](/capa/ghidra/capa_ghidra.py), to your Ghidra user scripts directory OR manually add `</path/to/ghidra_capa.py/>` to the Ghidra Script Manager.
   1. This entrypoint script is located in `capa_install_dir/capa/ghidra/`

Once Ghidrathon is configured, you may now invoke capa from within Ghidra in three different ways. Each method suits different use cases of capa, and they include Ghidra's `headlessAnalyzer`, `Scripting Console`, and `Script Manger`.

## Running capa with the Ghidra feature extractor

### Ghidra's headlessAnalyzer

To invoke capa headlessly (i.e. without the Ghidra user interface), we must call the `analyzeHeadless` script provided in your `$GHIDRA_INSTALL_DIR/support` and point it towards capa's `capa_ghidra.py`. One thing to note is that capa runs as a `PostScript`, as in post-analysis script, so we need to provide `analyzeHeadless` with the path and script to run against our project. The preferred method for the Ghidra feature extractor is the entrypoint script, `/capa/ghidra/capa_ghidra.py`. Additional capa command line arguments must be provided in a single, space-delimited string i.e. `"/path/to/rules -v"`. To display the help & usage statement, the keyword `help` must be used instead of the typical `-h or --help`.

The syntax is as so:
```bash
./$GHIDRA_INSTALL_DIR/support/analyzeHeadless /path/to/gpr_dir/ gpr_name -process sample_name.exe_ -ScriptPath /path/to/capa_install/capa/ghidra -PostScript capa_ghidra.py "/path/to/rules/"
```
> **Note:** You may add the `$GHIDRA_INSTALL_DIR/support` to your `$PATH` in order to call `analyzeHeadless` as a standalone program.

If you do not have an existing ghidra project, you may also create one with the headlessAnalyzer via the `-Import` flag. Post scripts may also be ran in the same invocation.

The syntax to both import a new file and run capa against it is:
```bash
./$GHIDRA_INSTALL_DIR/support/analyzeHeadless /path/to/gpr_dir/ gpr_name -Import /path/to/sample_name.exe_ -ScriptPath /path/to/capa_install/capa/ghidra -PostScript capa_ghidra.py "/path/to/rules/"
```
> **Note:** The `/path/to/gpr_dir/` must exist before importing a new project into it.

**Example Output - very verbose flag:**
```
$ analyzeHeadless /home/wampus test -process Practical\ Malware\ Analysis\ Lab\ 01-01.dll_ -PostScript capa_ghidra.py "/home/wampus/capa/rules -vv"
[...]
INFO  REPORT: Analysis succeeded for file: /Practical Malware Analysis Lab 01-01.dll_ (HeadlessAnalyzer)  
INFO  SCRIPT: /ghidra_scripts/capa_ghidra.py (HeadlessAnalyzer)  
md5                     290934c61de9176ad682ffdd65f0a669                                                                                                                                                                                                   
sha1
sha256                  f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba
path                    /home/spring/Documents/capa/tests/data/Practical Malware Analysis Lab 01-01.dll_
timestamp               2023-08-25 15:40:39.990986
capa version            6.0.0
os                      windows
format                  Portable Executable (PE)
arch                    x86
extractor               ghidra
base address            global
rules                   /home/spring/Documents/capa/rules
function count          5
library function count  0
total feature count     376

contain loop (3 matches, only showing first match of library rule)
author  moritz.raabe@mandiant.com
scope   function
function @ 0x10001010
  or:
    characteristic: loop @ 0x10001010

delay execution (2 matches, only showing first match of library rule)
author      michael.hunhoff@mandiant.com, @ramen0x3f
scope       basic block
mbc         Anti-Behavioral Analysis::Dynamic Analysis Evasion::Delayed Execution [B0003.003]
references  https://docs.microsoft.com/en-us/windows/win32/sync/wait-functions, https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/TimingAttacks/timing.cpp
basic block @ 0x10001154 in function 0x10001010
  or:
    and:
      os: windows
      or:
        api: kernel32.Sleep @ 0x10001159

check mutex
namespace  host-interaction/mutex
author     moritz.raabe@mandiant.com, anushka.virgaonkar@mandiant.com
scope      basic block
mbc        Process::Check Mutex [C0043]
basic block @ 0x1000102E in function 0x10001010
  and:
    or:
      api: kernel32.OpenMutex @ 0x10001059

create mutex
namespace  host-interaction/mutex
author     moritz.raabe@mandiant.com, michael.hunhoff@mandiant.com
scope      function
mbc        Process::Create Mutex [C0042]
function @ 0x10001010
  or:
    api: kernel32.CreateMutex @ 0x1000106E

create process on Windows
namespace  host-interaction/process/create
author     moritz.raabe@mandiant.com
scope      basic block
mbc        Process::Create Process [C0017]
basic block @ 0x10001179 in function 0x10001010
  or:
    api: kernel32.CreateProcess @ 0x100011AF



Script /ghidra_scripts/capa_ghidra.py called exit with code 0
INFO  ANALYZING changes made by post scripts: /Practical Malware Analysis Lab 01-01.dll_ (HeadlessAnalyzer)  

[...]
```

### Ghidra's Script Manager

To invoke capa from the `Ghidra Script Manager`, open your Ghidra Project's Code Browser and open the `Script Manager` window by navigating to `Window -> Script Manager`. Select `capa_ghidra.py` and run the script. capa will then prompt you to choose a `rules` directory and specify the output verbosity level. 
> **Note:** In order for the Script Manager to recognize `capa_ghidra.py` you must either copy it to your Ghidra user scripts directory or update the Script Manager search path to include directory that contains it.


<div align="center">
    <img src="/doc/img/ghidra_script_mngr_rules.png">
    <img src="/doc/img/ghidra_script_mngr_verbosity.png">
    <img src="/doc/img/ghidra_script_mngr_output.png">
</div>

### Ghidrathon's Script Console

To invoke capa from Ghidrathon's Script Console, open your Ghidra project's Code Browser and open the `Ghidrathon` window by navigating to `Window -> Ghidrathon`.

You must import capa into the console and run it via:

```python3
>>> import capa
>>> from capa.ghidra import capa_ghidra 
>>> capa_ghidra.main()
```

Similarly to the Ghidra Script Manager, you will be prompted to choose a capa rules directory and specify output verbosity:

<div align="center">
    <img src="/doc/img/ghidra_console_output.png">
</div>

