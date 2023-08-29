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

3. Copy `capa_ghidra.py`, found [here](/capa/ghidra/capa_ghidra.py), to your `$USER_HOME/ghidra_scripts` directory OR manually add `</path/to/ghidra_capa.py/>` to the Ghidra Script Manager.
   1. This entrypoint script is located in `capa_install_dir/capa/ghidra/`

Once Ghidrathon is configured, you may now invoke capa from within Ghidra in two different ways. These include Ghidra's Headless Analyzer and Script Manager.

## Running capa with the Ghidra feature extractor

### Ghidra's Script Manager

To invoke capa from the `Ghidra Script Manager`, open your Ghidra Project's Code Browser and open the `Script Manager` window by navigating to `Window -> Script Manager`. Select `capa_ghidra.py` and run the script. capa will then prompt you to choose a `rules` directory and specify the output verbosity level. 
> **Note:** In order for the Script Manager to recognize `capa_ghidra.py` you must either copy it to your `$USER_HOME/ghidra_scripts` directory or update the Script Manager search path to include the directory that contains it.

<div align="center">
    <img src="/doc/img/ghidra_script_mngr_rules.png">
    <img src="/doc/img/ghidra_script_mngr_verbosity.png">
    <img src="/doc/img/ghidra_script_mngr_output.png">
</div>

### Ghidra's Headless Analyzer

To invoke capa using the Ghidra Headless Analyzer, you can use Ghidra's `analyzeHeadless` script, located in your `$GHIDRA_INSTALL_DIR/support` directory.

`analyzeHeadless` requires these arguments to invoke capa:
1. `/path/to/ghidra/project ghidra_project_name`
2. `-process sample.exe_` OR `-Import /path/to/sample/sample.exe_`
3. `-ScriptPath /path/to/capa_ghidra/`
4. `-PostScript capa_ghidra.py`
5. `"/path/to/rules/ <args_to_capa>"`
> `"/path/to/rules/ <args_to_capa>"` must be provided in a single, space-delimited string. The help statement, normally accessed via `-h or --help`, must be accessed using the keyword `help` instead. 

To run capa against shellcode, Ghidra will require an additional argument to be passed to the Headless Analyzer. `-processor <languageID>` is used to specify the architecture in which Ghidra will process the sample.
> **Note:** More information on specifying the languageID can be found in the `$GHIDRA_INSTALL_DIR/support/analyzeHeadlessREADME.html` documentation.

The syntax is as so:
```bash
./$GHIDRA_INSTALL_DIR/support/analyzeHeadless /path/to/ghidra/project/ ghidra_project_name -process sample.exe_ -ScriptPath /path/to/capa_ghidra/ -PostScript capa_ghidra.py "/path/to/rules/ -vv"
```
> **Note:** You may add the `$GHIDRA_INSTALL_DIR/support` to your `$PATH` in order to call `analyzeHeadless` as a standalone program.

If you do not have an existing Ghidra project, you may also create one with the Headless Analyzer via the `-Import` flag. Post scripts may also be ran in the same invocation.

The syntax to both import a new file and run capa against it is:
```bash
./$GHIDRA_INSTALL_DIR/support/analyzeHeadless /path/to/ghidra/project/ ghidra_project_name -Import /path/to/sample/sample.exe_ -ScriptPath /path/to/capa_ghidra/ -PostScript capa_ghidra.py "/path/to/rules/"
```
> **Note:** The `/path/to/ghidra/project/` must exist before importing a new project into it.

To view the usage and help statement, the syntax is:
```bash
./$GHIDRA_INSTALL_DIR/support/analyzeHeadless /path/to/ghidra/project/ ghidra_project_name -process sample.exe_ -ScriptPath /path/to/capa_ghidra/ -PostScript capa_ghidra.py "help"
```

**Example Output: Shellcode & -vv flag**
```
$ analyzeHeadless ~/Desktop/ghidra_projects/ capa_test -process 499c2a85f6e8142c3f48d4251c9c7cd6.raw32 -processor x86:LE:32:default -ScriptPath ./capa/ghidra/ -PostScript capa_ghidra.py "./rules -vv"
[...]
INFO  REPORT: Analysis succeeded for file: /499c2a85f6e8142c3f48d4251c9c7cd6.raw32 (HeadlessAnalyzer)  
INFO  SCRIPT: /home/wumbo/capa/./capa/ghidra/capa_ghidra.py (HeadlessAnalyzer)  
md5                     499c2a85f6e8142c3f48d4251c9c7cd6                                                                                                                                                                                                    
sha1
sha256                  e8e02191c1b38c808d27a899ac164b3675eb5cadd3a8907b0ffa863714000e72
path                    /home/wumbo/capa/./tests/data/499c2a85f6e8142c3f48d4251c9c7cd6.raw32
timestamp               2023-08-29 17:57:00.946588
capa version            6.1.0
os                      unknown os
format                  Raw Binary
arch                    x86
extractor               ghidra
base address            global
rules                   /home/wumbo/capa/rules
function count          42
library function count  0
total feature count     1970

contain loop (24 matches, only showing first match of library rule)
author  moritz.raabe@mandiant.com
scope   function
function @ 0x0
  or:
    characteristic: loop @ 0x0
    characteristic: tight loop @ 0x278

contain obfuscated stackstrings
namespace  anti-analysis/obfuscation/string/stackstring
author     moritz.raabe@mandiant.com
scope      basic block
att&ck     Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools [T1027.005]
mbc        Anti-Static Analysis::Executable Code Obfuscation::Argument Obfuscation [B0032.020], Anti-Static Analysis::Executable Code Obfuscation::Stack Strings [B0032.017]
basic block @ 0x0 in function 0x0
  characteristic: stack string @ 0x0

encode data using XOR
namespace  data-manipulation/encoding/xor
author     moritz.raabe@mandiant.com
scope      basic block
att&ck     Defense Evasion::Obfuscated Files or Information [T1027]
mbc        Defense Evasion::Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02], Data::Encode Data::XOR [C0026.002]
basic block @ 0x8AF in function 0x8A1
  and:
    characteristic: tight loop @ 0x8AF
    characteristic: nzxor @ 0x8C0
    not: = filter for potential false positives
      or:
        or: = unsigned bitwise negation operation (~i)
          number: 0xFFFFFFFF = bitwise negation for unsigned 32 bits
          number: 0xFFFFFFFFFFFFFFFF = bitwise negation for unsigned 64 bits
        or: = signed bitwise negation operation (~i)
          number: 0xFFFFFFF = bitwise negation for signed 32 bits
          number: 0xFFFFFFFFFFFFFFF = bitwise negation for signed 64 bits
        or: = Magic constants used in the implementation of strings functions.
          number: 0x7EFEFEFF = optimized string constant for 32 bits
          number: 0x81010101 = -0x81010101 = 0x7EFEFEFF
          number: 0x81010100 = 0x81010100 = ~0x7EFEFEFF
          number: 0x7EFEFEFEFEFEFEFF = optimized string constant for 64 bits
          number: 0x8101010101010101 = -0x8101010101010101 = 0x7EFEFEFEFEFEFEFF
          number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF

get OS information via KUSER_SHARED_DATA
namespace   host-interaction/os/version
author      @mr-tz
scope       function
att&ck      Discovery::System Information Discovery [T1082]
references  https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
function @ 0x1CA6
  or:
    number: 0x7FFE026C = NtMajorVersion @ 0x1D18



Script /home/wumbo/capa/./capa/ghidra/capa_ghidra.py called exit with code 0
[...]
```
