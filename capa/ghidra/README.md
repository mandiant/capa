<div align="center">
    <img src="/doc/img/ghidra_backend_logo.png" width=300 height=175>
</div>

The Ghidra feature extractor is an application of the FLARE team's open-source project, Ghidrathon, to integrate capa with Ghidra using Python 3. capa is a framework that uses a well-defined collection of rules to identify capabilities in a program. You can run capa against a PE file, ELF file, or shellcode and it tells you what it thinks the program can do. For example, it might suggest that the program is a backdoor, can install services, or relies on HTTP to communicate. The Ghidra feature extractor can be used to run capa analysis on your Ghidra databases without needing access to the original binary file.

## Getting Started

### Installation

Please ensure that you have the following dependencies installed before continuing:

| Dependency | Version | Source |
|------------|---------|--------|
| Ghidrathon | `>= 3.0.0` | https://github.com/mandiant/Ghidrathon |
| Python | `>= 3.8` | https://www.python.org/downloads |
| Ghidra | `>= 10.2` | https://ghidra-sre.org |

You can run capa in Ghidra by completing the following steps using the Python 3 interpreter that you have configured for your Ghidrathon installation:

1. Install capa and its dependencies from PyPI using the following command:
```bash
$ pip install flare-capa
```

2. Download and extract the [official capa rules](https://github.com/mandiant/capa-rules/releases) that match the capa version you have installed. Use the following command to view the version of capa you have installed:
```bash
$ pip show flare-capa
OR
$ capa --version
```

3. Copy [capa_explorer.py](capa/ghidra/capa_explorer.py) and [capa_ghidra.py](/capa/ghidra/capa_ghidra.py) to your `$USER_HOME/ghidra_scripts` directory or manually add `</paths/to/scripts.py/>` to the Ghidra Script Manager.

## Usage

After completing the installation steps you can execute `capa_explorer.py` using the Ghidra Script Manager to integrate capa's results with Ghidra's UI. `capa_ghidra.py` is designed to be ran with both the Ghidra Script Manager and Headless Analyzer for capa's normal reports.  

### Ghidra Script Manager

Use the following steps to execute `capa_explorer.py` and `capa_ghidra.py` using Ghidra's Script Manager:
1. Open the Ghidra Script Manager by navigating to `Window > Script Manager`
2. Locate `capa_explorer.py` and `capa_ghidra.py` by selecting the `Python 3 > capa` category or using the Ghidra Script Manager search functionality
3. Double-click `capa_explorer.py` or `capa_ghidra.py` to execute the script

If you don't see `capa_explorer.py` and `capa_ghidra.py` make sure you have copied these scripts to your `$USER_HOME/ghidra_scripts` directory or manually added `</path/to/scripts>` to the Ghidra Script Manager.

Both scripts ask you to provide the path of your capa rules directory. `capa_ghidra.py` also asks you to select `default`, `verbose`, and `vverbose` output formats used when writing output to the Ghidra Console Window.

### Using `capa_ghidra.py`

The following is an example of running `capa_ghidra.py` using the Ghidra Script Manager:

Selecting capa rules:
<img src="/doc/img/ghidra_script_mngr_rules.png">

Choosing output format:
<img src="/doc/img/ghidra_script_mngr_verbosity.png">

Viewing results in Ghidra Console Window:
<img src="/doc/img/ghidra_script_mngr_output.png">

### Interpreting `capa_explorer.py` Results

By invoking capa analysis via `capa_explorer.py`, this script will take the results and import them directly into the Ghidra project. In the Symbol Tree Window, under the Namespaces section, you can find the matched rules as well as the corresponding functions that contain the extracted features.

Namespaces & Labeled Functions:

![image](https://github.com/mandiant/capa/assets/66766340/eeae33f4-99d4-42dc-a5e8-4c1b8c661492)

Labeled functions may be clicked on from the Symbol Tree Window in order to hop straight to these sections of code in the Disassembly Listing and Decompilation views. Plate comments will be found above the function symbol, containing each matched rule for that function. Throughout the listing and decompilation views, you will also find pre-comments that highlight extracted features and the rules they correspond to.

Commented Matches and Subscoped Features:

![image](https://github.com/mandiant/capa/assets/66766340/bb2b4170-7fd4-45fc-8c7b-ff8f2e2f101b)

This script will also create Bookmarks on functions that may be categorized under the MITRE ATT&CK Framework as well as the Malware Behavior Catalog (MBC). These may be found via the Bookmarks Window, and the Labels may also be double clicked to align the Disassembly Listing and Decompilation views. 

MITRE ATT&CK & MBC Bookmarks:

![image](https://github.com/mandiant/capa/assets/66766340/7f9a66a9-7be7-4223-91c6-4b8fc4651336)

### Ghidra Headless Analyzer

To execute `capa_ghidra.py` using the Ghidra Headless Analyzer, you can use the Ghidra `analyzeHeadless` script located in your `$GHIDRA_HOME/support` directory. You will need to provide the following arguments to the Ghidra `analyzeHeadless` script:

1. `</path/to/ghidra/project/>`: path to Ghidra project
2. `<ghidra_project_name>`: name of Ghidra Project
3. `-process <sample_name>`: name of sample `<sample_name>`
4. `-ScriptPath </path/to/capa_ghidra/>`: OPTIONAL argument specifying path `</path/to/capa_ghidra/>` to `capa_ghidra.py`
5. `-PostScript capa_ghidra.py`: executes `capa_ghidra.py` as post-analysis script
6. `"<capa_args>"`: single, quoted string containing capa arguments that must specify capa rules directory and output format, e.g. `"<path/to/capa/rules> --verbose"`. `capa_ghidra.py` supports `default`, `verbose`, `vverbose` and `json` formats when executed using the Ghidra Headless Analyzer. `capa_ghidra.py` writes output to the console window used to execute the Ghidra `analyzeHeadless` script.
7. `-processor <languageID>`: required ONLY if sample `<sample_name>` is shellcode. More information on specifying the `<languageID>` can be found in the `$GHIDRA_HOME/support/analyzeHeadlessREADME.html` documentation.

The following is an example of combining these arguments into a single `analyzeHeadless` script command:

```
$GHIDRA_HOME/support/analyzeHeadless </path/to/ghidra/project/> <ghidra_project_name> -process <sample_name> -PostScript capa_ghidra.py "/path/to/capa/rules/ --verbose"
```

You may also want to run capa against a sample that you have not yet imported into your Ghidra project. The following is an example of importing a sample and running `capa_ghidra.py` using a single `analyzeHeadless` script command:

```
$GHIDRA_HOME/support/analyzeHeadless </path/to/ghidra/project/> <ghidra_project_name> -Import </path/to/sample> -PostScript capa_ghidra.py "/path/to/capa/rules/ --verbose"
```

You can also provide `capa_ghidra.py` the single argument `"help"` to view supported arguments when running the script using the Ghidra Headless Analyzer:
```
$GHIDRA_HOME/support/analyzeHeadless </path/to/ghidra/project/> <ghidra_project_name> -process <sample_name> -PostScript capa_ghidra.py "help"
```

#### Example

The following is an example of running `capa_ghidra.py` against a shellcode sample using the Ghidra `analyzeHeadless` script:
```
$ analyzeHeadless /home/wumbo/Desktop/ghidra_projects/ capa_test -process 499c2a85f6e8142c3f48d4251c9c7cd6.raw32 -processor x86:LE:32:default -PostScript capa_ghidra.py "/home/wumbo/capa/rules -vv"
[...]

INFO  REPORT: Analysis succeeded for file: /499c2a85f6e8142c3f48d4251c9c7cd6.raw32 (HeadlessAnalyzer)  
INFO  SCRIPT: /home/wumbo/ghidra_scripts/capa_ghidra.py (HeadlessAnalyzer)  
md5                     499c2a85f6e8142c3f48d4251c9c7cd6                                                                                                                                                                                                    
sha1
sha256                  e8e02191c1b38c808d27a899ac164b3675eb5cadd3a8907b0ffa863714000e72
path                    /home/wumbo/capa/tests/data/499c2a85f6e8142c3f48d4251c9c7cd6.raw32
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



Script /home/wumbo/ghidra_scripts/capa_ghidra.py called exit with code 0

[...]
```
