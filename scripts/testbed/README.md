# Testbed
Goal of the testbed is to support the development of new `capa` rules. Scripts allow to test rules against a large sample set and to batch process samples, e.g. to freeze features or to generate other meta data used for testing.

The testbed contains malicious and benign files. Data sources are:
- Microsoft EXE and DLL files from `C:\Windows\System32`, `C:\Windows\SysWOW64`, etc.
- samples analyzed and annotated by FLARE analysts during malware analysis

Samples containing the keyword `slow` in their path indicate a longer test run time (>20 seconds) and can be ignored via the `-f` argument.

Running a rule against a large set of executable programs helps to quickly determine on which functions/samples a rule hits. This helps to identify:
- true positives: hits on expected functions
- false positives: hits on unexpected functions, for example
  - if a rule is to generic or
  - if a rule hits on a capability present in many (benign) samples

To provide additional context the testbed contains function names from the following data sources:
- benign files: function names from Microsoft's PDB information
- malicious files: function names provided by FLARE analysts and obtained from 
the LabelMaker 2000 (LM2k) annotations repository

For each test sample the testbed contains the following files:
- a `.frz` file storing the extracted `capa` features
  - `capa`'s serialized features, via `capa.features.freeze`
- a `.fnames` file mapping function addresses to function names
  - JSON file that maps fvas to function names or
  - CSV file with entries `idbmd5;md5;fva;fname`
- (optional) the binary file with extension `.exe_`, `.dll_`, or `.mal_`

## Scripts
### `run_rule_on_testbed.py`
Run a `capa` rule file against the testbed (frozen features in a directory).

Meant to be run on directories that contain `.frz` and `.fnames` files. 

Example usage:

    run_rule_on_testbed.py <testbed dir>
    run_rule_on_testbed.py samples

With the `-s <image_path>` argument, the script exports images of function graphs to the provided path.
Converting the images requires `graphviz`. See https://graphviz.gitlab.io/about/; get Python interface via `pip install graphviz`.

## Helper Scripts
### `freeze_features.py`
Use `freeze_features.py` to freeze `capa` features of a file or of files in a directory.

Example usage:

    freeze_features.py <testbed dir>
    freeze_features.py samples

### `start_ida_dump_fnames.py`
Start IDA Pro in autonomous mode to dump JSON file of function names `{fva: fname}`. Processes a single file or a directory.

This script uses `_dump_fnames.py` to dump the JSON file of functions names and is meant to be run on benign files with PDB information. IDA should apply function names from the PDB information automatically.

Example usage:

    start_ida_dump_fnames.py <candidate files dir>
    start_ida_dump_fnames.py samples\benign

### `start_ida_export_fimages.py`
Start IDA Pro in autonomous mode to export images of function graphs.
`run_rule_on_testbed.py` integrates the export mechanism (`-s` option)

This script uses `_export_fimages.py` to export DOT files of function graphs and then converts them to PNG images using `graphviz`.

Example usage:

    start_ida_export_fimages.py <target file> <output dir> -f <function list>
    start_ida_export_fimages.py test.exe imgs -f 0x401000,0x402F90
