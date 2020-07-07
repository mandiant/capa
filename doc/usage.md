# capa usage

```
usage: capa [-h] [-r RULES] [-t TAG] [--version] [-j] [-v] [-vv] [-d] [-q]
            [-f {auto,pe,sc32,sc64,freeze}]
            sample

detect capabilities in programs.

positional arguments:
  sample                Path to sample to analyze

optional arguments:
  -h, --help            show this help message and exit
  -r RULES, --rules RULES
                        Path to rule file or directory, use embedded rules by
                        default
  -t TAG, --tag TAG     Filter on rule meta field values
  --version             Print the executable version and exit
  -j, --json            Emit JSON instead of text
  -v, --verbose         Enable verbose result document (no effect with --json)
  -vv, --vverbose       Enable very verbose result document (no effect with
                        --json)
  -d, --debug           Enable debugging output on STDERR
  -q, --quiet           Disable all output but errors
  -f {auto,pe,sc32,sc64,freeze}, --format {auto,pe,sc32,sc64,freeze}
                        Select sample format, auto: (default) detect file type
                        automatically, pe: Windows PE file, sc32: 32-bit
                        shellcode, sc64: 64-bit shellcode, freeze: features
                        previously frozen by capa
```

## tips and tricks

  - [match only rules by given author or namespace](#only-run-selected-rules)
  - [IDA Pro capa explorer](#capa-explorer)
  - [IDA Pro rule generator](#rule-generator)

### only run selected rules
Use the `-t` option to run rules with the given metadata value (see therule  fields `rule.meta.*`).
For example, `capa -t william.ballenthin@mandiant.com` runs rules that reference Willi's email address (probably as the author), or
`capa -t communication` runs rules with the namespace `communication`.

### IDA Pro integrations
You can run capa from within IDA Pro. Run `capa/main.py` via `File - Script file...` (or ALT + F7). 
When running in IDA, capa uses IDA's disassembly and file analysis as its backend. 
These results may vary from the standalone version that uses vivisect.
IDA's analysis is generally a bit faster and more thorough than vivisect's, so you might prefer this mode.

When run under IDA, capa supports both Python 2 and Python 3 interpreters.
If you encounter issues with your specific setup, please open a new [Issue](https://github.com/fireeye/capa/issues).

Additionally, capa comes with two IDA Pro plugins located in the `capa/ida` directory: the explorer and the rule generator.

#### capa explorer
The capa explorer allows you to interactively display and browse capabilities capa identified in a binary.
As you select rules or logic, capa will highlight the addresses that support its analysis conclusions.
We like to use capa to help find the most interesting parts of a program, such as where the C2 mechanism might be.

![capa explorer](capa_explorer.png)

#### rule generator
The rule generator helps you to easily write new rules based on the function you are currently analyzing in your IDA disassembly view.
It shows the features that capa can extract from the function, and lets you quickly pull these into a rule template.
You'll still have to provide the logic structures (`and`, `or`, `not`, etc.) but the features will be prepared for you.
