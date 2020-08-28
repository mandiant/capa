# capa usage

See `capa -h` for all supported arguments and usage examples.

## tips and tricks

  - [match only rules by given author or namespace](#only-run-selected-rules)
  - [IDA Pro capa explorer](#capa-explorer)
  - [IDA Pro rule generator](#rule-generator)

### only run selected rules
Use the `-t` option to run rules with the given metadata value (see the rule fields `rule.meta.*`).
For example, `capa -t william.ballenthin@mandiant.com` runs rules that reference Willi's email address (probably as the author), or
`capa -t communication` runs rules with the namespace `communication`.

### IDA Pro integrations
You can run capa from within IDA Pro. Run `capa/main.py` via `File - Script file...` (or ALT + F7). 
When running in IDA, capa uses IDA's disassembly and file analysis as its backend. 
These results may vary from the standalone version that uses vivisect.
IDA's analysis is generally a bit faster and more thorough than vivisect's, so you might prefer this mode.

When run under IDA, capa supports both Python 2 and Python 3 interpreters.
If you encounter issues with your specific setup, please open a new [Issue](https://github.com/fireeye/capa/issues).

Additionally, capa comes with an IDA Pro plugin located in the `capa/ida/plugin` directory: the explorer.

#### capa explorer
The capa explorer allows you to interactively display and browse capabilities capa identified in a binary.
As you select rules or logic, capa will highlight the addresses that support its analysis conclusions.
We like to use capa to help find the most interesting parts of a program, such as where the C2 mechanism might be.

![capa explorer](img/capa_explorer.png)

The plugin currently supports IDA Pro 7.1 through 7.5 with either Python 2 or Python 3. To use the plugin, install capa
by following method 2 or 3 from the [installation guide](doc/installation.md) and copy [capa_plugin_ida.py](capa_plugin_ida.py)
to the plugins directory of your IDA Pro installation. Following these steps you can run capa explorer in IDA Pro by navigating 
to `Edit > Plugins > capa explorer`. The plugin will prompt you to select a rules directory to use for analysis. You can 
use the [default rule set](https://github.com/fireeye/capa-rules/) or point the plugin to your own directory of rules.
