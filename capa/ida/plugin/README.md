FLARE capa plugin brings the program capabilities detection of [capa](https://github.com/fireeye/capa) to IDA. This plugin adds 
new user interface elements including an interactive tree view of rule matches and their locations
within the current database. You can use FLARE capa plugin to dissect capa rules at the assembly level or quickly jump to interesting parts of a program, 
such as where the C2 mechanism might be.

FLARE capa plugin consists of two components:

* A [feature extractor](https://github.com/fireeye/capa/tree/master/capa/features/extractors/ida) built on top of IDA's powerful binary analysis engine
* An [interactive plugin](https://github.com/fireeye/capa/tree/master/capa/ida/plugin) for displaying and exploring capa rules matched against an IDA database

![](../../../doc/img/ida_plugin_intro.gif)

# requirements

* IDA Pro 7.4+ with Python 2.7 or Python 3.x

# supported file types

* Windows `32-bit` and `64-bit` PE files
* Windows `32-bit` and `64-bit` shellcode

# installation

## quick install
1. Install capa for the Python interpreter used by your IDA installation:

    ```
    $ pip install flare-capa
    ```
   
3. Copy [capa_plugin_ida.py](https://raw.githubusercontent.com/fireeye/capa/master/capa/ida/plugin/capa_plugin_ida.py) to your IDA  plugins directory

## development
1. Install capa for the Python interpreter used by your IDA installation using method 3 of the instructions found [here](https://github.com/fireeye/capa/blob/master/doc/installation.md#method-3-inspecting-the-capa-source-code)
2. Copy [capa_plugin_ida.py](https://raw.githubusercontent.com/fireeye/capa/master/capa/ida/plugin/capa_plugin_ida.py) to your IDA plugins directory

If you encounter issues with your specific setup, please open a new [Issue](https://github.com/fireeye/capa/issues).

# usage
1. Run IDA and analyze a supported file type (select `Manual Load` and `Load Resources` for best results)
2. Open FLARE capa plugin in IDA by navigating to `Edit > Plugins > FLARE capa plugin` or using the keyboard shortcut `Alt+F5`
3. Click `Analyze`

When running the plugin for the first time you are prompted to select a file directory containing capa rules. The plugin conviently
remembers your selection for future runs; you can change this selection by navigating to `Rules > Change rules directory...`. We recommend 
downloading and using the [standard collection of capa rules](https://github.com/fireeye/capa-rules) when first getting familiar with the plugin but any
file directory containing [valid capa rules](https://github.com/fireeye/capa-rules/blob/master/doc/format.md) can be used.

# features
* Display capa results in an interactive tree view of rule matches and their locations in the current database
* Export results as formatted JSON by navigating to `File > Export results...`
* Remember a user's `capa` rules directory for future runs; change `capa` rules directory by navigating to `Rules > Change rules directory...`
* Search for keywords or phrases found in the `Rule Information`, `Address`, or `Details` columns
* Display rule source content when a user hovers their cursor over a rule match
* Double-click `Address` column to view associated feature in the IDA Disassembly view
* Limit tree view results to the function currently displayed in the IDA Disassembly view; update results as a user navigates to different functions
* Reset tree view and IDA Disassembly view highlighting by clicking `Reset`
* Automatically re-analyze database when user performs a program rebase
* Automatically update results when IDA is used to rename a function
* Select one or more checkboxes to highlight the associated addresses in the IDA Disassembly view
* Right-click a function match to rename it; the new function name is propagated to the current IDA database
* Right-click to copy a result by column or by row
