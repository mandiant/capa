## Rules

Capa utilizes a collection of rules to identify capabilities within a program. 
The [github.com/mandiant/capa-rules](https://github.com/mandiant/capa-rules) repository contains hundreds of standard library rules that are distributed with Capa.

When you download a standalone version of Capa, this standard library is embedded within the executable, and Capa will use these rules by default:

```console
$ capa suspicious.exe
```

However, you may want to modify the rules for a variety of reasons:
   
   - detect new behaviors
   - tweak existing rules to reduce false-positives
   - collect a private selection of rules not shared publicly.

Alternatively, you may want to use Capa as a Python library within another application.

In these scenarios, you must provide the rule set to Capa as a directory on your file system. Do this using the `-r`/`--rules` parameter:

```console
$ capa --rules /local/path/to/rules suspicious.exe
```

You can download the standard set of rules as ZIP or tar.gz archives from the [capa-rules release page](https://github.com/mandiant/capa-rules/releases).

Note that you must match the rules' major version with the Capa major version, i.e., use `v1` rules with `v1` of Capa.
This is so that new versions of Capa can update rule syntax, such as by adding new fields and logic.

Otherwise, using rules with a mismatched version of Capa may lead to errors, such as:

```console
$ capa --rules /path/to/mismatched/rules suspicious.exe
ERROR:lint:invalid rule: injection.yml: invalid rule: unexpected statement: instruction
```
You can check the version of Capa you're currently using like this:

````console
$ capa --version
capa 3.0.3
````
