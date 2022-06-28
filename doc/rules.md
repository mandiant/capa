### rules


capa uses a collection of rules to identify capabilities within a program.
The [github.com/mandiant/capa-rules](https://github.com/mandiant/capa-rules) repository contains hundreds of standard library rules that are distributed with capa.

When you download a standalone version of capa, this standard library is embedded within the executable and capa will use these rules by default:

```console
$ capa suspicious.exe
```

However, you may want to modify the rules for a variety of reasons:

  - develop new rules to find behaviors, and/or
  - tweak existing rules to reduce false positives, and/or
  - collect a private selection of rules not shared publicly.

Or, you may want to use capa as a Python library within another application.

In these scenarios, you must provide the rule set to capa as a directory on your file system. Do this using the `-r`/`--rules` parameter:

```console
$ capa    --rules /local/path/to/rules    suspicious.exe
```

You can collect the standard set of rules in two ways:

  - [download from the Github releases page](#download-release-archive), or
  - [clone from Github](#clone-with-git).

Note that you must use match the rules major version with the capa major version,
i.e., use `v1` rules with `v1` of capa.
This is so that new versions of capa can update rule syntax, such as by adding new fields and logic.

Otherwise, using rules with a mismatched version of capa may lead to errors like:

```
$ capa   --rules /path/to/mismatched/rules    suspicious.exe
ERROR:lint:invalid rule: injection.yml: invalid rule: unexpected statement: instruction
```                

You can check the version of capa you're currently using like this:
                         
```console
$ capa --version
capa 3.0.3
```

#### download release archive

The releases page is [here](https://github.com/mandiant/capa-rules/tags/).
Find the most recent release corresponding to your major version of capa and download the ZIP archive.
Here are some quick links:
  - v1: [v1](https://github.com/mandiant/capa-rules/releases/tag/v1)
  - v2: [v2](https://github.com/mandiant/capa-rules/releases/tag/v2)
  - v3: [v3](https://github.com/mandiant/capa-rules/releases/tag/v3)

#### clone with git

To fetch with git, clone the appropriate branch like this:

```console
$ git clone https://github.com/mandiant/capa-rules.git -b v3 /local/path/to/rules
```

Note that the branch name (`v3` in the example above) must match the major version of capa you're using.

  - [v1](https://github.com/mandiant/capa-rules/tree/v1): `v1`
  - [v2](https://github.com/mandiant/capa-rules/tree/v2): `v2`
  - [v3](https://github.com/mandiant/capa-rules/tree/v3): `v3`

