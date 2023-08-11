# Packers
Packed programs have often been obfuscated to hide their logic. Since capa cannot handle obfuscation well, results may be misleading or incomplete. If possible, users should unpack input files before analyzing them with capa.

If capa detects that a program may be packed using its rules it warns the user.


# Installers, run-time programs, etc.
capa cannot handle installers, run-time programs, or other packaged applications like AutoIt well. This means that the results may be misleading or incomplete.

If capa detects an installer, run-time program, etc. it warns the user.


# Wrapper functions and matches in child functions
Currently capa does not handle wrapper functions or other matches in child functions.

Consider this example call tree where `f1` calls a wrapper function `f2` and the `CreateProcess` API. `f2` writes to a file.

```
f1
  f2 (WriteFile wrapper)
    CreateFile
    WriteFile
  CreateProcess
```

Here capa does not match a rule that hits on file creation and execution on function `f1`.  

Software often contains such nested calls because programmers wrap API calls in helper functions or because specific compilers or languages, such as Go, layer calls.

While a feature to capture nested functionality is desirable it introduces various issues and complications. These include:

- how to assign matches from child to parent functions?
- a potential significant increase in analysis requirements and rule matching complexity  

Moreover, we require more real-world samples to see how prevalent this really is and how much it would improve capa's results. 


# Loop scope
Encryption, encoding, or processing functions often contain loops and it could be beneficial to capture functionality within loops.

However, tracking all basic blocks part of a loop especially with nested loop constructs is not trivial.

As a compromise, capa provides the `characteristic(loop)` feature to filter on functions that contain a loop.

We need more practical use cases and test samples to justify the additional workload to implement a full loop scope feature.


# ATT&CK, MAEC, MBC, and other capability tagging
capa uses namespaces to group capabilities (see https://github.com/mandiant/capa-rules/tree/master#namespace-organization).

The `rule.meta` field also supports `att&ck`, `mbc`, and `maec` fields to associate rules with the respective taxonomy (see https://github.com/mandiant/capa-rules/blob/master/doc/format.md#meta-block).
