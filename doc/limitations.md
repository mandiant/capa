# Packers
Packed programs have often been obfuscated to hide their logic. Since capa cannot handle obfuscation well, results may be misleading or incomplete. If possible, users should unpack input files before analyzing them with capa.

If capa detects that a program may be packed using its rules it warns the user.


# Installers, run-time programs, etc.
capa cannot handle installers, run-time programs like .NET applications, or other packaged applications like AutoIt well. This means that the results may be misleading or incomplete.

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
capa uses a custom category tagging that assigns capabilities with objective, behavior, and technique (see https://github.com/fireeye/capa#meta-block).

The category tagging is loosely based on the ELWUN/Nucleus capability tags.

While exploring other tagging mechanisms we discovered the following shortcomings:

- ATT&CK: does not cover all the capabilities we are trying to express and is intended for a different purpose (general adversary tactics and techniques)
- MAEC: the ELWUN tags are related to the MAEC format, but express capabilities more appropriately for us
- MBC: this is the right scope, but a rather new project, if there's more support and demand in the community for this schema further work in this direction could be promising

Adding tags from a new schema to the existing rules is a cumbersome process. We will hold on to amending rules until we have identified an appropriate schema.

Additionally, if we choose to support a public standard, we would like to provide expertise back to the community.
