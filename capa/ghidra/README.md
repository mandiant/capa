<div align="center">
    <img src="/doc/img/ghidra_backend_logo.png" width=300 height=200>
</div>

The Ghidra Backend is an application of the FLARE team's open-source project, Ghidrathon, to integrate capa with Ghidra. capa is a framework that is able to extract features from binaries and use that data to match against a curated collection of well-defined rules to identify capabilities in a program. You can use capa to run against PE files, ELF files, or shellcode and it tells you what it thinks the program can do. For example, it might suggest that the program is a backdoor, can install services, or relies on HTTP to communicate. The Ghidra Backend will will run capa analysis on the databases present in your Ghidra projects (.gpr) without needing access to the original binary file. Once a project has been analyzed, the Ghidra Backend helps you identify interesting areas of a program and build new capa rules using features extracted from your Ghidra projects.

