![capa](https://github.com/mandiant/capa/blob/master/.github/logo.png)

[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/flare-capa)](https://pypi.org/project/flare-capa)
[![Last release](https://img.shields.io/github/v/release/mandiant/capa)](https://github.com/mandiant/capa/releases)
[![Number of rules](https://img.shields.io/badge/rules-794-blue.svg)](https://github.com/mandiant/capa-rules)
[![CI status](https://github.com/mandiant/capa/workflows/CI/badge.svg)](https://github.com/mandiant/capa/actions?query=workflow%3ACI+event%3Apush+branch%3Amaster)
[![Downloads](https://img.shields.io/github/downloads/mandiant/capa/total)](https://github.com/mandiant/capa/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

capa detects capabilities in executable files.
You run it against a PE, ELF, .NET module, or shellcode file and it tells you what it thinks the program can do.
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.

Check out:
- the overview in our first [capa blog post](https://www.mandiant.com/resources/capa-automatically-identify-malware-capabilities)
- the major version 2.0 updates described in our [second blog post](https://www.mandiant.com/resources/capa-2-better-stronger-faster)
- the major version 3.0 (ELF support) described in the [third blog post](https://www.mandiant.com/resources/elfant-in-the-room-capa-v3)
- the major version 4.0 (.NET support) described in the [fourth blog post](https://www.mandiant.com/resources/blog/capa-v4-casting-wider-net)

```
$ capa.exe suspicious.exe

+------------------------+--------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                               |
|------------------------+--------------------------------------------------------------------------------|
| DEFENSE EVASION        | Obfuscated Files or Information [T1027]                                        |
| DISCOVERY              | Query Registry [T1012]                                                         |
|                        | System Information Discovery [T1082]                                           |
| EXECUTION              | Command and Scripting Interpreter::Windows Command Shell [T1059.003]           |
|                        | Shared Modules [T1129]                                                         |
| EXFILTRATION           | Exfiltration Over C2 Channel [T1041]                                           |
| PERSISTENCE            | Create or Modify System Process::Windows Service [T1543.003]                   |
+------------------------+--------------------------------------------------------------------------------+

+-------------------------------------------------------+-------------------------------------------------+
| CAPABILITY                                            | NAMESPACE                                       |
|-------------------------------------------------------+-------------------------------------------------|
| check for OutputDebugString error                     | anti-analysis/anti-debugging/debugger-detection |
| read and send data from client to server              | c2/file-transfer                                |
| execute shell command and capture output              | c2/shell                                        |
| receive data (2 matches)                              | communication                                   |
| send data (6 matches)                                 | communication                                   |
| connect to HTTP server (3 matches)                    | communication/http/client                       |
| send HTTP request (3 matches)                         | communication/http/client                       |
| create pipe                                           | communication/named-pipe/create                 |
| get socket status (2 matches)                         | communication/socket                            |
| receive data on socket (2 matches)                    | communication/socket/receive                    |
| send data on socket (3 matches)                       | communication/socket/send                       |
| connect TCP socket                                    | communication/socket/tcp                        |
| encode data using Base64                              | data-manipulation/encoding/base64               |
| encode data using XOR (6 matches)                     | data-manipulation/encoding/xor                  |
| run as a service                                      | executable/pe                                   |
| get common file path (3 matches)                      | host-interaction/file-system                    |
| read file                                             | host-interaction/file-system/read               |
| write file (2 matches)                                | host-interaction/file-system/write              |
| print debug messages (2 matches)                      | host-interaction/log/debug/write-event          |
| resolve DNS                                           | host-interaction/network/dns/resolve            |
| get hostname                                          | host-interaction/os/hostname                    |
| create a process with modified I/O handles and window | host-interaction/process/create                 |
| create process                                        | host-interaction/process/create                 |
| create registry key                                   | host-interaction/registry/create                |
| create service                                        | host-interaction/service/create                 |
| create thread                                         | host-interaction/thread/create                  |
| persist via Windows service                           | persistence/service                             |
+-------------------------------------------------------+-------------------------------------------------+
```

# download and usage

Download stable releases of the standalone capa binaries [here](https://github.com/mandiant/capa/releases). You can run the standalone binaries without installation. capa is a command line tool that should be run from the terminal.

To use capa as a library or integrate with another tool, see [doc/installation.md](https://github.com/mandiant/capa/blob/master/doc/installation.md) for further setup instructions.

For more information about how to use capa, see [doc/usage.md](https://github.com/mandiant/capa/blob/master/doc/usage.md).

# example

In the above sample output, we ran capa against an unknown binary (`suspicious.exe`),
and the tool reported that the program can send HTTP requests, decode data via XOR and Base64,
install services, and spawn new processes.
Taken together, this makes us think that `suspicious.exe` could be a persistent backdoor.
Therefore, our next analysis step might be to run `suspicious.exe` in a sandbox and try to recover the command and control server.

By passing the `-vv` flag (for very verbose), capa reports exactly where it found evidence of these capabilities.
This is useful for at least two reasons:

  - it helps explain why we should trust the results, and enables us to verify the conclusions, and
  - it shows where within the binary an experienced analyst might study with IDA Pro

```
$ capa.exe suspicious.exe -vv
...
execute shell command and capture output
namespace   c2/shell
author      matthew.williams@mandiant.com
scope       function
att&ck      Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]
references  https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
function @ 0x4011C0
  and:
    match: create a process with modified I/O handles and window @ 0x4011C0
      and:
        number: 257 = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW @ 0x4012B8
        or:
          number: 68 = StartupInfo.cb (size) @ 0x401282
        or: = API functions that accept a pointer to a STARTUPINFO structure
          api: kernel32.CreateProcess @ 0x401343
    match: create pipe @ 0x4011C0
      or:
        api: kernel32.CreatePipe @ 0x40126F, 0x401280
    optional:
      match: create thread @ 0x40136A, 0x4013BA
        or:
          and:
            os: windows
            or:
              api: kernel32.CreateThread @ 0x4013D7
        or:
          and:
            os: windows
            or:
              api: kernel32.CreateThread @ 0x401395
    or:
      string: "cmd.exe" @ 0x4012FD
...
```

capa uses a collection of rules to identify capabilities within a program.
These rules are easy to write, even for those new to reverse engineering.
By authoring rules, you can extend the capabilities that capa recognizes.
In some regards, capa rules are a mixture of the OpenIOC, Yara, and YAML formats.

Here's an example rule used by capa:

```yaml
rule:
  meta:
    name: hash data with CRC32
    namespace: data-manipulation/checksum/crc32
    authors:
      - moritz.raabe@mandiant.com
    scope: function
    mbc:
      - Data::Checksum::CRC32 [C0032.001]
    examples:
      - 2D3EDC218A90F03089CC01715A9F047F:0x403CBD
      - 7D28CB106CB54876B2A5C111724A07CD:0x402350  # RtlComputeCrc32
      - 7EFF498DE13CC734262F87E6B3EF38AB:0x100084A6
  features:
    - or:
      - and:
        - mnemonic: shr
        - or:
          - number: 0xEDB88320
          - bytes: 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E = crc32_tab
        - number: 8
        - characteristic: nzxor
      - and:
        - number: 0x8320
        - number: 0xEDB8
        - characteristic: nzxor
      - api: RtlComputeCrc32
```

The [github.com/mandiant/capa-rules](https://github.com/mandiant/capa-rules) repository contains hundreds of standard library rules that are distributed with capa.
Please learn to write rules and contribute new entries as you find interesting techniques in malware.

If you use IDA Pro, then you can use the [capa explorer](https://github.com/mandiant/capa/tree/master/capa/ida/plugin) plugin.
capa explorer helps you identify interesting areas of a program and build new capa rules using features extracted directly from your IDA Pro database.

![capa + IDA Pro integration](https://github.com/mandiant/capa/blob/master/doc/img/explorer_expanded.png)

# further information
## capa
- [Installation](https://github.com/mandiant/capa/blob/master/doc/installation.md)
- [Usage](https://github.com/mandiant/capa/blob/master/doc/usage.md)
- [Limitations](https://github.com/mandiant/capa/blob/master/doc/limitations.md)
- [Contributing Guide](https://github.com/mandiant/capa/blob/master/.github/CONTRIBUTING.md)

## capa rules
- [capa-rules repository](https://github.com/mandiant/capa-rules)
- [capa-rules rule format](https://github.com/mandiant/capa-rules/blob/master/doc/format.md)

## capa testfiles
The [capa-testfiles repository](https://github.com/mandiant/capa-testfiles) contains the data we use to test capa's code and rules
