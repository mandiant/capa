![capa](https://github.com/mandiant/capa/blob/master/.github/logo.png)

[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/flare-capa)](https://pypi.org/project/flare-capa)
[![Last release](https://img.shields.io/github/v/release/mandiant/capa)](https://github.com/mandiant/capa/releases)
[![Number of rules](https://img.shields.io/badge/rules-866-blue.svg)](https://github.com/mandiant/capa-rules)
[![CI status](https://github.com/mandiant/capa/workflows/CI/badge.svg)](https://github.com/mandiant/capa/actions?query=workflow%3ACI+event%3Apush+branch%3Amaster)
[![Downloads](https://img.shields.io/github/downloads/mandiant/capa/total)](https://github.com/mandiant/capa/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

capa detects capabilities in executable files.
You run it against a PE, ELF, .NET module, shellcode file, or a sandbox report and it tells you what it thinks the program can do.
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

Additionally, capa also supports analyzing [CAPE](https://github.com/kevoreilly/CAPEv2) sandbox reports for dynamic capabilty extraction.
In order to use this, you first submit your sample to CAPE for analysis, and then run capa against the generated report (JSON).

Here's an example of running capa against a packed binary, and then running capa against the CAPE report of that binary:

```yaml
$ capa 05be49819139a3fdcdbddbdefd298398779521f3d68daa25275cc77508e42310.exe
WARNING:capa.capabilities.common:--------------------------------------------------------------------------------
WARNING:capa.capabilities.common: This sample appears to be packed.
WARNING:capa.capabilities.common: 
WARNING:capa.capabilities.common: Packed samples have often been obfuscated to hide their logic.
WARNING:capa.capabilities.common: capa cannot handle obfuscation well using static analysis. This means the results may be misleading or incomplete.
WARNING:capa.capabilities.common: If possible, you should try to unpack this input file before analyzing it with capa.
WARNING:capa.capabilities.common: Alternatively, run the sample in a supported sandbox and invoke capa against the report to obtain dynamic analysis results.
WARNING:capa.capabilities.common: 
WARNING:capa.capabilities.common: Identified via rule: (internal) packer file limitation
WARNING:capa.capabilities.common: 
WARNING:capa.capabilities.common: Use -v or -vv if you really want to see the capabilities identified by capa.
WARNING:capa.capabilities.common:--------------------------------------------------------------------------------

$ capa 05be49819139a3fdcdbddbdefd298398779521f3d68daa25275cc77508e42310.json

┍━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ ATT&CK Tactic          │ ATT&CK Technique                                                                   │
┝━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ CREDENTIAL ACCESS      │ Credentials from Password Stores T1555                                             │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ DEFENSE EVASION        │ File and Directory Permissions Modification T1222                                  │
│                        │ Modify Registry T1112                                                              │
│                        │ Obfuscated Files or Information T1027                                              │
│                        │ Virtualization/Sandbox Evasion::User Activity Based Checks T1497.002               │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ DISCOVERY              │ Account Discovery T1087                                                            │
│                        │ Application Window Discovery T1010                                                 │
│                        │ File and Directory Discovery T1083                                                 │
│                        │ Query Registry T1012                                                               │
│                        │ System Information Discovery T1082                                                 │
│                        │ System Location Discovery::System Language Discovery T1614.001                     │
│                        │ System Owner/User Discovery T1033                                                  │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ EXECUTION              │ System Services::Service Execution T1569.002                                       │
├────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ PERSISTENCE            │ Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder T1547.001    │
│                        │ Boot or Logon Autostart Execution::Winlogon Helper DLL T1547.004                   │
│                        │ Create or Modify System Process::Windows Service T1543.003                         │
┕━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙

┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑
│ Capability                                           │ Namespace                                            │
┝━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┥
│ check for unmoving mouse cursor (3 matches)          │ anti-analysis/anti-vm/vm-detection                   │
│ gather bitkinex information                          │ collection/file-managers                             │
│ gather classicftp information                        │ collection/file-managers                             │
│ gather filezilla information                         │ collection/file-managers                             │
│ gather total-commander information                   │ collection/file-managers                             │
│ gather ultrafxp information                          │ collection/file-managers                             │
│ resolve DNS (23 matches)                             │ communication/dns                                    │
│ initialize Winsock library (7 matches)               │ communication/socket                                 │
│ act as TCP client (3 matches)                        │ communication/tcp/client                             │
│ create new key via CryptAcquireContext               │ data-manipulation/encryption                         │
│ encrypt or decrypt via WinCrypt                      │ data-manipulation/encryption                         │
│ hash data via WinCrypt                               │ data-manipulation/hashing                            │
│ initialize hashing via WinCrypt                      │ data-manipulation/hashing                            │
│ hash data with MD5                                   │ data-manipulation/hashing/md5                        │
│ generate random numbers via WinAPI                   │ data-manipulation/prng                               │
│ extract resource via kernel32 functions (2 matches)  │ executable/resource                                  │
│ interact with driver via control codes (2 matches)   │ host-interaction/driver                              │
│ get Program Files directory (18 matches)             │ host-interaction/file-system                         │
│ get common file path (575 matches)                   │ host-interaction/file-system                         │
│ create directory (2 matches)                         │ host-interaction/file-system/create                  │
│ delete file                                          │ host-interaction/file-system/delete                  │
│ get file attributes (122 matches)                    │ host-interaction/file-system/meta                    │
│ set file attributes (8 matches)                      │ host-interaction/file-system/meta                    │
│ move file                                            │ host-interaction/file-system/move                    │
│ find taskbar (3 matches)                             │ host-interaction/gui/taskbar/find                    │
│ get keyboard layout (12 matches)                     │ host-interaction/hardware/keyboard                   │
│ get disk size                                        │ host-interaction/hardware/storage                    │
│ get hostname (4 matches)                             │ host-interaction/os/hostname                         │
│ allocate or change RWX memory (3 matches)            │ host-interaction/process/inject                      │
│ query or enumerate registry key (3 matches)          │ host-interaction/registry                            │
│ query or enumerate registry value (8 matches)        │ host-interaction/registry                            │
│ delete registry key                                  │ host-interaction/registry/delete                     │
│ start service                                        │ host-interaction/service/start                       │
│ get session user name                                │ host-interaction/session                             │
│ persist via Run registry key                         │ persistence/registry/run                             │
│ persist via Winlogon Helper DLL registry key         │ persistence/registry/winlogon-helper                 │
│ persist via Windows service (2 matches)              │ persistence/service                                  │
┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙
```

capa uses a collection of rules to identify capabilities within a program.
These rules are easy to write, even for those new to reverse engineering.
By authoring rules, you can extend the capabilities that capa recognizes.
In some regards, capa rules are a mixture of the OpenIOC, Yara, and YAML formats.

Here's an example rule used by capa:

```yaml
rule:
  meta:
    name: create TCP socket
    namespace: communication/socket/tcp
    authors:
      - william.ballenthin@mandiant.com
      - joakim@intezer.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Communication::Socket Communication::Create TCP Socket [C0001.011]
    examples:
      - Practical Malware Analysis Lab 01-01.dll_:0x10001010
  features:
    - or:
      - and:
        - number: 6 = IPPROTO_TCP
        - number: 1 = SOCK_STREAM
        - number: 2 = AF_INET
        - or:
          - api: ws2_32.socket
          - api: ws2_32.WSASocket
          - api: socket
      - property/read: System.Net.Sockets.TcpClient::Client
```

The [github.com/mandiant/capa-rules](https://github.com/mandiant/capa-rules) repository contains hundreds of standard library rules that are distributed with capa.
Please learn to write rules and contribute new entries as you find interesting techniques in malware.

If you use IDA Pro, then you can use the [capa explorer](https://github.com/mandiant/capa/tree/master/capa/ida/plugin) plugin.
capa explorer helps you identify interesting areas of a program and build new capa rules using features extracted directly from your IDA Pro database.

![capa + IDA Pro integration](https://github.com/mandiant/capa/blob/master/doc/img/explorer_expanded.png)

If you use Ghidra, you can use the Python 3 [Ghidra feature extractor](/capa/ghidra/). This integration enables capa to extract features directly from your Ghidra database, which can help you identify capabilities in programs that you analyze using Ghidra.

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
