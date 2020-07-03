# capa

capa detects capabilities in executable files.
You run it against a .exe or .dll and it tells you what it thinks the program can do.
For example, it might suggest that the file is a backdoor, is capable of installing services, or relies on HTTP to communicate.

```
$ capa.exe suspicious.exe

+------------------------+----------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                     |
|------------------------+----------------------------------------------------------------------|
| DEFENSE EVASION        | Obfuscated Files or Information [T1027]                              |
| DISCOVERY              | Query Registry [T1012]                                               |
|                        | System Information Discovery [T1082]                                 |
| EXECUTION              | Command and Scripting Interpreter::Windows Command Shell [T1059.003] |
|                        | Shared Modules [T1129]                                               |
| EXFILTRATION           | Exfiltration Over C2 Channel [T1041]                                 |
| PERSISTENCE            | Create or Modify System Process::Windows Service [T1543.003]         |
+------------------------+----------------------------------------------------------------------+

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

# download

Download stable releases of the standalone capa binaries [here](/releases). You can run the standalone binaries without installation. See [doc/installation.md](doc/installation.md) for details on using capa as a library in another project.

Alternatively, you can fetch a nightly build of a standalone binary from one of the following links. These are built using the latest development branch.
- Windows 64bit: TODO
- Linux: TODO
- OSX: TODO


# installation

See [doc/installation.md](doc/installation.md) for information on how to setup the project, including how to use it as a Python library.

For more information about how to use capa, including running it as an IDA script/plugin see [doc/usage.md](doc/usage.md).

# example

In the above sample output, we ran capa against an unknown binary (`suspicious.exe`),
and the tool reported that the program can decode data via XOR,
contains an embedded PE, writes to a file, and spawns a new process.
Taken together, this makes us think that `suspicious.exe` could be a dropper or backdoor.
Therefore, our next analysis step might be to run `suspicious.exe` in a sandbox and try to recover the payload.

By passing the `-vv` flag (for Very Verbose), capa reports exactly where it found evidence of these capabilities.
This is useful for at least two reasons:

  - it helps explain why we should trust the results, and enables us to verify the conclusions, and
  - it shows where within the binary an experienced analyst might study with IDA Pro

```
λ capa.exe suspicious.exe -vv
execute shell command and capture output
namespace   c2/shell
author      matthew.williams@fireeye.com
scope       function
att&ck      Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]
references  https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
examples    Practical Malware Analysis Lab 14-02.exe_:0x4011C0
function @ 0x10003A13
  and:
    match: create a process with modified I/O handles and window @ 0x10003A13
      and:
        or:
          api: kernel32.CreateProcess @ 0x10003D6D
        number: 0x101 @ 0x10003B03
        or:
          number: 0x44 @ 0x10003ADC
        optional:
          api: kernel32.GetStartupInfo @ 0x10003AE4
    match: create pipe @ 0x10003A13
      or:
        api: kernel32.CreatePipe @ 0x10003ACB
    or:
      string: cmd.exe /c  @ 0x10003AED
...
```



# limitations

To learn more about capa's current limitations see [here](doc/limitations.md).
