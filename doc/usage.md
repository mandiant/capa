# capa usage

See `capa -h` for all supported arguments and usage examples.

## tips and tricks

### only run selected rules
Use the `-t` option to run rules with the given metadata value (see the rule fields `rule.meta.*`).
For example, `capa -t william.ballenthin@mandiant.com` runs rules that reference Willi's email address (probably as the author), or
`capa -t communication` runs rules with the namespace `communication`.

### only analyze selected functions
Use the `--restrict-to-functions` option to extract capabilities from only a selected set of functions. This is useful for analyzing 
large functions and figuring out their capabilities and their address of occurance; for example: PEB access, RC4 encryption, etc.

To use this, you can copy the virtual addresses from your favorite disassembler and pass them to capa as follows:
`capa sample.exe --restrict-to-functions 0x4019C0,0x401CD0`. If you add the `-v` option then capa will extract the interesting parts of a function for you.

### only analyze selected processes
Use the `--restrict-to-processes` option to extract capabilities from only a selected set of processes. This is useful for filtering the noise 
generated from analyzing non-malicious processes that can be reported by some sandboxes, as well as reduce the execution time 
by not analyzing such processes in the first place.

To use this, you can pick the PIDs of the processes you are interested in from the sandbox-generated process tree (or from the sandbox-reported malware PID) 
and pass that to capa as follows: `capa report.log --restrict-to-processes 3888,3214,4299`. If you add the `-v` option then capa will tell you 
which threads perform what actions (encrypt/decrypt data, initiate a connection, etc.).

### IDA Pro plugin: capa explorer
Please check out the [capa explorer documentation](/capa/ida/plugin/README.md).

### save time by reusing .viv files
Set the environment variable `CAPA_SAVE_WORKSPACE` to instruct the underlying analysis engine to 
cache its intermediate results to the file system. For example, vivisect will create `.viv` files.
Subsequently, capa may run faster when reprocessing the same input file.
This is particularly useful during rule development as you repeatedly test a rule against a known sample.
