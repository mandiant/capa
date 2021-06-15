# capa usage

See `capa -h` for all supported arguments and usage examples.

## tips and tricks

### only run selected rules
Use the `-t` option to run rules with the given metadata value (see the rule fields `rule.meta.*`).
For example, `capa -t william.ballenthin@mandiant.com` runs rules that reference Willi's email address (probably as the author), or
`capa -t communication` runs rules with the namespace `communication`.

### IDA Pro plugin: capa explorer
Please check out the [capa explorer documentation](/capa/ida/plugin/README.md).

### save time by reusing .viv files
Set the environment variable `CAPA_SAVE_WORKSPACE` to instruct the underlying analysis engine to 
cache its intermediate results to the file system. For example, vivisect will create `.viv` files.
Subsequently, capa may run faster when reprocessing the same input file.
This is particularly useful during rule development as you repeatedly test a rule against a known sample.