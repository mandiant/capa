# capa usage

See `capa -h` for all supported arguments and usage examples.

## tips and tricks

  - [match only rules by given author or namespace](#only-run-selected-rules)
  - [IDA Pro capa explorer](#capa-explorer)
  - [IDA Pro rule generator](#rule-generator)

### only run selected rules
Use the `-t` option to run rules with the given metadata value (see the rule fields `rule.meta.*`).
For example, `capa -t william.ballenthin@mandiant.com` runs rules that reference Willi's email address (probably as the author), or
`capa -t communication` runs rules with the namespace `communication`.
