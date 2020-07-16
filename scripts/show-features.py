#!/usr/bin/env python2
"""
show-features

Show the features that capa extracts from the given sample,
to assist with the development of rules.

If you have a function with a capability that you'd like to detect,
you can run this tool and grep for the function/basic block/instruction addresses
to see what capa picks up.
This way, you can verify that capa successfully notices the features you'd reference.

Example::

    $ python scripts/show-features.py /tmp/suspicious.dll_
    ...
    file: 0x10004e4d: export(__entry)
    file: 0x10004706: export(Install)
    file: 0x10004c2b: export(uninstallA)
    file: 0x10005034: import(kernel32.GetStartupInfoA)
    file: 0x10005034: import(GetStartupInfoA)
    file: 0x10005048: import(kernel32.SetLastError)
    file: 0x00004e10: string(Y29ubmVjdA==)
    file: 0x00004e28: string(practicalmalwareanalysis.com)
    file: 0x00004e68: string(serve.html)
    file: 0x00004eb8: string(dW5zdXBwb3J0)
    file: 0x00004ec8: string(c2xlZXA=)
    func: 0x100012c2: characteristic(calls to)
    func: 0x10001000: characteristic(loop)
    bb  : 0x10001000: basic block
    insn: 0x10001000: mnemonic(push)
    insn: 0x10001001: mnemonic(push)
    insn: 0x10001002: mnemonic(push)
    insn: 0x10001003: mnemonic(push)
    insn: 0x10001004: mnemonic(push)
    insn: 0x10001005: mnemonic(push)
    insn: 0x10001006: mnemonic(xor)
    insn: 0x10001008: number(0x1)
    insn: 0x10001008: mnemonic(mov)
    bb  : 0x1000100a: basic block
    bb  : 0x1000100a: characteristic(tight loop)
    insn: 0x1000100a: mnemonic(movzx)
    insn: 0x1000100d: mnemonic(mov)
    insn: 0x1000100f: offset(0x1000A7C8)
    insn: 0x1000100f: mnemonic(mov)
    insn: 0x10001015: offset(0x100075C8)
    insn: 0x10001015: mnemonic(mov)
    insn: 0x1000101b: mnemonic(mov)
    insn: 0x1000101d: number(0x80)
    insn: 0x1000101d: mnemonic(and)
    insn: 0x10001020: mnemonic(neg)
    insn: 0x10001022: mnemonic(sbb)
    insn: 0x10001024: number(0x1B)
    insn: 0x10001024: mnemonic(and)
    insn: 0x10001027: number(0x1)
    insn: 0x10001027: mnemonic(shl)
    ...

Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""
import sys
import logging
import argparse

import capa.main
import capa.rules
import capa.engine
import capa.features
import capa.features.freeze
import capa.features.extractors.viv


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    formats = [
        ("auto", "(default) detect file type automatically"),
        ("pe", "Windows PE file"),
        ("sc32", "32-bit shellcode"),
        ("sc64", "64-bit shellcode"),
        ("freeze", "features previously frozen by capa"),
    ]
    format_help = ", ".join(["%s: %s" % (f[0], f[1]) for f in formats])

    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    parser.add_argument("sample", type=str, help="Path to sample to analyze")
    parser.add_argument(
        "-f", "--format", choices=[f[0] for f in formats], default="auto", help="Select sample format, %s" % format_help
    )
    parser.add_argument("-F", "--function", type=lambda x: int(x, 0), help="Show features for specific function")
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    if args.format == "freeze":
        with open(args.sample, "rb") as f:
            extractor = capa.features.freeze.load(f.read())
    else:
        vw = capa.main.get_workspace(args.sample, args.format)
        extractor = capa.features.extractors.viv.VivisectFeatureExtractor(vw, args.sample)

    if not args.function:
        for feature, va in extractor.extract_file_features():
            if va:
                print("file: 0x%08x: %s" % (va, feature))
            else:
                print("file: 0x00000000: %s" % (feature))

    functions = extractor.get_functions()

    if args.function:
        if args.format == "freeze":
            functions = filter(lambda f: f == args.function, functions)
        else:
            functions = filter(lambda f: f.va == args.function, functions)

    for f in functions:
        for feature, va in extractor.extract_function_features(f):
            print("func: 0x%08x: %s" % (va, feature))

        for bb in extractor.get_basic_blocks(f):
            for feature, va in extractor.extract_basic_block_features(f, bb):
                print("bb  : 0x%08x: %s" % (va, feature))

            for insn in extractor.get_instructions(f, bb):
                for feature, va in extractor.extract_insn_features(f, bb, insn):
                    print("insn: 0x%08x: %s" % (va, feature))

    return 0


if __name__ == "__main__":
    sys.exit(main())
