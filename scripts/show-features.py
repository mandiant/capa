#!/usr/bin/env python2
'''
show the features extracted by capa.
'''
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
        ('auto', '(default) detect file type automatically'),
        ('pe', 'Windows PE file'),
        ('sc32', '32-bit shellcode'),
        ('sc64', '64-bit shellcode'),
        ('freeze', 'features previously frozen by capa'),
    ]
    format_help = ', '.join(['%s: %s' % (f[0], f[1]) for f in formats])

    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    parser.add_argument("sample", type=str,
                        help="Path to sample to analyze")
    parser.add_argument("-f", "--format", choices=[f[0] for f in formats], default="auto",
                        help="Select sample format, %s" % format_help)
    parser.add_argument("-F", "--function", type=lambda x: int(x, 0),
                        help="Show features for specific function")
    args = parser.parse_args(args=argv)

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    if args.format == 'freeze':
        with open(args.sample, 'rb') as f:
            extractor = capa.features.freeze.load(f.read())
    else:
        vw = capa.main.get_workspace(args.sample, args.format)
        extractor = capa.features.extractors.viv.VivisectFeatureExtractor(vw, args.sample)

    if not args.function:
        for feature, va in extractor.extract_file_features():
            if va:
                print('file: 0x%08x: %s' % (va, feature))
            else:
                print('file: 0x00000000: %s' % (feature))

    functions = extractor.get_functions()

    if args.function:
        if args.format == 'freeze':
            functions = filter(lambda f: f == args.function, functions)
        else:
            functions = filter(lambda f: f.va == args.function, functions)

    for f in functions:
        for feature, va in extractor.extract_function_features(f):
            print('func: 0x%08x: %s' % (va, feature))

        for bb in extractor.get_basic_blocks(f):
            for feature, va in extractor.extract_basic_block_features(f, bb):
                print('bb  : 0x%08x: %s' % (va, feature))

            for insn in extractor.get_instructions(f, bb):
                for feature, va in extractor.extract_insn_features(f, bb, insn):
                    print('insn: 0x%08x: %s' % (va, feature))

    return 0


if __name__ == "__main__":
    sys.exit(main())
