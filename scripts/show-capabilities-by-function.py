#!/usr/bin/env python2
"""
show-capabilities-by-function

Invoke capa to extract the capabilities of the given sample
and emit the results grouped by function.

This is useful to identify "complex functions" - that is,
functions that implement a lot of different types of logic.

Example::

    $ python scripts/show-capabilities-by-function.py /tmp/suspicious.dll_
    function at 0x1000321A with 33 features:
      - get hostname
      - initialize Winsock library
    function at 0x10003286 with 63 features:
      - create thread
      - terminate thread
    function at 0x10003415 with 116 features:
      - write file
      - send data
      - link function at runtime
      - create HTTP request
      - get common file path
      - send HTTP request
      - connect to HTTP server
    function at 0x10003797 with 81 features:
      - get socket status
      - send data
      - receive data
      - create TCP socket
      - send data on socket
      - receive data on socket
      - act as TCP client
      - resolve DNS
      - create UDP socket
      - initialize Winsock library
      - set socket configuration
      - connect TCP socket
    ...

Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import os
import sys
import logging
import argparse
import collections

import colorama

import capa.main
import capa.rules
import capa.engine
import capa.render
import capa.features
import capa.render.utils as rutils
import capa.features.freeze
import capa.features.extractors.viv
from capa.helpers import get_file_taste

logger = logging.getLogger("capa.show-capabilities-by-function")


def render_matches_by_function(doc):
    """
        like:

            function at 0x1000321a with 33 features:
              - get hostname
              - initialize Winsock library
            function at 0x10003286 with 63 features:
              - create thread
              - terminate thread
            function at 0x10003415 with 116 features:
              - write file
              - send data
              - link function at runtime
              - create HTTP request
              - get common file path
              - send HTTP request
              - connect to HTTP server
    """
    ostream = rutils.StringIO()

    matches_by_function = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        for va in rule["matches"].keys():
            matches_by_function[va].add(rule["meta"]["name"])

    for va, feature_count in sorted(doc["meta"]["analysis"]["feature_counts"]["functions"].items()):
        va = int(va)
        if not matches_by_function.get(va, {}):
            continue
        ostream.writeln("function at 0x%X with %d features: " % (va, feature_count))
        for rule_name in matches_by_function[va]:
            ostream.writeln("  - " + rule_name)

    ostream.write("\n")
    return ostream.getvalue()


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
            "-r",
            "--rules",
            type=str,
            default="(embedded rules)",
            help="Path to rule file or directory, use embedded rules by default",
        )
        parser.add_argument("-t", "--tag", type=str, help="Filter on rule meta field values")
        parser.add_argument("-d", "--debug", action="store_true", help="Enable debugging output on STDERR")
        parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output but errors")
        parser.add_argument(
            "-f",
            "--format",
            choices=[f[0] for f in formats],
            default="auto",
            help="Select sample format, %s" % format_help,
        )
        args = parser.parse_args(args=argv)

        if args.quiet:
            logging.basicConfig(level=logging.ERROR)
            logging.getLogger().setLevel(logging.ERROR)
        elif args.debug:
            logging.basicConfig(level=logging.DEBUG)
            logging.getLogger().setLevel(logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger().setLevel(logging.INFO)

        # disable vivisect-related logging, it's verbose and not relevant for capa users
        capa.main.set_vivisect_log_level(logging.CRITICAL)

        try:
            taste = get_file_taste(args.sample)
        except IOError as e:
            logger.error("%s", str(e))
            return -1

        # py2 doesn't know about cp65001, which is a variant of utf-8 on windows
        # tqdm bails when trying to render the progress bar in this setup.
        # because cp65001 is utf-8, we just map that codepage to the utf-8 codec.
        # see #380 and: https://stackoverflow.com/a/3259271/87207
        import codecs

        codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)

        if args.rules == "(embedded rules)":
            logger.info("-" * 80)
            logger.info(" Using default embedded rules.")
            logger.info(" To provide your own rules, use the form `capa.exe -r ./path/to/rules/  /path/to/mal.exe`.")
            logger.info(" You can see the current default rule set here:")
            logger.info("     https://github.com/fireeye/capa-rules")
            logger.info("-" * 80)

            logger.debug("detected running from source")
            args.rules = os.path.join(os.path.dirname(__file__), "..", "rules")
            logger.debug("default rule path (source method): %s", args.rules)
        else:
            logger.info("using rules path: %s", args.rules)

        try:
            rules = capa.main.get_rules(args.rules)
            rules = capa.rules.RuleSet(rules)
            logger.info("successfully loaded %s rules", len(rules))
            if args.tag:
                rules = rules.filter_rules_by_meta(args.tag)
                logger.info("selected %s rules", len(rules))
        except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
            logger.error("%s", str(e))
            return -1

        if (args.format == "freeze") or (args.format == "auto" and capa.features.freeze.is_freeze(taste)):
            format = "freeze"
            with open(args.sample, "rb") as f:
                extractor = capa.features.freeze.load(f.read())
        else:
            format = args.format
            try:
                extractor = capa.main.get_extractor(args.sample, args.format)
            except capa.main.UnsupportedFormatError:
                logger.error("-" * 80)
                logger.error(" Input file does not appear to be a PE file.")
                logger.error(" ")
                logger.error(
                    " capa currently only supports analyzing PE files (or shellcode, when using --format sc32|sc64)."
                )
                logger.error(
                    " If you don't know the input file type, you can try using the `file` utility to guess it."
                )
                logger.error("-" * 80)
                return -1
            except capa.main.UnsupportedRuntimeError:
                logger.error("-" * 80)
                logger.error(" Unsupported runtime or Python interpreter.")
                logger.error(" ")
                logger.error(" capa supports running under Python 2.7 using Vivisect for binary analysis.")
                logger.error(" It can also run within IDA Pro, using either Python 2.7 or 3.5+.")
                logger.error(" ")
                logger.error(
                    " If you're seeing this message on the command line, please ensure you're running Python 2.7."
                )
                logger.error("-" * 80)
                return -1

        meta = capa.main.collect_metadata(argv, args.sample, args.rules, format, extractor)
        capabilities, counts = capa.main.find_capabilities(rules, extractor)
        meta["analysis"].update(counts)

        if capa.main.has_file_limitation(rules, capabilities):
            # bail if capa encountered file limitation e.g. a packed binary
            # do show the output in verbose mode, though.
            if not (args.verbose or args.vverbose or args.json):
                return -1

        # colorama will detect:
        #  - when on Windows console, and fixup coloring, and
        #  - when not an interactive session, and disable coloring
        # renderers should use coloring and assume it will be stripped out if necessary.
        colorama.init()
        doc = capa.render.convert_capabilities_to_result_document(meta, rules, capabilities)
        print(render_matches_by_function(doc))
        colorama.deinit()

        logger.info("done.")

        return 0


if __name__ == "__main__":
    sys.exit(main())
