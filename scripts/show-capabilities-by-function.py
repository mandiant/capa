#!/usr/bin/env python2
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
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

Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
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
from typing import Dict
from pathlib import Path

import colorama

import capa.main
import capa.rules
import capa.engine
import capa.helpers
import capa.features
import capa.exceptions
import capa.render.utils as rutils
import capa.render.verbose
import capa.features.freeze
import capa.render.result_document as rd
from capa.helpers import get_file_taste
from capa.features.common import FORMAT_AUTO
from capa.features.freeze import Address

logger = logging.getLogger("capa.show-capabilities-by-function")


def render_matches_by_function(doc: rd.ResultDocument):
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
    functions_by_bb: Dict[Address, Address] = {}
    for finfo in doc.meta.analysis.layout.functions:
        faddress = finfo.address

        for bb in finfo.matched_basic_blocks:
            bbaddress = bb.address
            functions_by_bb[bbaddress] = faddress

    ostream = rutils.StringIO()

    matches_by_function = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if rule.meta.scope == capa.rules.FUNCTION_SCOPE:
            for addr, _ in rule.matches:
                matches_by_function[addr].add(rule.meta.name)
        elif rule.meta.scope == capa.rules.BASIC_BLOCK_SCOPE:
            for addr, _ in rule.matches:
                function = functions_by_bb[addr]
                matches_by_function[function].add(rule.meta.name)
        else:
            # file scope
            pass

    for f in doc.meta.analysis.feature_counts.functions:
        if not matches_by_function.get(f.address, {}):
            continue
        ostream.writeln(f"function at {capa.render.verbose.format_address(addr)} with {f.count} features: ")
        for rule_name in sorted(matches_by_function[f.address]):
            ostream.writeln("  - " + rule_name)

    return ostream.getvalue()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    capa.main.install_common_args(parser, wanted={"format", "os", "backend", "sample", "signatures", "rules", "tag"})
    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    try:
        taste = get_file_taste(Path(args.sample))
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    try:
        rules = capa.main.get_rules(args.rules)
        logger.info("successfully loaded %s rules", len(rules))
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.info("selected %s rules", len(rules))
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    try:
        sig_paths = capa.main.get_signatures(args.signatures)
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    if (args.format == "freeze") or (args.format == FORMAT_AUTO and capa.features.freeze.is_freeze(taste)):
        format_ = "freeze"
        extractor = capa.features.freeze.load(Path(args.sample).read_bytes())
    else:
        format_ = args.format
        should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)

        try:
            extractor = capa.main.get_extractor(
                args.sample, args.format, args.os, args.backend, sig_paths, should_save_workspace
            )
        except capa.exceptions.UnsupportedFormatError:
            capa.helpers.log_unsupported_format_error()
            return -1
        except capa.exceptions.UnsupportedRuntimeError:
            capa.helpers.log_unsupported_runtime_error()
            return -1

    meta = capa.main.collect_metadata(argv, args.sample, format_, args.os, args.rules, extractor)
    capabilities, counts = capa.main.find_capabilities(rules, extractor)

    meta.analysis.feature_counts = counts["feature_counts"]
    meta.analysis.library_functions = counts["library_functions"]
    meta.analysis.layout = capa.main.compute_layout(rules, extractor, capabilities)

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
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    print(render_matches_by_function(doc))
    colorama.deinit()

    return 0


if __name__ == "__main__":
    sys.exit(main())
