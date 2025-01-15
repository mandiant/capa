#!/usr/bin/env python2
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
"""
import sys
import logging
import argparse
import collections

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
import capa.capabilities.common
import capa.render.result_document as rd
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
    assert isinstance(doc.meta.analysis, rd.StaticAnalysis)
    functions_by_bb: dict[Address, Address] = {}
    for finfo in doc.meta.analysis.layout.functions:
        faddress = finfo.address

        for bb in finfo.matched_basic_blocks:
            bbaddress = bb.address
            functions_by_bb[bbaddress] = faddress

    ostream = rutils.StringIO()

    matches_by_function = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if capa.rules.Scope.FUNCTION in rule.meta.scopes:
            for addr, _ in rule.matches:
                matches_by_function[addr].add(rule.meta.name)
        elif capa.rules.Scope.BASIC_BLOCK in rule.meta.scopes:
            for addr, _ in rule.matches:
                function = functions_by_bb[addr]
                matches_by_function[function].add(rule.meta.name)
        else:
            # file scope
            pass

    for f in doc.meta.analysis.feature_counts.functions:
        if not matches_by_function.get(f.address, {}):
            continue
        ostream.writeln(f"function at {capa.render.verbose.format_address(f.address)} with {f.count} features: ")
        for rule_name in sorted(matches_by_function[f.address]):
            ostream.writeln("  - " + rule_name)

    return ostream.getvalue()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    capa.main.install_common_args(
        parser, wanted={"format", "os", "backend", "input_file", "signatures", "rules", "tag"}
    )
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)
        input_format = capa.main.get_input_format_from_cli(args)
        rules = capa.main.get_rules_from_cli(args)
        backend = capa.main.get_backend_from_cli(args, input_format)
        sample_path = capa.main.get_sample_path_from_cli(args, backend)
        if sample_path is None:
            os_ = "unknown"
        else:
            os_ = capa.loader.get_os(sample_path)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
    except capa.main.ShouldExitError as e:
        return e.status_code

    capabilities, counts = capa.capabilities.common.find_capabilities(rules, extractor)

    meta = capa.loader.collect_metadata(argv, args.input_file, input_format, os_, args.rules, extractor, counts)
    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities)

    if capa.capabilities.common.has_file_limitation(rules, capabilities):
        # bail if capa encountered file limitation e.g. a packed binary
        # do show the output in verbose mode, though.
        if not (args.verbose or args.vverbose or args.json):
            return capa.main.E_FILE_LIMITATION

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    print(render_matches_by_function(doc))
    colorama.deinit()

    return 0


if __name__ == "__main__":
    sys.exit(main())
