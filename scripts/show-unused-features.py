#!/usr/bin/env python3
"""
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
import typing
import logging
import argparse
from typing import Set, Tuple
from pathlib import Path
from collections import Counter

import tabulate
from termcolor import colored

import capa.main
import capa.rules
import capa.helpers
import capa.features
import capa.exceptions
import capa.render.verbose as v
import capa.features.common
import capa.features.freeze
import capa.features.address
import capa.features.extractors.pefile
import capa.features.extractors.base_extractor
from capa.helpers import log_unsupported_runtime_error
from capa.features.common import Feature
from capa.features.extractors.base_extractor import FunctionHandle

logger = logging.getLogger("show-unused-features")


def format_address(addr: capa.features.address.Address) -> str:
    return v.format_address(capa.features.freeze.Address.from_capa((addr)))


def get_rules_feature_set(rules_path) -> Set[Feature]:
    ruleset = capa.main.get_rules(rules_path)
    rules_feature_set: Set[Feature] = set()
    for _, rule in ruleset.rules.items():
        rules_feature_set.update(rule.extract_all_features())

    return rules_feature_set


def get_file_features(
    functions: Tuple[FunctionHandle, ...], extractor: capa.features.extractors.base_extractor.FeatureExtractor
) -> typing.Counter[Feature]:
    feature_map: typing.Counter[Feature] = Counter()

    for f in functions:
        if extractor.is_library_function(f.address):
            function_name = extractor.get_function_name(f.address)
            logger.debug("skipping library function %s (%s)", format_address(f.address), function_name)
            continue

        for feature, _ in extractor.extract_function_features(f):
            if capa.features.common.is_global_feature(feature):
                continue
            feature_map.update([feature])

        for bb in extractor.get_basic_blocks(f):
            for feature, _ in extractor.extract_basic_block_features(f, bb):
                if capa.features.common.is_global_feature(feature):
                    continue
                feature_map.update([feature])

            for insn in extractor.get_instructions(f, bb):
                for feature, _ in extractor.extract_insn_features(f, bb, insn):
                    if capa.features.common.is_global_feature(feature):
                        continue
                    feature_map.update([feature])
    return feature_map


def get_colored(s: str):
    if "(" in s and ")" in s:
        s_split = s.split("(", 1)
        s_color = colored(s_split[1][:-1], "cyan")
        return f"{s_split[0]}({s_color})"
    else:
        return colored(s, "cyan")


def print_unused_features(feature_map: typing.Counter[Feature], rules_feature_set: Set[Feature]):
    unused_features = []
    for feature, count in reversed(feature_map.most_common()):
        if feature in rules_feature_set:
            continue
        unused_features.append((str(count), get_colored(str(feature))))
    print("\n")
    print(tabulate.tabulate(unused_features, headers=["Count", "Feature"], tablefmt="plain"))
    print("\n")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Show the features that capa doesn't have rules for yet")
    capa.main.install_common_args(parser, wanted={"format", "os", "sample", "signatures", "backend", "rules"})

    parser.add_argument("-F", "--function", type=str, help="Show features for specific function")
    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    if args.function and args.backend == "pefile":
        print("pefile backend does not support extracting function features")
        return -1

    try:
        taste = capa.helpers.get_file_taste(Path(args.sample))
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    try:
        sig_paths = capa.main.get_signatures(args.signatures)
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    if (args.format == "freeze") or (
        args.format == capa.features.common.FORMAT_AUTO and capa.features.freeze.is_freeze(taste)
    ):
        extractor = capa.features.freeze.load(Path(args.sample).read_bytes())
    else:
        should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)
        try:
            extractor = capa.main.get_extractor(
                args.sample, args.format, args.os, args.backend, sig_paths, should_save_workspace
            )
        except capa.exceptions.UnsupportedFormatError:
            capa.helpers.log_unsupported_format_error()
            return -1
        except capa.exceptions.UnsupportedRuntimeError:
            log_unsupported_runtime_error()
            return -1

    feature_map: typing.Counter[Feature] = Counter()

    feature_map.update([feature for feature, _ in extractor.extract_global_features()])

    function_handles: Tuple[FunctionHandle, ...]
    if isinstance(extractor, capa.features.extractors.pefile.PefileFeatureExtractor):
        # pefile extractor doesn't extract function features
        function_handles = ()
    else:
        function_handles = tuple(extractor.get_functions())

    if args.function:
        if args.format == "freeze":
            function_handles = tuple(filter(lambda fh: fh.address == args.function, function_handles))
        else:
            function_handles = tuple(filter(lambda fh: format_address(fh.address) == args.function, function_handles))

            if args.function not in [format_address(fh.address) for fh in function_handles]:
                print(f"{args.function} not a function")
                return -1

        if len(function_handles) == 0:
            print(f"{args.function} not a function")
            return -1

    feature_map.update(get_file_features(function_handles, extractor))

    rules_feature_set = get_rules_feature_set(args.rules)

    print_unused_features(feature_map, rules_feature_set)
    return 0


def ida_main():
    import idc

    import capa.main
    import capa.features.extractors.ida.extractor

    function = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
    print(f"getting features for current function {hex(function)}")

    extractor = capa.features.extractors.ida.extractor.IdaFeatureExtractor()
    feature_map: typing.Counter[Feature] = Counter()

    feature_map.update([feature for feature, _ in extractor.extract_file_features()])

    function_handles = tuple(extractor.get_functions())

    if function:
        function_handles = tuple(filter(lambda fh: fh.inner.start_ea == function, function_handles))

        if len(function_handles) == 0:
            print(f"{hex(function)} not a function")
            return -1

    feature_map.update(get_file_features(function_handles, extractor))

    rules_path = capa.main.get_default_root() / "rules"
    rules_feature_set = get_rules_feature_set([rules_path])

    print_unused_features(feature_map, rules_feature_set)

    return 0


if __name__ == "__main__":
    if capa.helpers.is_runtime_ida():
        ida_main()
    else:
        sys.exit(main())
