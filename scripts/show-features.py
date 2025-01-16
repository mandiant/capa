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
"""
import sys
import logging
import argparse

import capa.main
import capa.rules
import capa.engine
import capa.loader
import capa.helpers
import capa.features
import capa.exceptions
import capa.render.verbose as v
import capa.features.freeze
import capa.features.address
import capa.features.extractors.pefile
from capa.helpers import assert_never
from capa.features.insn import API, Number
from capa.features.common import String, Feature, is_global_feature
from capa.features.extractors.base_extractor import FunctionHandle, StaticFeatureExtractor, DynamicFeatureExtractor

logger = logging.getLogger("capa.show-features")


def format_address(addr: capa.features.address.Address) -> str:
    return v.format_address(capa.features.freeze.Address.from_capa((addr)))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Show the features that capa extracts from the given sample")
    capa.main.install_common_args(parser, wanted={"input_file", "format", "os", "signatures", "backend"})

    parser.add_argument("-F", "--function", type=str, help="Show features for specific function")
    parser.add_argument("-P", "--process", type=str, help="Show features for specific process name")
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)

        if args.function and args.backend == "pefile":
            print("pefile backend does not support extracting function features")
            return -1

        input_format = capa.main.get_input_format_from_cli(args)

        backend = capa.main.get_backend_from_cli(args, input_format)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
    except capa.main.ShouldExitError as e:
        return e.status_code

    if isinstance(extractor, DynamicFeatureExtractor):
        print_dynamic_analysis(extractor, args)
    elif isinstance(extractor, StaticFeatureExtractor):
        print_static_analysis(extractor, args)
    else:
        assert_never(extractor)

    return 0


def print_static_analysis(extractor: StaticFeatureExtractor, args):
    for feature, addr in extractor.extract_global_features():
        print(f"global: {format_address(addr)}: {feature}")

    if not args.function:
        for feature, addr in extractor.extract_file_features():
            print(f"file: {format_address(addr)}: {feature}")

    function_handles: tuple[FunctionHandle, ...]
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

    print_static_features(function_handles, extractor)


def print_dynamic_analysis(extractor: DynamicFeatureExtractor, args):
    for feature, addr in extractor.extract_global_features():
        print(f"global: {format_address(addr)}: {feature}")

    if not args.process:
        for feature, addr in extractor.extract_file_features():
            print(f"file: {format_address(addr)}: {feature}")

    process_handles = tuple(extractor.get_processes())

    if args.process:
        process_handles = tuple(filter(lambda ph: extractor.get_process_name(ph) == args.process, process_handles))
        if args.process not in [extractor.get_process_name(ph) for ph in process_handles]:
            print(f"{args.process} not a process")
            return -1

    print_dynamic_features(process_handles, extractor)


def print_static_features(functions, extractor: StaticFeatureExtractor):
    for f in functions:
        if extractor.is_library_function(f.address):
            function_name = extractor.get_function_name(f.address)
            logger.debug("skipping library function %s (%s)", format_address(f.address), function_name)
            continue

        print(f"func: {format_address(f.address)}")

        for feature, addr in extractor.extract_function_features(f):
            if is_global_feature(feature):
                continue

            if f.address != addr:
                print(f" func: {format_address(f.address)}: {feature} -> {format_address(addr)}")
            else:
                print(f" func: {format_address(f.address)}: {feature}")

        for bb in extractor.get_basic_blocks(f):
            for feature, addr in extractor.extract_basic_block_features(f, bb):
                if is_global_feature(feature):
                    continue

                if bb.address != addr:
                    print(f" bb: {format_address(bb.address)}: {feature} -> {format_address(addr)}")
                else:
                    print(f" bb: {format_address(bb.address)}: {feature}")

            for insn in extractor.get_instructions(f, bb):
                for feature, addr in extractor.extract_insn_features(f, bb, insn):
                    if is_global_feature(feature):
                        continue

                    try:
                        if insn.address != addr:
                            print(
                                f"  insn: {format_address(f.address)}: {format_address(insn.address)}: {feature} -> {format_address(addr)}"
                            )
                        else:
                            print(f"  insn: {format_address(insn.address)}: {feature}")

                    except UnicodeEncodeError:
                        # may be an issue while piping to less and encountering non-ascii characters
                        continue


def print_dynamic_features(processes, extractor: DynamicFeatureExtractor):
    for p in processes:
        print(f"proc: {extractor.get_process_name(p)} (ppid={p.address.ppid}, pid={p.address.pid})")

        for feature, _ in extractor.extract_process_features(p):
            if is_global_feature(feature):
                continue

            print(f" proc: {extractor.get_process_name(p)}: {feature}")

        for t in extractor.get_threads(p):
            print(f"  thread: {t.address.tid}")
            for feature, addr in extractor.extract_thread_features(p, t):
                if is_global_feature(feature):
                    continue

                if feature != Feature(0):
                    print(f"   {format_address(addr)}: {feature}")

            for call in extractor.get_calls(p, t):
                apis = []
                arguments = []
                for feature, addr in extractor.extract_call_features(p, t, call):
                    if is_global_feature(feature):
                        continue

                    if isinstance(feature, API):
                        assert isinstance(addr, capa.features.address.DynamicCallAddress)
                        apis.append((addr.id, str(feature.value)))

                    if isinstance(feature, (Number, String)):
                        arguments.append(str(feature.value))

                for cid, api in apis:
                    print(f"    call {cid}: {api}({', '.join(arguments)})")


def ida_main():
    import idc

    import capa.features.extractors.ida.extractor

    function = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
    print(f"getting features for current function {hex(function)}")

    extractor = capa.features.extractors.ida.extractor.IdaFeatureExtractor()

    if not function:
        for feature, addr in extractor.extract_file_features():
            print(f"file: {format_address(addr)}: {feature}")
        return

    function_handles = tuple(extractor.get_functions())

    if function:
        function_handles = tuple(filter(lambda fh: fh.inner.start_ea == function, function_handles))

        if len(function_handles) == 0:
            print(f"{hex(function)} not a function")
            return -1

    print_static_features(function_handles, extractor)

    return 0


def ghidra_main():
    import capa.features.extractors.ghidra.extractor

    extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()

    for feature, addr in extractor.extract_file_features():
        print(f"file: {format_address(addr)}: {feature}")

    function_handles = tuple(extractor.get_functions())

    print_static_features(function_handles, extractor)

    return 0


if __name__ == "__main__":
    if capa.helpers.is_runtime_ida():
        ida_main()
    elif capa.helpers.is_runtime_ghidra():
        ghidra_main()
    else:
        sys.exit(main())
