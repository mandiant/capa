#!/usr/bin/env python3
"""
Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

match-function-id

Show the names of functions as recognized by the function identification subsystem.
This can help identify library functions statically linked into a program,
such as when triaging false positive matches in capa rules.

Example::

    $ python scripts/match-function-id.py --signature sigs/vc6.pat.gz /tmp/suspicious.dll_
    0x44cf30: ?GetPdbDll@@YAPAUHINSTANCE__@@XZ
    0x44bb20: ?_strlen_priv@@YAIPBD@Z
    0x44b6b0: ?invoke_main@@YAHXZ
    0x44a5d0: ?find_pe_section@@YAPAU_IMAGE_SECTION_HEADER@@QAEI@Z
    0x44a690: ?is_potentially_valid_image_base@@YA_NQAX@Z
    0x44cbe0: ___get_entropy
    0x44a4a0: __except_handler4
    0x44b3d0: ?pre_cpp_initialization@@YAXXZ
    0x44b2e0: ?pre_c_initialization@@YAHXZ
    0x44b3c0: ?post_pgo_initialization@@YAHXZ
    0x420156: ?
    0x420270: ?
    0x430dcd: ?
    0x44d930: __except_handler4_noexcept
    0x41e960: ?
    0x44a1e0: @_RTC_AllocaHelper@12
    0x44ba90: ?_getMemBlockDataString@@YAXPAD0PBDI@Z
    0x44a220: @_RTC_CheckStackVars2@12
    0x44a790: ___scrt_dllmain_after_initialize_c
    0x44a7d0: ___scrt_dllmain_before_initialize_c
    0x44a800: ___scrt_dllmain_crt_thread_attach
    0x44a860: ___scrt_dllmain_exception_filter
    0x44a900: ___scrt_dllmain_uninitialize_critical
    0x44ad10: _at_quick_exit
    0x44b940: ?_RTC_Failure@@YAXPAXH@Z
    0x44be60: __RTC_UninitUse
    0x44bfd0: __RTC_GetErrDesc
    0x44c060: __RTC_SetErrorType
    0x44cb60: ?
    0x44cba0: __guard_icall_checks_enforced
"""
import sys
import logging
import argparse

import flirt
import viv_utils
import viv_utils.flirt

import capa.main
import capa.rules
import capa.engine
import capa.helpers
import capa.features
import capa.features.freeze

logger = logging.getLogger("capa.match-function-id")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="FLIRT match each function")
    parser.add_argument("sample", type=str, help="Path to sample to analyze")
    parser.add_argument(
        "-F",
        "--function",
        type=lambda x: int(x, 0x10),
        help="match a specific function by VA, rather than add functions",
    )
    parser.add_argument(
        "--signature",
        action="append",
        dest="signatures",
        type=str,
        default=[],
        help="use the given signatures to identify library functions, file system paths to .sig/.pat files.",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output but errors")
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

    analyzers = []
    for sigpath in args.signatures:
        sigs = viv_utils.flirt.load_flirt_signature(sigpath)

        with capa.main.timing("flirt: compiling sigs"):
            matcher = flirt.compile(sigs)

        analyzer = viv_utils.flirt.FlirtFunctionAnalyzer(matcher, sigpath)
        logger.debug("registering viv function analyzer: %s", repr(analyzer))
        analyzers.append(analyzer)

    vw = viv_utils.getWorkspace(args.sample, analyze=True, should_save=False)

    functions = vw.getFunctions()
    if args.function:
        functions = [args.function]

    for function in functions:
        logger.debug("matching function: 0x%04x", function)
        for analyzer in analyzers:
            name = viv_utils.flirt.match_function_flirt_signatures(analyzer.matcher, vw, function)
            if name:
                print(f"0x{function:04x}: {name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
