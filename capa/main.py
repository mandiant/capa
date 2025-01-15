#!/usr/bin/env python3
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

import io
import os
import sys
import time
import logging
import argparse
import textwrap
import contextlib
from types import TracebackType
from typing import Any, Optional, TypedDict
from pathlib import Path

import colorama
from pefile import PEFormatError
from rich.logging import RichHandler
from elftools.common.exceptions import ELFError

import capa.perf
import capa.rules
import capa.engine
import capa.loader
import capa.helpers
import capa.version
import capa.render.json
import capa.rules.cache
import capa.render.default
import capa.render.verbose
import capa.features.common
import capa.render.vverbose
import capa.features.extractors
import capa.render.result_document
import capa.render.result_document as rdoc
import capa.features.extractors.common
from capa.rules import RuleSet
from capa.engine import MatchResults
from capa.loader import (
    BACKEND_IDA,
    BACKEND_VIV,
    BACKEND_CAPE,
    BACKEND_BINJA,
    BACKEND_VMRAY,
    BACKEND_DOTNET,
    BACKEND_FREEZE,
    BACKEND_PEFILE,
    BACKEND_DRAKVUF,
    BACKEND_BINEXPORT2,
)
from capa.helpers import (
    get_file_taste,
    get_auto_format,
    log_unsupported_os_error,
    log_unsupported_arch_error,
    log_unsupported_format_error,
    log_empty_sandbox_report_error,
    log_unsupported_cape_report_error,
    log_unsupported_vmray_report_error,
    log_unsupported_drakvuf_report_error,
)
from capa.exceptions import (
    InvalidArgument,
    EmptyReportError,
    UnsupportedOSError,
    UnsupportedArchError,
    UnsupportedFormatError,
    UnsupportedRuntimeError,
)
from capa.features.common import (
    OS_AUTO,
    OS_LINUX,
    OS_MACOS,
    FORMAT_PE,
    FORMAT_ELF,
    OS_WINDOWS,
    FORMAT_AUTO,
    FORMAT_CAPE,
    FORMAT_SC32,
    FORMAT_SC64,
    FORMAT_VMRAY,
    FORMAT_DOTNET,
    FORMAT_FREEZE,
    FORMAT_RESULT,
    FORMAT_DRAKVUF,
    STATIC_FORMATS,
    DYNAMIC_FORMATS,
    FORMAT_BINJA_DB,
    FORMAT_BINEXPORT2,
)
from capa.capabilities.common import find_capabilities, has_file_limitation, find_file_capabilities
from capa.features.extractors.base_extractor import (
    ProcessFilter,
    FunctionFilter,
    FeatureExtractor,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)

RULES_PATH_DEFAULT_STRING = "(embedded rules)"
SIGNATURES_PATH_DEFAULT_STRING = "(embedded signatures)"
BACKEND_AUTO = "auto"

E_MISSING_RULES = 10
E_MISSING_FILE = 11
E_INVALID_RULE = 12
E_CORRUPT_FILE = 13
E_FILE_LIMITATION = 14
E_INVALID_SIG = 15
E_INVALID_FILE_TYPE = 16
E_INVALID_FILE_ARCH = 17
E_INVALID_FILE_OS = 18
E_UNSUPPORTED_IDA_VERSION = 19
E_UNSUPPORTED_GHIDRA_VERSION = 20
E_MISSING_CAPE_STATIC_ANALYSIS = 21
E_MISSING_CAPE_DYNAMIC_ANALYSIS = 22
E_EMPTY_REPORT = 23
E_UNSUPPORTED_GHIDRA_EXECUTION_MODE = 24
E_INVALID_INPUT_FORMAT = 25
E_INVALID_FEATURE_EXTRACTOR = 26

logger = logging.getLogger("capa")


class FilterConfig(TypedDict, total=False):
    processes: set[int]
    functions: set[int]


@contextlib.contextmanager
def timing(msg: str):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.debug("perf: %s: %0.2fs", msg, t1 - t0)


def set_vivisect_log_level(level):
    logging.getLogger("vivisect").setLevel(level)
    logging.getLogger("vivisect.base").setLevel(level)
    logging.getLogger("vivisect.impemu").setLevel(level)
    logging.getLogger("vtrace").setLevel(level)
    logging.getLogger("envi").setLevel(level)
    logging.getLogger("envi.codeflow").setLevel(level)
    logging.getLogger("Elf").setLevel(level)


def get_default_root() -> Path:
    """
    get the file system path to the default resources directory.
    under PyInstaller, this comes from _MEIPASS.
    under source, this is the root directory of the project.
    """
    # we only expect capa.main to be packaged within PyInstaller,
    # so we don't put this in a more common place, like capa.helpers.

    if capa.helpers.is_running_standalone():
        # pylance/mypy don't like `sys._MEIPASS` because this isn't standard.
        # its injected by pyinstaller.
        # so we'll fetch this attribute dynamically.
        assert hasattr(sys, "_MEIPASS")
        return Path(sys._MEIPASS)
    else:
        return Path(__file__).resolve().parent.parent


def get_default_signatures() -> list[Path]:
    """
    compute a list of file system paths to the default FLIRT signatures.
    """
    sigs_path = get_default_root() / "sigs"
    logger.debug("signatures path: %s", sigs_path)

    ret = []
    for file in sigs_path.rglob("*"):
        if file.is_file() and file.suffix.lower() in (".pat", ".pat.gz", ".sig"):
            ret.append(file)

    return ret


def simple_message_exception_handler(
    exctype: type[BaseException], value: BaseException, traceback: TracebackType | None
):
    """
    prints friendly message on unexpected exceptions to regular users (debug mode shows regular stack trace)
    """

    if exctype is KeyboardInterrupt:
        print("KeyboardInterrupt detected, program terminated", file=sys.stderr)
    else:
        print(
            f"Unexpected exception raised: {exctype}. Please run capa in debug mode (-d/--debug) "
            + "to see the stack trace.\nPlease also report your issue on the capa GitHub page so we "
            + "can improve the code! (https://github.com/mandiant/capa/issues)",
            file=sys.stderr,
        )


def install_common_args(parser, wanted=None):
    """
    register a common set of command line arguments for re-use by main & scripts.
    these are things like logging/coloring/etc.
    also enable callers to opt-in to common arguments, like specifying the input file.

    this routine lets many script use the same language for cli arguments.
    see `handle_common_args` to do common configuration.

    args:
      parser (argparse.ArgumentParser): a parser to update in place, adding common arguments.
      wanted (set[str]): collection of arguments to opt-into, including:
        - "input_file": required positional argument to input file.
        - "format": flag to override file format.
        - "os": flag to override file operating system.
        - "backend": flag to override analysis backend.
        - "rules": flag to override path to capa rules.
        - "tag": flag to override/specify which rules to match.
    """
    if wanted is None:
        wanted = set()

    #
    # common arguments that all scripts will have
    #

    parser.add_argument("--version", action="version", version="%(prog)s {:s}".format(capa.version.__version__))
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose result document (no effect with --json)"
    )
    parser.add_argument(
        "-vv", "--vverbose", action="store_true", help="enable very verbose result document (no effect with --json)"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    parser.add_argument(
        "--color",
        type=str,
        choices=("auto", "always", "never"),
        default="auto",
        help="enable ANSI color codes in results, default: only during interactive session",
    )

    if "input_file" in wanted:
        parser.add_argument(
            "input_file",
            type=str,
            help="path to file to analyze",
        )

    if "format" in wanted:
        formats = [
            (FORMAT_AUTO, "(default) detect file type automatically"),
            (FORMAT_PE, "Windows PE file"),
            (FORMAT_DOTNET, ".NET PE file"),
            (FORMAT_ELF, "Executable and Linkable Format"),
            (FORMAT_SC32, "32-bit shellcode"),
            (FORMAT_SC64, "64-bit shellcode"),
            (FORMAT_CAPE, "CAPE sandbox report"),
            (FORMAT_DRAKVUF, "DRAKVUF sandbox report"),
            (FORMAT_VMRAY, "VMRay sandbox report"),
            (FORMAT_FREEZE, "features previously frozen by capa"),
            (FORMAT_BINEXPORT2, "BinExport2"),
            (FORMAT_BINJA_DB, "Binary Ninja Database"),
        ]
        format_help = ", ".join([f"{f[0]}: {f[1]}" for f in formats])

        parser.add_argument(
            "-f",
            "--format",
            choices=[f[0] for f in formats],
            default=FORMAT_AUTO,
            help=f"select input format, {format_help}",
        )

    if "backend" in wanted:
        backends = [
            (BACKEND_AUTO, "(default) detect appropriate backend automatically"),
            (BACKEND_VIV, "vivisect"),
            (BACKEND_IDA, "IDA via idalib"),
            (BACKEND_PEFILE, "pefile (file features only)"),
            (BACKEND_BINJA, "Binary Ninja"),
            (BACKEND_DOTNET, ".NET"),
            (BACKEND_BINEXPORT2, "BinExport2"),
            (BACKEND_FREEZE, "capa freeze"),
            (BACKEND_CAPE, "CAPE"),
            (BACKEND_DRAKVUF, "DRAKVUF"),
            (BACKEND_VMRAY, "VMRay"),
        ]
        backend_help = ", ".join([f"{f[0]}: {f[1]}" for f in backends])
        parser.add_argument(
            "-b",
            "--backend",
            type=str,
            choices=[f[0] for f in backends],
            default=BACKEND_AUTO,
            help=f"select backend, {backend_help}",
        )

    if "restrict-to-functions" in wanted:
        parser.add_argument(
            "--restrict-to-functions",
            type=lambda s: s.replace(" ", "").split(","),
            default=[],
            help="provide a list of comma-separated function virtual addresses to analyze (static analysis).",
        )

    if "restrict-to-processes" in wanted:
        parser.add_argument(
            "--restrict-to-processes",
            type=lambda s: s.replace(" ", "").split(","),
            default=[],
            help="provide a list of comma-separated process IDs to analyze (dynamic analysis).",
        )

    if "os" in wanted:
        oses = [
            (OS_AUTO, "detect OS automatically - default"),
            (OS_LINUX,),
            (OS_MACOS,),
            (OS_WINDOWS,),
        ]
        os_help = ", ".join([f"{o[0]} ({o[1]})" if len(o) == 2 else o[0] for o in oses])
        parser.add_argument(
            "--os",
            choices=[o[0] for o in oses],
            default=OS_AUTO,
            help=f"select sample OS: {os_help}",
        )

    if "rules" in wanted:
        parser.add_argument(
            "-r",
            "--rules",
            type=str,
            default=[RULES_PATH_DEFAULT_STRING],
            action="append",
            help="path to rule file or directory, use embedded rules by default",
        )

    if "signatures" in wanted:
        parser.add_argument(
            "-s",
            "--signatures",
            type=str,
            default=SIGNATURES_PATH_DEFAULT_STRING,
            help="path to .sig/.pat file or directory used to identify library functions, use embedded signatures by default",
        )

    if "tag" in wanted:
        parser.add_argument("-t", "--tag", type=str, help="filter on rule meta field values")


###############################################################################
#
# "main routines"
#
# All of the following routines are considered "main routines".
# That is, they rely upon the given CLI arguments and write to output streams.
# We prefer to keep as much logic away from input/output as possible;
# however, capa does handle many combinations of flags/switches/overrides,
# so these routines deal with that logic.
#
# Other scripts may use this routines, but should also prefer to invoke them
# directly within `main()`, not within library code.
# Library code should *not* call these functions.
#
# These main routines may raise `ShouldExitError` to indicate the program
# ...should exit. It's a tiny step away from doing `sys.exit()` directly.
# I'm not sure if we should just do that. In the meantime, programs should
# handle `ShouldExitError` and pass the status code to `sys.exit()`.
#


class ShouldExitError(Exception):
    """raised when a main-related routine indicates the program should exit."""

    def __init__(self, status_code: int):
        self.status_code = status_code


def handle_common_args(args):
    """
    handle the global config specified by `install_common_args`,
    such as configuring logging/coloring/etc.
    the following fields will be overwritten when present:
      - rules: file system path to rule files.
      - signatures: file system path to signature files.

    the following fields may be added:
      - is_default_rules: if the default rules were used.
      - is_default_signatures: if the default signatures were used.

    args:
      args: The parsed command line arguments from `install_common_args`.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # use [/] after the logger name to reset any styling,
    # and prevent the color from carrying over to the message
    logformat = "[dim]%(name)s[/]: %(message)s"

    # set markup=True to allow the use of Rich's markup syntax in log messages
    rich_handler = RichHandler(markup=True, show_time=False, show_path=True, console=capa.helpers.log_console)
    rich_handler.setFormatter(logging.Formatter(logformat))

    # use RichHandler for root logger
    logging.getLogger().addHandler(rich_handler)

    # disable vivisect-related logging, it's verbose and not relevant for capa users
    set_vivisect_log_level(logging.CRITICAL)

    if isinstance(sys.stdout, io.TextIOWrapper) or hasattr(sys.stdout, "reconfigure"):
        # from sys.stdout type hint:
        #
        # TextIO is used instead of more specific types for the standard streams,
        # since they are often monkeypatched at runtime. At startup, the objects
        # are initialized to instances of TextIOWrapper.
        #
        # To use methods from TextIOWrapper, use an isinstance check to ensure that
        # the streams have not been overridden:
        #
        # if isinstance(sys.stdout, io.TextIOWrapper):
        #    sys.stdout.reconfigure(...)
        sys.stdout.reconfigure(encoding="utf-8")
    colorama.just_fix_windows_console()

    if args.color == "always":
        colorama.init(strip=False)
    elif args.color == "auto":
        # colorama will detect:
        #  - when on Windows console, and fixup coloring, and
        #  - when not an interactive session, and disable coloring
        # renderers should use coloring and assume it will be stripped out if necessary.
        colorama.init()
    elif args.color == "never":
        colorama.init(strip=True)
    else:
        raise RuntimeError("unexpected --color value: " + args.color)

    if not args.debug:
        sys.excepthook = simple_message_exception_handler

    if hasattr(args, "input_file"):
        args.input_file = Path(args.input_file)

    if hasattr(args, "rules"):
        rules_paths: list[Path] = []

        if args.rules == [RULES_PATH_DEFAULT_STRING]:
            logger.debug("-" * 80)
            logger.debug(" Using default embedded rules.")
            logger.debug(" To provide your own rules, use the form:")
            logger.debug("")
            logger.debug("     `capa.exe -r ./path/to/rules/  /path/to/mal.exe`.")
            logger.debug("")
            logger.debug(" You can see the current default rule set here:")
            logger.debug("")
            logger.debug("     https://github.com/mandiant/capa-rules")
            logger.debug("-" * 80)

            default_rule_path = get_default_root() / "rules"

            if not default_rule_path.exists():
                # when a users installs capa via pip,
                # this pulls down just the source code - not the default rules.
                # i'm not sure the default rules should even be written to the library directory,
                # so in this case, we require the user to use -r to specify the rule directory.
                logger.error("default embedded rules not found! (maybe you installed capa as a library?)")
                logger.error("provide your own rule set via the `-r` option.")
                raise ShouldExitError(E_MISSING_RULES)

            rules_paths.append(default_rule_path)
            args.is_default_rules = True
        else:
            for rule in args.rules:
                if RULES_PATH_DEFAULT_STRING != rule:
                    rules_paths.append(Path(rule))

            for rule_path in rules_paths:
                logger.debug("using rules path: %s", rule_path)

            args.is_default_rules = False

        args.rules = rules_paths

    if hasattr(args, "signatures"):
        if args.signatures == SIGNATURES_PATH_DEFAULT_STRING:
            sigs_path = get_default_root() / "sigs"
            args.is_default_signatures = True
        else:
            sigs_path = Path(args.signatures)
            args.is_default_signatures = False

        args.signatures = sigs_path


def ensure_input_exists_from_cli(args):
    """
    args:
      args: The parsed command line arguments from `install_common_args`.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    try:
        _ = get_file_taste(args.input_file)
    except IOError as e:
        # per our research there's not a programmatic way to render the IOError with non-ASCII filename unless we
        # handle the IOError separately and reach into the args
        logger.error("%s", e.args[0])
        raise ShouldExitError(E_MISSING_FILE) from e


def get_input_format_from_cli(args) -> str:
    """
    Determine the format of the input file.

    Note: this may not be the same as the format of the sample.
    Cape, Freeze, etc. formats describe a sample without being the sample itself.

    args:
      args: The parsed command line arguments from `install_common_args`.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    format_ = args.format

    if format_ != FORMAT_AUTO:
        return format_

    try:
        return get_auto_format(args.input_file)
    except PEFormatError as e:
        logger.error("Input file '%s' is not a valid PE file: %s", args.input_file, str(e))
        raise ShouldExitError(E_CORRUPT_FILE) from e
    except UnsupportedFormatError as e:
        log_unsupported_format_error()
        raise ShouldExitError(E_INVALID_FILE_TYPE) from e


def get_backend_from_cli(args, input_format: str) -> str:
    """
    Determine the backend that should be used for the given input file.
    Respects an override provided by the user, otherwise, use a good default.

    args:
      args: The parsed command line arguments from `install_common_args`.
      input_format: The file format of the input file.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    if args.backend != BACKEND_AUTO:
        return args.backend

    if input_format == FORMAT_CAPE:
        return BACKEND_CAPE

    if input_format == FORMAT_DRAKVUF:
        return BACKEND_DRAKVUF

    elif input_format == FORMAT_VMRAY:
        return BACKEND_VMRAY

    elif input_format == FORMAT_DOTNET:
        return BACKEND_DOTNET

    elif input_format == FORMAT_FREEZE:
        return BACKEND_FREEZE

    elif input_format == FORMAT_BINEXPORT2:
        return BACKEND_BINEXPORT2

    else:
        return BACKEND_VIV


def get_sample_path_from_cli(args, backend: str) -> Optional[Path]:
    """
    Determine the path to the underlying sample, if it exists.

    Note: this may not be the same as the input file.
    Cape, Freeze, etc. formats describe a sample without being the sample itself.

    args:
      args: The parsed command line arguments from `install_common_args`.
      backend: The backend that will handle the input file.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    if backend in (BACKEND_CAPE, BACKEND_DRAKVUF, BACKEND_VMRAY):
        return None
    elif backend == BACKEND_BINEXPORT2:
        import capa.features.extractors.binexport2

        be2 = capa.features.extractors.binexport2.get_binexport2(args.input_file)
        return capa.features.extractors.binexport2.get_sample_from_binexport2(
            args.input_file, be2, [Path(os.environ.get("CAPA_SAMPLES_DIR", "."))]
        )
    else:
        return args.input_file


def get_os_from_cli(args, backend) -> str:
    """
    Determine the OS for the given sample.
    Respects an override provided by the user, otherwise, use heuristics and
    algorithms to detect the OS.

    args:
      args: The parsed command line arguments from `install_common_args`.
      backend: The backend that will handle the input file.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    if args.os:
        return args.os

    sample_path = get_sample_path_from_cli(args, backend)
    if sample_path is None:
        return "unknown"
    return capa.loader.get_os(sample_path)


def get_rules_from_cli(args) -> RuleSet:
    """
    args:
      args: The parsed command line arguments from `install_common_args`.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    enable_cache: bool = True
    try:
        if capa.helpers.is_running_standalone() and args.is_default_rules:
            cache_dir = get_default_root() / "cache"
        else:
            cache_dir = capa.rules.cache.get_default_cache_directory()

        if capa.helpers.is_dev_environment():
            # using the rules cache during development may result in unexpected errors, see #1898
            enable_cache = capa.helpers.is_cache_newer_than_rule_code(cache_dir)
            if not enable_cache:
                logger.debug("not using cache. delete the cache file manually to use rule caching again")
            else:
                logger.debug("cache can be used, no potentially outdated cache files found")

        rules = capa.rules.get_rules(args.rules, cache_dir=cache_dir, enable_cache=enable_cache)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        logger.error(
            "Make sure your file directory contains properly formatted capa rules. You can download the standard "  # noqa: G003 [logging statement uses +]
            + "collection of capa rules from https://github.com/mandiant/capa-rules/releases."
        )
        logger.error(
            "Please ensure you're using the rules that correspond to your major version of capa (%s)",
            capa.version.get_major_version(),
        )
        logger.error(
            "Or, for more details, see the rule set documentation here: %s",
            "https://github.com/mandiant/capa/blob/master/doc/rules.md",
        )
        raise ShouldExitError(E_INVALID_RULE) from e

    logger.debug(
        "successfully loaded %s rules",
        # during the load of the RuleSet, we extract subscope statements into their own rules
        # that are subsequently `match`ed upon. this inflates the total rule count.
        # so, filter out the subscope rules when reporting total number of loaded rules.
        len(list(filter(lambda r: not (r.is_subscope_rule()), rules.rules.values()))),
    )

    if hasattr(args, "tag") and args.tag:
        rules = rules.filter_rules_by_meta(args.tag)
        logger.debug("selected %d rules", len(rules))
        for i, r in enumerate(rules.rules, 1):
            logger.debug(" %d. %s", i, r)

    return rules


def get_file_extractors_from_cli(args, input_format: str) -> list[FeatureExtractor]:
    """
    args:
      args: The parsed command line arguments from `install_common_args`.
      input_format: The file format of the input file.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    # file feature extractors are pretty lightweight: they don't do any code analysis.
    # so we can fairly quickly determine if the given file has "pure" file-scope rules
    # that indicate a limitation (like "file is packed based on section names")
    # and avoid doing a full code analysis on difficult/impossible binaries.
    #
    # this pass can inspect multiple file extractors, e.g., dotnet and pe to identify
    # various limitations
    try:
        return capa.loader.get_file_extractors(args.input_file, input_format)
    except PEFormatError as e:
        logger.error("Input file '%s' is not a valid PE file: %s", args.input_file, str(e))
        raise ShouldExitError(E_CORRUPT_FILE) from e
    except (ELFError, OverflowError) as e:
        logger.error("Input file '%s' is not a valid ELF file: %s", args.input_file, str(e))
        raise ShouldExitError(E_CORRUPT_FILE) from e
    except UnsupportedFormatError as e:
        if input_format == FORMAT_CAPE:
            log_unsupported_cape_report_error(str(e))
        elif input_format == FORMAT_DRAKVUF:
            log_unsupported_drakvuf_report_error(str(e))
        elif input_format == FORMAT_VMRAY:
            log_unsupported_vmray_report_error(str(e))
        else:
            log_unsupported_format_error()
        raise ShouldExitError(E_INVALID_FILE_TYPE) from e
    except EmptyReportError as e:
        if input_format == FORMAT_CAPE:
            log_empty_sandbox_report_error(str(e), sandbox_name="CAPE")
            raise ShouldExitError(E_EMPTY_REPORT) from e
        elif input_format == FORMAT_DRAKVUF:
            log_empty_sandbox_report_error(str(e), sandbox_name="DRAKVUF")
            raise ShouldExitError(E_EMPTY_REPORT) from e
        else:
            log_unsupported_format_error()
            raise ShouldExitError(E_INVALID_FILE_TYPE) from e


def find_file_limitations_from_cli(args, rules: RuleSet, file_extractors: list[FeatureExtractor]) -> bool:
    """
    args:
      args: The parsed command line arguments from `install_common_args`.

    Dynamic feature extractors can handle packed samples and do not need to be considered here.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    found_file_limitation = False
    for file_extractor in file_extractors:
        try:
            pure_file_capabilities, _ = find_file_capabilities(rules, file_extractor, {})
        except PEFormatError as e:
            logger.error("Input file '%s' is not a valid PE file: %s", args.input_file, str(e))
            raise ShouldExitError(E_CORRUPT_FILE) from e
        except (ELFError, OverflowError) as e:
            logger.error("Input file '%s' is not a valid ELF file: %s", args.input_file, str(e))
            raise ShouldExitError(E_CORRUPT_FILE) from e

        # file limitations that rely on non-file scope won't be detected here.
        # nor on FunctionName features, because pefile doesn't support this.
        found_file_limitation = has_file_limitation(rules, pure_file_capabilities)
        if found_file_limitation:
            # bail if capa encountered file limitation e.g. a packed binary
            # do show the output in verbose mode, though.
            if not (args.verbose or args.vverbose or args.json):
                logger.debug("file limitation short circuit, won't analyze fully.")
                raise ShouldExitError(E_FILE_LIMITATION)
    return found_file_limitation


def get_signatures_from_cli(args, input_format: str, backend: str) -> list[Path]:
    if backend != BACKEND_VIV:
        logger.debug("skipping library code matching: only supported by the vivisect backend")
        return []

    if input_format != FORMAT_PE:
        logger.debug("skipping library code matching: signatures only supports PE files")
        return []

    if args.is_default_signatures:
        logger.debug("-" * 80)
        logger.debug(" Using default embedded signatures.")
        logger.debug(
            " To provide your own signatures, use the form `capa.exe --signature ./path/to/signatures/  /path/to/mal.exe`."
        )
        logger.debug("-" * 80)

        if not args.signatures.exists():
            logger.error(
                "Using default signature path, but it doesn't exist. "  # noqa: G003 [logging statement uses +]
                + "Please install the signatures first: "
                + "https://github.com/mandiant/capa/blob/master/doc/installation.md#method-2-using-capa-as-a-python-library."
            )
            raise IOError(f"signatures path {args.signatures} does not exist or cannot be accessed")
    else:
        logger.debug("using signatures path: %s", args.signatures)

    try:
        return capa.loader.get_signatures(args.signatures)
    except IOError as e:
        logger.error("%s", str(e))
        raise ShouldExitError(E_INVALID_SIG) from e


def get_extractor_from_cli(args, input_format: str, backend: str) -> FeatureExtractor:
    """
    args:
      args: The parsed command line arguments from `install_common_args`.
      input_format: The file format of the input file.
      backend: The backend that will handle the input file.

    raises:
      ShouldExitError: if the program is invoked incorrectly and should exit.
    """
    sig_paths = get_signatures_from_cli(args, input_format, backend)

    should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)

    os_ = get_os_from_cli(args, backend)
    sample_path = get_sample_path_from_cli(args, backend)
    extractor_filters = get_extractor_filters_from_cli(args, input_format)

    logger.debug("format:  %s", input_format)
    logger.debug("backend: %s", backend)

    try:
        extractor = capa.loader.get_extractor(
            args.input_file,
            input_format,
            os_,
            backend,
            sig_paths,
            should_save_workspace=should_save_workspace,
            disable_progress=args.quiet or args.debug,
            sample_path=sample_path,
        )
        return apply_extractor_filters(extractor, extractor_filters)
    except UnsupportedFormatError as e:
        if input_format == FORMAT_CAPE:
            log_unsupported_cape_report_error(str(e))
        elif input_format == FORMAT_DRAKVUF:
            log_unsupported_drakvuf_report_error(str(e))
        elif input_format == FORMAT_VMRAY:
            log_unsupported_vmray_report_error(str(e))
        else:
            log_unsupported_format_error()
        raise ShouldExitError(E_INVALID_FILE_TYPE) from e
    except UnsupportedArchError as e:
        log_unsupported_arch_error()
        raise ShouldExitError(E_INVALID_FILE_ARCH) from e
    except UnsupportedOSError as e:
        log_unsupported_os_error()
        raise ShouldExitError(E_INVALID_FILE_OS) from e
    except capa.loader.CorruptFile as e:
        logger.error("Input file '%s' is not a valid file: %s", args.input_file, str(e))
        raise ShouldExitError(E_CORRUPT_FILE) from e


def get_extractor_filters_from_cli(args, input_format) -> FilterConfig:
    if not hasattr(args, "restrict_to_processes") and not hasattr(args, "restrict_to_functions"):
        # no processes or function filters were installed in the args
        return {}

    if input_format in STATIC_FORMATS:
        if args.restrict_to_processes:
            raise InvalidArgument("Cannot filter processes with static analysis.")
        return {"functions": {int(addr, 0) for addr in args.restrict_to_functions}}
    elif input_format in DYNAMIC_FORMATS:
        if args.restrict_to_functions:
            raise InvalidArgument("Cannot filter functions with dynamic analysis.")
        return {"processes": {int(pid, 0) for pid in args.restrict_to_processes}}
    else:
        raise ShouldExitError(E_INVALID_INPUT_FORMAT)


def apply_extractor_filters(extractor: FeatureExtractor, extractor_filters: FilterConfig):
    if not any(extractor_filters.values()):
        return extractor

    # if the user specified extractor filters, then apply them here
    if isinstance(extractor, StaticFeatureExtractor):
        assert extractor_filters["functions"]
        return FunctionFilter(extractor, extractor_filters["functions"])
    elif isinstance(extractor, DynamicFeatureExtractor):
        assert extractor_filters["processes"]
        return ProcessFilter(extractor, extractor_filters["processes"])
    else:
        raise ShouldExitError(E_INVALID_FEATURE_EXTRACTOR)


def main(argv: Optional[list[str]] = None):
    if sys.version_info < (3, 10):
        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.10+")

    if argv is None:
        argv = sys.argv[1:]

    desc = "The FLARE team's open-source tool to identify capabilities in executable files."
    epilog = textwrap.dedent(
        """
        By default, capa uses a default set of embedded rules.
        You can see the rule set here:
          https://github.com/mandiant/capa-rules

        You can load capa JSON output to capa Explorer Web:
          https://github.com/mandiant/capa/explorer

        To provide your own rule set, use the `-r` flag:
          capa  --rules /path/to/rules  suspicious.exe
          capa  -r      /path/to/rules  suspicious.exe

        examples:
          identify capabilities in a binary
            capa suspicious.exe

          identify capabilities in 32-bit shellcode, see `-f` for all supported formats
            capa -f sc32 shellcode.bin

          report match locations
            capa -v suspicious.exe

          report all feature match details
            capa -vv suspicious.exe

          filter rules by meta fields, e.g. rule name or namespace
            capa -t "create TCP socket" suspicious.exe
         """
    )

    parser = argparse.ArgumentParser(
        description=desc, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    install_common_args(
        parser,
        {
            "input_file",
            "format",
            "backend",
            "os",
            "signatures",
            "rules",
            "tag",
            "restrict-to-functions",
            "restrict-to-processes",
        },
    )
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(args=argv)

    try:
        handle_common_args(args)
        ensure_input_exists_from_cli(args)
        input_format = get_input_format_from_cli(args)
        rules = get_rules_from_cli(args)
        found_file_limitation = False
        if input_format in STATIC_FORMATS:
            # only static extractors have file limitations
            file_extractors = get_file_extractors_from_cli(args, input_format)
            found_file_limitation = find_file_limitations_from_cli(args, rules, file_extractors)
    except ShouldExitError as e:
        return e.status_code

    meta: rdoc.Metadata
    capabilities: MatchResults
    counts: dict[str, Any]

    if input_format == FORMAT_RESULT:
        # result document directly parses into meta, capabilities
        result_doc = capa.render.result_document.ResultDocument.from_file(args.input_file)
        meta, capabilities = result_doc.to_capa()

    else:
        # all other formats we must create an extractor
        # and use that to extract meta and capabilities

        try:
            backend = get_backend_from_cli(args, input_format)
            sample_path = get_sample_path_from_cli(args, backend)
            if sample_path is None:
                os_ = "unknown"
            else:
                os_ = capa.loader.get_os(sample_path)
            extractor = get_extractor_from_cli(args, input_format, backend)
        except ShouldExitError as e:
            return e.status_code

        capabilities, counts = find_capabilities(rules, extractor, disable_progress=args.quiet)

        meta = capa.loader.collect_metadata(argv, args.input_file, input_format, os_, args.rules, extractor, counts)
        meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities)

        if isinstance(extractor, StaticFeatureExtractor) and found_file_limitation:
            # bail if capa's static feature extractor encountered file limitation e.g. a packed binary
            # do show the output in verbose mode, though.
            if not (args.verbose or args.vverbose or args.json):
                return E_FILE_LIMITATION

    if args.json:
        print(capa.render.json.render(meta, rules, capabilities))
    elif args.vverbose:
        print(capa.render.vverbose.render(meta, rules, capabilities))
    elif args.verbose:
        print(capa.render.verbose.render(meta, rules, capabilities))
    else:
        print(capa.render.default.render(meta, rules, capabilities))
    colorama.deinit()

    logger.debug("done.")

    return 0


def ida_main():
    import capa.rules
    import capa.ida.helpers
    import capa.render.default
    import capa.features.extractors.ida.extractor

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    if not capa.ida.helpers.is_supported_ida_version():
        return E_UNSUPPORTED_IDA_VERSION

    if not capa.ida.helpers.is_supported_file_type():
        return E_INVALID_FILE_TYPE

    logger.debug("-" * 80)
    logger.debug(" Using default embedded rules.")
    logger.debug(" ")
    logger.debug(" You can see the current default rule set here:")
    logger.debug("     https://github.com/mandiant/capa-rules")
    logger.debug("-" * 80)

    rules_path = get_default_root() / "rules"
    logger.debug("rule path: %s", rules_path)
    rules = capa.rules.get_rules([rules_path])

    meta = capa.ida.helpers.collect_metadata([rules_path])

    capabilities, counts = find_capabilities(rules, capa.features.extractors.ida.extractor.IdaFeatureExtractor())

    meta.analysis.feature_counts = counts["feature_counts"]
    meta.analysis.library_functions = counts["library_functions"]

    if has_file_limitation(rules, capabilities, is_standalone=False):
        capa.ida.helpers.inform_user_ida_ui("capa encountered warnings during analysis")

    colorama.init(strip=True)
    print(capa.render.default.render(meta, rules, capabilities))


def ghidra_main():
    import capa.rules
    import capa.ghidra.helpers
    import capa.render.default
    import capa.features.extractors.ghidra.extractor

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    logger.debug("-" * 80)
    logger.debug(" Using default embedded rules.")
    logger.debug(" ")
    logger.debug(" You can see the current default rule set here:")
    logger.debug("     https://github.com/mandiant/capa-rules")
    logger.debug("-" * 80)

    rules_path = get_default_root() / "rules"
    logger.debug("rule path: %s", rules_path)
    rules = capa.rules.get_rules([rules_path])

    meta = capa.ghidra.helpers.collect_metadata([rules_path])

    capabilities, counts = find_capabilities(
        rules,
        capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor(),
        not capa.ghidra.helpers.is_running_headless(),
    )

    meta.analysis.feature_counts = counts["feature_counts"]
    meta.analysis.library_functions = counts["library_functions"]

    if has_file_limitation(rules, capabilities, is_standalone=False):
        logger.info("capa encountered warnings during analysis")

    print(capa.render.default.render(meta, rules, capabilities))


if __name__ == "__main__":
    if capa.helpers.is_runtime_ida():
        ida_main()
    elif capa.helpers.is_runtime_ghidra():
        ghidra_main()
    else:
        sys.exit(main())
