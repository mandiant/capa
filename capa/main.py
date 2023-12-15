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
import io
import os
import sys
import json
import time
import logging
import argparse
import datetime
import textwrap
import contextlib
from types import TracebackType
from typing import Any, Set, Dict, List, Callable, Optional
from pathlib import Path

import halo
import colorama
from pefile import PEFormatError
from typing_extensions import assert_never
from elftools.common.exceptions import ELFError

import capa.perf
import capa.rules
import capa.engine
import capa.helpers
import capa.version
import capa.render.json
import capa.rules.cache
import capa.render.default
import capa.render.verbose
import capa.features.common
import capa.features.freeze as frz
import capa.render.vverbose
import capa.features.extractors
import capa.render.result_document
import capa.render.result_document as rdoc
import capa.features.extractors.common
import capa.features.extractors.pefile
import capa.features.extractors.elffile
import capa.features.extractors.dotnetfile
import capa.features.extractors.base_extractor
import capa.features.extractors.cape.extractor
from capa.rules import Rule, RuleSet
from capa.engine import MatchResults
from capa.helpers import (
    get_file_taste,
    get_auto_format,
    log_unsupported_os_error,
    log_unsupported_arch_error,
    log_empty_cape_report_error,
    log_unsupported_format_error,
    log_unsupported_cape_report_error,
)
from capa.exceptions import (
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
    FORMAT_DOTNET,
    FORMAT_FREEZE,
    FORMAT_RESULT,
)
from capa.features.address import Address
from capa.capabilities.common import find_capabilities, has_file_limitation, find_file_capabilities
from capa.features.extractors.base_extractor import (
    SampleHashes,
    FeatureExtractor,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)

RULES_PATH_DEFAULT_STRING = "(embedded rules)"
SIGNATURES_PATH_DEFAULT_STRING = "(embedded signatures)"
BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"

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

logger = logging.getLogger("capa")


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


def is_supported_format(sample: Path) -> bool:
    """
    Return if this is a supported file based on magic header values
    """
    taste = sample.open("rb").read(0x100)

    return len(list(capa.features.extractors.common.extract_format(taste))) == 1


def is_supported_arch(sample: Path) -> bool:
    buf = sample.read_bytes()

    return len(list(capa.features.extractors.common.extract_arch(buf))) == 1


def get_arch(sample: Path) -> str:
    buf = sample.read_bytes()

    for feature, _ in capa.features.extractors.common.extract_arch(buf):
        assert isinstance(feature.value, str)
        return feature.value

    return "unknown"


def is_supported_os(sample: Path) -> bool:
    buf = sample.read_bytes()

    return len(list(capa.features.extractors.common.extract_os(buf))) == 1


def get_os(sample: Path) -> str:
    buf = sample.read_bytes()

    for feature, _ in capa.features.extractors.common.extract_os(buf):
        assert isinstance(feature.value, str)
        return feature.value

    return "unknown"


def get_meta_str(vw):
    """
    Return workspace meta information string
    """
    meta = []
    for k in ["Format", "Platform", "Architecture"]:
        if k in vw.metadata:
            meta.append(f"{k.lower()}: {vw.metadata[k]}")
    return f"{', '.join(meta)}, number of functions: {len(vw.getFunctions())}"


def is_running_standalone() -> bool:
    """
    are we running from a PyInstaller'd executable?
    if so, then we'll be able to access `sys._MEIPASS` for the packaged resources.
    """
    return hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS")


def get_default_root() -> Path:
    """
    get the file system path to the default resources directory.
    under PyInstaller, this comes from _MEIPASS.
    under source, this is the root directory of the project.
    """
    if is_running_standalone():
        # pylance/mypy don't like `sys._MEIPASS` because this isn't standard.
        # its injected by pyinstaller.
        # so we'll fetch this attribute dynamically.
        assert hasattr(sys, "_MEIPASS")
        return Path(sys._MEIPASS)
    else:
        return Path(__file__).resolve().parent.parent


def get_default_signatures() -> List[Path]:
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


def get_workspace(path: Path, format_: str, sigpaths: List[Path]):
    """
    load the program at the given path into a vivisect workspace using the given format.
    also apply the given FLIRT signatures.

    supported formats:
      - pe
      - elf
      - shellcode 32-bit
      - shellcode 64-bit
      - auto

    this creates and analyzes the workspace; however, it does *not* save the workspace.
    this is the responsibility of the caller.
    """

    # lazy import enables us to not require viv if user wants SMDA, for example.
    import viv_utils
    import viv_utils.flirt

    logger.debug("generating vivisect workspace for: %s", path)
    if format_ == FORMAT_AUTO:
        if not is_supported_format(path):
            raise UnsupportedFormatError()

        # don't analyze, so that we can add our Flirt function analyzer first.
        vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    elif format_ in {FORMAT_PE, FORMAT_ELF}:
        vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    elif format_ == FORMAT_SC32:
        # these are not analyzed nor saved.
        vw = viv_utils.getShellcodeWorkspaceFromFile(str(path), arch="i386", analyze=False)
    elif format_ == FORMAT_SC64:
        vw = viv_utils.getShellcodeWorkspaceFromFile(str(path), arch="amd64", analyze=False)
    else:
        raise ValueError("unexpected format: " + format_)

    viv_utils.flirt.register_flirt_signature_analyzers(vw, [str(s) for s in sigpaths])

    vw.analyze()

    logger.debug("%s", get_meta_str(vw))
    return vw


def get_extractor(
    path: Path,
    format_: str,
    os_: str,
    backend: str,
    sigpaths: List[Path],
    should_save_workspace=False,
    disable_progress=False,
) -> FeatureExtractor:
    """
    raises:
      UnsupportedFormatError
      UnsupportedArchError
      UnsupportedOSError
    """

    if format_ not in (FORMAT_SC32, FORMAT_SC64, FORMAT_CAPE):
        if not is_supported_format(path):
            raise UnsupportedFormatError()

        if not is_supported_arch(path):
            raise UnsupportedArchError()

        if os_ == OS_AUTO and not is_supported_os(path):
            raise UnsupportedOSError()

    if format_ == FORMAT_CAPE:
        import capa.features.extractors.cape.extractor

        report = json.load(Path(path).open(encoding="utf-8"))
        return capa.features.extractors.cape.extractor.CapeExtractor.from_report(report)

    elif format_ == FORMAT_DOTNET:
        import capa.features.extractors.dnfile.extractor

        return capa.features.extractors.dnfile.extractor.DnfileFeatureExtractor(path)

    elif backend == BACKEND_BINJA:
        from capa.features.extractors.binja.find_binja_api import find_binja_path

        # When we are running as a standalone executable, we cannot directly import binaryninja
        # We need to fist find the binja API installation path and add it into sys.path
        if is_running_standalone():
            bn_api = find_binja_path()
            if bn_api.exists():
                sys.path.append(str(bn_api))

        try:
            import binaryninja
            from binaryninja import BinaryView
        except ImportError:
            raise RuntimeError(
                "Cannot import binaryninja module. Please install the Binary Ninja Python API first: "
                + "https://docs.binary.ninja/dev/batch.html#install-the-api)."
            )

        import capa.features.extractors.binja.extractor

        with halo.Halo(text="analyzing program", spinner="simpleDots", stream=sys.stderr, enabled=not disable_progress):
            bv: BinaryView = binaryninja.load(str(path))
            if bv is None:
                raise RuntimeError(f"Binary Ninja cannot open file {path}")

        return capa.features.extractors.binja.extractor.BinjaFeatureExtractor(bv)

    elif backend == BACKEND_PEFILE:
        import capa.features.extractors.pefile

        return capa.features.extractors.pefile.PefileFeatureExtractor(path)

    elif backend == BACKEND_VIV:
        import capa.features.extractors.viv.extractor

        with halo.Halo(text="analyzing program", spinner="simpleDots", stream=sys.stderr, enabled=not disable_progress):
            vw = get_workspace(path, format_, sigpaths)

            if should_save_workspace:
                logger.debug("saving workspace")
                try:
                    vw.saveWorkspace()
                except IOError:
                    # see #168 for discussion around how to handle non-writable directories
                    logger.info("source directory is not writable, won't save intermediate workspace")
            else:
                logger.debug("CAPA_SAVE_WORKSPACE unset, not saving workspace")

        return capa.features.extractors.viv.extractor.VivisectFeatureExtractor(vw, path, os_)

    else:
        raise ValueError("unexpected backend: " + backend)


def get_file_extractors(sample: Path, format_: str) -> List[FeatureExtractor]:
    file_extractors: List[FeatureExtractor] = []

    if format_ == FORMAT_PE:
        file_extractors.append(capa.features.extractors.pefile.PefileFeatureExtractor(sample))

    elif format_ == FORMAT_DOTNET:
        file_extractors.append(capa.features.extractors.pefile.PefileFeatureExtractor(sample))
        file_extractors.append(capa.features.extractors.dotnetfile.DotnetFileFeatureExtractor(sample))

    elif format_ == capa.features.common.FORMAT_ELF:
        file_extractors.append(capa.features.extractors.elffile.ElfFeatureExtractor(sample))

    elif format_ == FORMAT_CAPE:
        report = json.load(Path(sample).open(encoding="utf-8"))
        file_extractors.append(capa.features.extractors.cape.extractor.CapeExtractor.from_report(report))

    return file_extractors


def is_nursery_rule_path(path: Path) -> bool:
    """
    The nursery is a spot for rules that have not yet been fully polished.
    For example, they may not have references to public example of a technique.
    Yet, we still want to capture and report on their matches.
    The nursery is currently a subdirectory of the rules directory with that name.

    When nursery rules are loaded, their metadata section should be updated with:
      `nursery=True`.
    """
    return "nursery" in path.parts


def collect_rule_file_paths(rule_paths: List[Path]) -> List[Path]:
    """
    collect all rule file paths, including those in subdirectories.
    """
    rule_file_paths = []
    for rule_path in rule_paths:
        if not rule_path.exists():
            raise IOError(f"rule path {rule_path} does not exist or cannot be accessed")

        if rule_path.is_file():
            rule_file_paths.append(rule_path)
        elif rule_path.is_dir():
            logger.debug("reading rules from directory %s", rule_path)
            for root, _, files in os.walk(rule_path):
                if ".git" in root:
                    # the .github directory contains CI config in capa-rules
                    # this includes some .yml files
                    # these are not rules
                    # additionally, .git has files that are not .yml and generate the warning
                    # skip those too
                    continue
                for file in files:
                    if not file.endswith(".yml"):
                        if not (file.startswith(".git") or file.endswith((".git", ".md", ".txt"))):
                            # expect to see .git* files, readme.md, format.md, and maybe a .git directory
                            # other things maybe are rules, but are mis-named.
                            logger.warning("skipping non-.yml file: %s", file)
                        continue
                    rule_file_paths.append(Path(root) / file)
    return rule_file_paths


# TypeAlias. note: using `foo: TypeAlias = bar` is Python 3.10+
RulePath = Path


def on_load_rule_default(_path: RulePath, i: int, _total: int) -> None:
    return


def get_rules(
    rule_paths: List[RulePath],
    cache_dir=None,
    on_load_rule: Callable[[RulePath, int, int], None] = on_load_rule_default,
) -> RuleSet:
    """
    args:
      rule_paths: list of paths to rules files or directories containing rules files
      cache_dir: directory to use for caching rules, or will use the default detected cache directory if None
      on_load_rule: callback to invoke before a rule is loaded, use for progress or cancellation
    """
    if cache_dir is None:
        cache_dir = capa.rules.cache.get_default_cache_directory()
    # rule_paths may contain directory paths,
    # so search for file paths recursively.
    rule_file_paths = collect_rule_file_paths(rule_paths)

    # this list is parallel to `rule_file_paths`:
    # rule_file_paths[i] corresponds to rule_contents[i].
    rule_contents = [file_path.read_bytes() for file_path in rule_file_paths]

    ruleset = capa.rules.cache.load_cached_ruleset(cache_dir, rule_contents)
    if ruleset is not None:
        return ruleset

    rules: List[Rule] = []

    total_rule_count = len(rule_file_paths)
    for i, (path, content) in enumerate(zip(rule_file_paths, rule_contents)):
        on_load_rule(path, i, total_rule_count)

        try:
            rule = capa.rules.Rule.from_yaml(content.decode("utf-8"))
        except capa.rules.InvalidRule:
            raise
        else:
            rule.meta["capa/path"] = path.as_posix()
            rule.meta["capa/nursery"] = is_nursery_rule_path(path)

            rules.append(rule)
            logger.debug("loaded rule: '%s' with scope: %s", rule.name, rule.scopes)

    ruleset = capa.rules.RuleSet(rules)

    capa.rules.cache.cache_ruleset(cache_dir, ruleset)

    return ruleset


def get_signatures(sigs_path: Path) -> List[Path]:
    if not sigs_path.exists():
        raise IOError(f"signatures path {sigs_path} does not exist or cannot be accessed")

    paths: List[Path] = []
    if sigs_path.is_file():
        paths.append(sigs_path)
    elif sigs_path.is_dir():
        logger.debug("reading signatures from directory %s", sigs_path.resolve())
        for file in sigs_path.rglob("*"):
            if file.is_file() and file.suffix.lower() in (".pat", ".pat.gz", ".sig"):
                paths.append(file)

    # Convert paths to their absolute and normalized forms
    paths = [path.resolve().absolute() for path in paths]

    # load signatures in deterministic order: the alphabetic sorting of filename.
    # this means that `0_sigs.pat` loads before `1_sigs.pat`.
    paths = sorted(paths, key=lambda path: path.name)

    for path in paths:
        logger.debug("found signature file: %s", path)

    return paths


def get_sample_analysis(format_, arch, os_, extractor, rules_path, counts):
    if isinstance(extractor, StaticFeatureExtractor):
        return rdoc.StaticAnalysis(
            format=format_,
            arch=arch,
            os=os_,
            extractor=extractor.__class__.__name__,
            rules=tuple(rules_path),
            base_address=frz.Address.from_capa(extractor.get_base_address()),
            layout=rdoc.StaticLayout(
                functions=(),
                # this is updated after capabilities have been collected.
                # will look like:
                #
                # "functions": { 0x401000: { "matched_basic_blocks": [ 0x401000, 0x401005, ... ] }, ... }
            ),
            feature_counts=counts["feature_counts"],
            library_functions=counts["library_functions"],
        )
    elif isinstance(extractor, DynamicFeatureExtractor):
        return rdoc.DynamicAnalysis(
            format=format_,
            arch=arch,
            os=os_,
            extractor=extractor.__class__.__name__,
            rules=tuple(rules_path),
            layout=rdoc.DynamicLayout(
                processes=(),
            ),
            feature_counts=counts["feature_counts"],
        )
    else:
        raise ValueError("invalid extractor type")


def collect_metadata(
    argv: List[str],
    sample_path: Path,
    format_: str,
    os_: str,
    rules_path: List[Path],
    extractor: FeatureExtractor,
    counts: dict,
) -> rdoc.Metadata:
    # if it's a binary sample we hash it, if it's a report
    # we fetch the hashes from the report
    sample_hashes: SampleHashes = extractor.get_sample_hashes()
    md5, sha1, sha256 = sample_hashes.md5, sample_hashes.sha1, sample_hashes.sha256

    global_feats = list(extractor.extract_global_features())
    extractor_format = [f.value for (f, _) in global_feats if isinstance(f, capa.features.common.Format)]
    extractor_arch = [f.value for (f, _) in global_feats if isinstance(f, capa.features.common.Arch)]
    extractor_os = [f.value for (f, _) in global_feats if isinstance(f, capa.features.common.OS)]

    format_ = str(extractor_format[0]) if extractor_format else "unknown" if format_ == FORMAT_AUTO else format_
    arch = str(extractor_arch[0]) if extractor_arch else "unknown"
    os_ = str(extractor_os[0]) if extractor_os else "unknown" if os_ == OS_AUTO else os_

    if isinstance(extractor, StaticFeatureExtractor):
        meta_class: type = rdoc.StaticMetadata
    elif isinstance(extractor, DynamicFeatureExtractor):
        meta_class = rdoc.DynamicMetadata
    else:
        assert_never(extractor)

    rules = tuple(r.resolve().absolute().as_posix() for r in rules_path)

    return meta_class(
        timestamp=datetime.datetime.now(),
        version=capa.version.__version__,
        argv=tuple(argv) if argv else None,
        sample=rdoc.Sample(
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            path=Path(sample_path).resolve().as_posix(),
        ),
        analysis=get_sample_analysis(
            format_,
            arch,
            os_,
            extractor,
            rules,
            counts,
        ),
    )


def compute_dynamic_layout(rules, extractor: DynamicFeatureExtractor, capabilities: MatchResults) -> rdoc.DynamicLayout:
    """
    compute a metadata structure that links threads
    to the processes in which they're found.

    only collect the threads at which some rule matched.
    otherwise, we may pollute the json document with
    a large amount of un-referenced data.
    """
    assert isinstance(extractor, DynamicFeatureExtractor)

    matched_calls: Set[Address] = set()

    def result_rec(result: capa.features.common.Result):
        for loc in result.locations:
            if isinstance(loc, capa.features.address.DynamicCallAddress):
                matched_calls.add(loc)
        for child in result.children:
            result_rec(child)

    for matches in capabilities.values():
        for _, result in matches:
            result_rec(result)

    names_by_process: Dict[Address, str] = {}
    names_by_call: Dict[Address, str] = {}

    matched_processes: Set[Address] = set()
    matched_threads: Set[Address] = set()

    threads_by_process: Dict[Address, List[Address]] = {}
    calls_by_thread: Dict[Address, List[Address]] = {}

    for p in extractor.get_processes():
        threads_by_process[p.address] = []

        for t in extractor.get_threads(p):
            calls_by_thread[t.address] = []

            for c in extractor.get_calls(p, t):
                if c.address in matched_calls:
                    names_by_call[c.address] = extractor.get_call_name(p, t, c)
                    calls_by_thread[t.address].append(c.address)

            if calls_by_thread[t.address]:
                matched_threads.add(t.address)
                threads_by_process[p.address].append(t.address)

        if threads_by_process[p.address]:
            matched_processes.add(p.address)
            names_by_process[p.address] = extractor.get_process_name(p)

    layout = rdoc.DynamicLayout(
        processes=tuple(
            rdoc.ProcessLayout(
                address=frz.Address.from_capa(p),
                name=names_by_process[p],
                matched_threads=tuple(
                    rdoc.ThreadLayout(
                        address=frz.Address.from_capa(t),
                        matched_calls=tuple(
                            rdoc.CallLayout(
                                address=frz.Address.from_capa(c),
                                name=names_by_call[c],
                            )
                            for c in calls_by_thread[t]
                            if c in matched_calls
                        ),
                    )
                    for t in threads
                    if t in matched_threads
                )  # this object is open to extension in the future,
                # such as with the function name, etc.
            )
            for p, threads in threads_by_process.items()
            if p in matched_processes
        )
    )

    return layout


def compute_static_layout(rules, extractor: StaticFeatureExtractor, capabilities) -> rdoc.StaticLayout:
    """
    compute a metadata structure that links basic blocks
    to the functions in which they're found.

    only collect the basic blocks at which some rule matched.
    otherwise, we may pollute the json document with
    a large amount of un-referenced data.
    """
    functions_by_bb: Dict[Address, Address] = {}
    bbs_by_function: Dict[Address, List[Address]] = {}
    for f in extractor.get_functions():
        bbs_by_function[f.address] = []
        for bb in extractor.get_basic_blocks(f):
            functions_by_bb[bb.address] = f.address
            bbs_by_function[f.address].append(bb.address)

    matched_bbs = set()
    for rule_name, matches in capabilities.items():
        rule = rules[rule_name]
        if capa.rules.Scope.BASIC_BLOCK in rule.scopes:
            for addr, _ in matches:
                assert addr in functions_by_bb
                matched_bbs.add(addr)

    layout = rdoc.StaticLayout(
        functions=tuple(
            rdoc.FunctionLayout(
                address=frz.Address.from_capa(f),
                matched_basic_blocks=tuple(
                    rdoc.BasicBlockLayout(address=frz.Address.from_capa(bb)) for bb in bbs if bb in matched_bbs
                )  # this object is open to extension in the future,
                # such as with the function name, etc.
            )
            for f, bbs in bbs_by_function.items()
            if len([bb for bb in bbs if bb in matched_bbs]) > 0
        )
    )

    return layout


def compute_layout(rules, extractor, capabilities) -> rdoc.Layout:
    if isinstance(extractor, StaticFeatureExtractor):
        return compute_static_layout(rules, extractor, capabilities)
    elif isinstance(extractor, DynamicFeatureExtractor):
        return compute_dynamic_layout(rules, extractor, capabilities)
    else:
        raise ValueError("extractor must be either a static or dynamic extracotr")


def install_common_args(parser, wanted=None):
    """
    register a common set of command line arguments for re-use by main & scripts.
    these are things like logging/coloring/etc.
    also enable callers to opt-in to common arguments, like specifying the input sample.

    this routine lets many script use the same language for cli arguments.
    see `handle_common_args` to do common configuration.

    args:
      parser (argparse.ArgumentParser): a parser to update in place, adding common arguments.
      wanted (Set[str]): collection of arguments to opt-into, including:
        - "sample": required positional argument to input file.
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

    #
    # arguments that may be opted into:
    #
    #   - sample
    #   - format
    #   - os
    #   - rules
    #   - tag
    #

    if "sample" in wanted:
        parser.add_argument(
            "sample",
            type=str,
            help="path to sample to analyze",
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
            (FORMAT_FREEZE, "features previously frozen by capa"),
        ]
        format_help = ", ".join([f"{f[0]}: {f[1]}" for f in formats])
        parser.add_argument(
            "-f",
            "--format",
            choices=[f[0] for f in formats],
            default=FORMAT_AUTO,
            help=f"select sample format, {format_help}",
        )

    if "backend" in wanted:
        parser.add_argument(
            "-b",
            "--backend",
            type=str,
            help="select the backend to use",
            choices=(BACKEND_VIV, BACKEND_BINJA, BACKEND_PEFILE),
            default=BACKEND_VIV,
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


def handle_common_args(args):
    """
    handle the global config specified by `install_common_args`,
    such as configuring logging/coloring/etc.
    the following fields will be overwritten when present:
      - rules: file system path to rule files.
      - signatures: file system path to signature files.

    the following field may be added:
      - is_default_rules: if the default rules were used.

    args:
      args (argparse.Namespace): parsed arguments that included at least `install_common_args` args.
    """
    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

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

    if hasattr(args, "sample"):
        args.sample = Path(args.sample)

    if hasattr(args, "rules"):
        rules_paths: List[Path] = []

        if args.rules == [RULES_PATH_DEFAULT_STRING]:
            logger.debug("-" * 80)
            logger.debug(" Using default embedded rules.")
            logger.debug(" To provide your own rules, use the form `capa.exe -r ./path/to/rules/  /path/to/mal.exe`.")
            logger.debug(" You can see the current default rule set here:")
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
                return E_MISSING_RULES

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
            logger.debug("-" * 80)
            logger.debug(" Using default embedded signatures.")
            logger.debug(
                " To provide your own signatures, use the form `capa.exe --signature ./path/to/signatures/  /path/to/mal.exe`."
            )
            logger.debug("-" * 80)

            sigs_path = get_default_root() / "sigs"

            if not sigs_path.exists():
                logger.error(
                    "Using default signature path, but it doesn't exist. "  # noqa: G003 [logging statement uses +]
                    + "Please install the signatures first: "
                    + "https://github.com/mandiant/capa/blob/master/doc/installation.md#method-2-using-capa-as-a-python-library."
                )
                raise IOError(f"signatures path {sigs_path} does not exist or cannot be accessed")
        else:
            sigs_path = Path(args.signatures)
            logger.debug("using signatures path: %s", sigs_path)

        args.signatures = sigs_path


def simple_message_exception_handler(exctype, value: BaseException, traceback: TracebackType):
    """
    prints friendly message on unexpected exceptions to regular users (debug mode shows regular stack trace)

    args:
      # TODO(aaronatp): Once capa drops support for Python 3.8, move the exctype type annotation to
      # the function parameters and remove the "# type: ignore[assignment]" from the relevant place
      # in the main function, see (https://github.com/mandiant/capa/issues/1896)
      exctype (type[BaseException]): exception class
    """

    if exctype is KeyboardInterrupt:
        print("KeyboardInterrupt detected, program terminated")
    else:
        print(
            f"Unexpected exception raised: {exctype}. Please run capa in debug mode (-d/--debug) "
            + "to see the stack trace. Please also report your issue on the capa GitHub page so we "
            + "can improve the code! (https://github.com/mandiant/capa/issues)"
        )


def main(argv: Optional[List[str]] = None):
    if sys.version_info < (3, 8):
        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.8+")

    if argv is None:
        argv = sys.argv[1:]

    desc = "The FLARE team's open-source tool to identify capabilities in executable files."
    epilog = textwrap.dedent(
        """
        By default, capa uses a default set of embedded rules.
        You can see the rule set here:
          https://github.com/mandiant/capa-rules

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
    install_common_args(parser, {"sample", "format", "backend", "os", "signatures", "rules", "tag"})
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(args=argv)
    if not args.debug:
        sys.excepthook = simple_message_exception_handler  # type: ignore[assignment]
    ret = handle_common_args(args)
    if ret is not None and ret != 0:
        return ret

    try:
        _ = get_file_taste(args.sample)
    except IOError as e:
        # per our research there's not a programmatic way to render the IOError with non-ASCII filename unless we
        # handle the IOError separately and reach into the args
        logger.error("%s", e.args[0])
        return E_MISSING_FILE

    format_ = args.format
    if format_ == FORMAT_AUTO:
        try:
            format_ = get_auto_format(args.sample)
        except PEFormatError as e:
            logger.error("Input file '%s' is not a valid PE file: %s", args.sample, str(e))
            return E_CORRUPT_FILE
        except UnsupportedFormatError:
            log_unsupported_format_error()
            return E_INVALID_FILE_TYPE

    try:
        if is_running_standalone() and args.is_default_rules:
            cache_dir = get_default_root() / "cache"
        else:
            cache_dir = capa.rules.cache.get_default_cache_directory()

        rules = get_rules(args.rules, cache_dir=cache_dir)

        logger.debug(
            "successfully loaded %s rules",
            # during the load of the RuleSet, we extract subscope statements into their own rules
            # that are subsequently `match`ed upon. this inflates the total rule count.
            # so, filter out the subscope rules when reporting total number of loaded rules.
            len(list(filter(lambda r: not (r.is_subscope_rule()), rules.rules.values()))),
        )
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.debug("selected %d rules", len(rules))
            for i, r in enumerate(rules.rules, 1):
                logger.debug(" %d. %s", i, r)

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
        return E_INVALID_RULE

    # file feature extractors are pretty lightweight: they don't do any code analysis.
    # so we can fairly quickly determine if the given file has "pure" file-scope rules
    # that indicate a limitation (like "file is packed based on section names")
    # and avoid doing a full code analysis on difficult/impossible binaries.
    #
    # this pass can inspect multiple file extractors, e.g., dotnet and pe to identify
    # various limitations
    try:
        file_extractors = get_file_extractors(args.sample, format_)
    except PEFormatError as e:
        logger.error("Input file '%s' is not a valid PE file: %s", args.sample, str(e))
        return E_CORRUPT_FILE
    except (ELFError, OverflowError) as e:
        logger.error("Input file '%s' is not a valid ELF file: %s", args.sample, str(e))
        return E_CORRUPT_FILE
    except UnsupportedFormatError as e:
        if format_ == FORMAT_CAPE:
            log_unsupported_cape_report_error(str(e))
        else:
            log_unsupported_format_error()
        return E_INVALID_FILE_TYPE
    except EmptyReportError as e:
        if format_ == FORMAT_CAPE:
            log_empty_cape_report_error(str(e))
            return E_EMPTY_REPORT
        else:
            log_unsupported_format_error()
            return E_INVALID_FILE_TYPE

    found_file_limitation = False
    for file_extractor in file_extractors:
        if isinstance(file_extractor, DynamicFeatureExtractor):
            # Dynamic feature extractors can handle packed samples
            continue

        try:
            pure_file_capabilities, _ = find_file_capabilities(rules, file_extractor, {})
        except PEFormatError as e:
            logger.error("Input file '%s' is not a valid PE file: %s", args.sample, str(e))
            return E_CORRUPT_FILE
        except (ELFError, OverflowError) as e:
            logger.error("Input file '%s' is not a valid ELF file: %s", args.sample, str(e))
            return E_CORRUPT_FILE

        # file limitations that rely on non-file scope won't be detected here.
        # nor on FunctionName features, because pefile doesn't support this.
        found_file_limitation = has_file_limitation(rules, pure_file_capabilities)
        if found_file_limitation:
            # bail if capa encountered file limitation e.g. a packed binary
            # do show the output in verbose mode, though.
            if not (args.verbose or args.vverbose or args.json):
                logger.debug("file limitation short circuit, won't analyze fully.")
                return E_FILE_LIMITATION

    meta: rdoc.Metadata
    capabilities: MatchResults
    counts: Dict[str, Any]

    if format_ == FORMAT_RESULT:
        # result document directly parses into meta, capabilities
        result_doc = capa.render.result_document.ResultDocument.from_file(Path(args.sample))
        meta, capabilities = result_doc.to_capa()

    else:
        # all other formats we must create an extractor
        # and use that to extract meta and capabilities

        if format_ == FORMAT_FREEZE:
            # freeze format deserializes directly into an extractor
            extractor: FeatureExtractor = frz.load(Path(args.sample).read_bytes())
        else:
            # all other formats we must create an extractor,
            # such as viv, binary ninja, etc. workspaces
            # and use those for extracting.

            try:
                if format_ == FORMAT_PE:
                    sig_paths = get_signatures(args.signatures)
                else:
                    sig_paths = []
                    logger.debug("skipping library code matching: only have native PE signatures")
            except IOError as e:
                logger.error("%s", str(e))
                return E_INVALID_SIG

            should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)

            # TODO(mr-tz): this should be wrapped and refactored as it's tedious to update everywhere
            #  see same code and show-features above examples
            #  https://github.com/mandiant/capa/issues/1813
            try:
                extractor = get_extractor(
                    args.sample,
                    format_,
                    args.os,
                    args.backend,
                    sig_paths,
                    should_save_workspace,
                    disable_progress=args.quiet or args.debug,
                )
            except UnsupportedFormatError as e:
                if format_ == FORMAT_CAPE:
                    log_unsupported_cape_report_error(str(e))
                else:
                    log_unsupported_format_error()
                return E_INVALID_FILE_TYPE
            except UnsupportedArchError:
                log_unsupported_arch_error()
                return E_INVALID_FILE_ARCH
            except UnsupportedOSError:
                log_unsupported_os_error()
                return E_INVALID_FILE_OS

        capabilities, counts = find_capabilities(rules, extractor, disable_progress=args.quiet)

        meta = collect_metadata(argv, args.sample, args.format, args.os, args.rules, extractor, counts)
        meta.analysis.layout = compute_layout(rules, extractor, capabilities)

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
    rules = get_rules([rules_path])

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
    rules = get_rules([rules_path])

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
