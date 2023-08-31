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
import time
import hashlib
import logging
import argparse
import datetime
import textwrap
import itertools
import contextlib
import collections
from typing import Any, Dict, List, Tuple, Callable, Optional
from pathlib import Path

import halo
import tqdm
import colorama
import tqdm.contrib.logging
from pefile import PEFormatError
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
import capa.features.extractors.dnfile_
import capa.features.extractors.elffile
import capa.features.extractors.dotnetfile
import capa.features.extractors.base_extractor
from capa.rules import Rule, Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
from capa.helpers import (
    get_format,
    get_file_taste,
    get_auto_format,
    log_unsupported_os_error,
    redirecting_print_to_tqdm,
    log_unsupported_arch_error,
    log_unsupported_format_error,
)
from capa.exceptions import UnsupportedOSError, UnsupportedArchError, UnsupportedFormatError, UnsupportedRuntimeError
from capa.features.common import (
    OS_AUTO,
    OS_LINUX,
    OS_MACOS,
    FORMAT_PE,
    FORMAT_ELF,
    OS_WINDOWS,
    FORMAT_AUTO,
    FORMAT_SC32,
    FORMAT_SC64,
    FORMAT_DOTNET,
    FORMAT_FREEZE,
    FORMAT_RESULT,
)
from capa.features.address import NO_ADDRESS, Address
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, FeatureExtractor

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


def find_instruction_capabilities(
    ruleset: RuleSet, extractor: FeatureExtractor, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
) -> Tuple[FeatureSet, MatchResults]:
    """
    find matches for the given rules for the given instruction.

    returns: tuple containing (features for instruction, match results for instruction)
    """
    # all features found for the instruction.
    features = collections.defaultdict(set)  # type: FeatureSet

    for feature, addr in itertools.chain(
        extractor.extract_insn_features(f, bb, insn), extractor.extract_global_features()
    ):
        features[feature].add(addr)

    # matches found at this instruction.
    _, matches = ruleset.match(Scope.INSTRUCTION, features, insn.address)

    for rule_name, res in matches.items():
        rule = ruleset[rule_name]
        for addr, _ in res:
            capa.engine.index_rule_matches(features, rule, [addr])

    return features, matches


def find_basic_block_capabilities(
    ruleset: RuleSet, extractor: FeatureExtractor, f: FunctionHandle, bb: BBHandle
) -> Tuple[FeatureSet, MatchResults, MatchResults]:
    """
    find matches for the given rules within the given basic block.

    returns: tuple containing (features for basic block, match results for basic block, match results for instructions)
    """
    # all features found within this basic block,
    # includes features found within instructions.
    features = collections.defaultdict(set)  # type: FeatureSet

    # matches found at the instruction scope.
    # might be found at different instructions, thats ok.
    insn_matches = collections.defaultdict(list)  # type: MatchResults

    for insn in extractor.get_instructions(f, bb):
        ifeatures, imatches = find_instruction_capabilities(ruleset, extractor, f, bb, insn)
        for feature, vas in ifeatures.items():
            features[feature].update(vas)

        for rule_name, res in imatches.items():
            insn_matches[rule_name].extend(res)

    for feature, va in itertools.chain(
        extractor.extract_basic_block_features(f, bb), extractor.extract_global_features()
    ):
        features[feature].add(va)

    # matches found within this basic block.
    _, matches = ruleset.match(Scope.BASIC_BLOCK, features, bb.address)

    for rule_name, res in matches.items():
        rule = ruleset[rule_name]
        for va, _ in res:
            capa.engine.index_rule_matches(features, rule, [va])

    return features, matches, insn_matches


def find_code_capabilities(
    ruleset: RuleSet, extractor: FeatureExtractor, fh: FunctionHandle
) -> Tuple[MatchResults, MatchResults, MatchResults, int]:
    """
    find matches for the given rules within the given function.

    returns: tuple containing (match results for function, match results for basic blocks, match results for instructions, number of features)
    """
    # all features found within this function,
    # includes features found within basic blocks (and instructions).
    function_features = collections.defaultdict(set)  # type: FeatureSet

    # matches found at the basic block scope.
    # might be found at different basic blocks, thats ok.
    bb_matches = collections.defaultdict(list)  # type: MatchResults

    # matches found at the instruction scope.
    # might be found at different instructions, thats ok.
    insn_matches = collections.defaultdict(list)  # type: MatchResults

    for bb in extractor.get_basic_blocks(fh):
        features, bmatches, imatches = find_basic_block_capabilities(ruleset, extractor, fh, bb)
        for feature, vas in features.items():
            function_features[feature].update(vas)

        for rule_name, res in bmatches.items():
            bb_matches[rule_name].extend(res)

        for rule_name, res in imatches.items():
            insn_matches[rule_name].extend(res)

    for feature, va in itertools.chain(extractor.extract_function_features(fh), extractor.extract_global_features()):
        function_features[feature].add(va)

    _, function_matches = ruleset.match(Scope.FUNCTION, function_features, fh.address)
    return function_matches, bb_matches, insn_matches, len(function_features)


def find_file_capabilities(ruleset: RuleSet, extractor: FeatureExtractor, function_features: FeatureSet):
    file_features = collections.defaultdict(set)  # type: FeatureSet

    for feature, va in itertools.chain(extractor.extract_file_features(), extractor.extract_global_features()):
        # not all file features may have virtual addresses.
        # if not, then at least ensure the feature shows up in the index.
        # the set of addresses will still be empty.
        if va:
            file_features[feature].add(va)
        else:
            if feature not in file_features:
                file_features[feature] = set()

    logger.debug("analyzed file and extracted %d features", len(file_features))

    file_features.update(function_features)

    _, matches = ruleset.match(Scope.FILE, file_features, NO_ADDRESS)
    return matches, len(file_features)


def find_capabilities(ruleset: RuleSet, extractor: FeatureExtractor, disable_progress=None) -> Tuple[MatchResults, Any]:
    all_function_matches = collections.defaultdict(list)  # type: MatchResults
    all_bb_matches = collections.defaultdict(list)  # type: MatchResults
    all_insn_matches = collections.defaultdict(list)  # type: MatchResults

    feature_counts = rdoc.FeatureCounts(file=0, functions=())
    library_functions: Tuple[rdoc.LibraryFunction, ...] = ()

    with redirecting_print_to_tqdm(disable_progress):
        with tqdm.contrib.logging.logging_redirect_tqdm():
            pbar = tqdm.tqdm
            if capa.helpers.is_runtime_ghidra():
                # Ghidrathon interpreter cannot properly handle
                # the TMonitor thread that is created via a monitor_interval
                # > 0
                pbar.monitor_interval = 0
            if disable_progress:
                # do not use tqdm to avoid unnecessary side effects when caller intends
                # to disable progress completely
                def pbar(s, *args, **kwargs):
                    return s

            functions = list(extractor.get_functions())
            n_funcs = len(functions)

            pb = pbar(functions, desc="matching", unit=" functions", postfix="skipped 0 library functions", leave=False)
            for f in pb:
                t0 = time.time()
                if extractor.is_library_function(f.address):
                    function_name = extractor.get_function_name(f.address)
                    logger.debug("skipping library function 0x%x (%s)", f.address, function_name)
                    library_functions += (
                        rdoc.LibraryFunction(address=frz.Address.from_capa(f.address), name=function_name),
                    )
                    n_libs = len(library_functions)
                    percentage = round(100 * (n_libs / n_funcs))
                    if isinstance(pb, tqdm.tqdm):
                        pb.set_postfix_str(f"skipped {n_libs} library functions ({percentage}%)")
                    continue

                function_matches, bb_matches, insn_matches, feature_count = find_code_capabilities(
                    ruleset, extractor, f
                )
                feature_counts.functions += (
                    rdoc.FunctionFeatureCount(address=frz.Address.from_capa(f.address), count=feature_count),
                )
                t1 = time.time()

                match_count = sum(len(res) for res in function_matches.values())
                match_count += sum(len(res) for res in bb_matches.values())
                match_count += sum(len(res) for res in insn_matches.values())
                logger.debug(
                    "analyzed function 0x%x and extracted %d features, %d matches in %0.02fs",
                    f.address,
                    feature_count,
                    match_count,
                    t1 - t0,
                )

                for rule_name, res in function_matches.items():
                    all_function_matches[rule_name].extend(res)
                for rule_name, res in bb_matches.items():
                    all_bb_matches[rule_name].extend(res)
                for rule_name, res in insn_matches.items():
                    all_insn_matches[rule_name].extend(res)

    # collection of features that captures the rule matches within function, BB, and instruction scopes.
    # mapping from feature (matched rule) to set of addresses at which it matched.
    function_and_lower_features: FeatureSet = collections.defaultdict(set)
    for rule_name, results in itertools.chain(
        all_function_matches.items(), all_bb_matches.items(), all_insn_matches.items()
    ):
        locations = {p[0] for p in results}
        rule = ruleset[rule_name]
        capa.engine.index_rule_matches(function_and_lower_features, rule, locations)

    all_file_matches, feature_count = find_file_capabilities(ruleset, extractor, function_and_lower_features)
    feature_counts.file = feature_count

    matches = dict(
        itertools.chain(
            # each rule exists in exactly one scope,
            # so there won't be any overlap among these following MatchResults,
            # and we can merge the dictionaries naively.
            all_insn_matches.items(),
            all_bb_matches.items(),
            all_function_matches.items(),
            all_file_matches.items(),
        )
    )

    meta = {
        "feature_counts": feature_counts,
        "library_functions": library_functions,
    }

    return matches, meta


def has_rule_with_namespace(rules: RuleSet, capabilities: MatchResults, namespace: str) -> bool:
    return any(
        rules.rules[rule_name].meta.get("namespace", "").startswith(namespace) for rule_name in capabilities.keys()
    )


def is_internal_rule(rule: Rule) -> bool:
    return rule.meta.get("namespace", "").startswith("internal/")


def is_file_limitation_rule(rule: Rule) -> bool:
    return rule.meta.get("namespace", "") == "internal/limitation/file"


def has_file_limitation(rules: RuleSet, capabilities: MatchResults, is_standalone=True) -> bool:
    file_limitation_rules = list(filter(is_file_limitation_rule, rules.rules.values()))

    for file_limitation_rule in file_limitation_rules:
        if file_limitation_rule.name not in capabilities:
            continue

        logger.warning("-" * 80)
        for line in file_limitation_rule.meta.get("description", "").split("\n"):
            logger.warning(" %s", line)
        logger.warning(" Identified via rule: %s", file_limitation_rule.name)
        if is_standalone:
            logger.warning(" ")
            logger.warning(" Use -v or -vv if you really want to see the capabilities identified by capa.")
        logger.warning("-" * 80)

        # bail on first file limitation
        return True

    return False


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
    if format_ not in (FORMAT_SC32, FORMAT_SC64):
        if not is_supported_format(path):
            raise UnsupportedFormatError()

        if not is_supported_arch(path):
            raise UnsupportedArchError()

        if os_ == OS_AUTO and not is_supported_os(path):
            raise UnsupportedOSError()

    if format_ == FORMAT_DOTNET:
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
            from binaryninja import BinaryView, BinaryViewType
        except ImportError:
            raise RuntimeError(
                "Cannot import binaryninja module. Please install the Binary Ninja Python API first: "
                + "https://docs.binary.ninja/dev/batch.html#install-the-api)."
            )

        import capa.features.extractors.binja.extractor

        with halo.Halo(text="analyzing program", spinner="simpleDots", stream=sys.stderr, enabled=not disable_progress):
            bv: BinaryView = BinaryViewType.get_view_of_file(str(path))
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
        file_extractors.append(capa.features.extractors.dnfile_.DnfileFeatureExtractor(sample))

    elif format_ == capa.features.extractors.common.FORMAT_ELF:
        file_extractors.append(capa.features.extractors.elffile.ElfFeatureExtractor(sample))

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

    rules = []  # type: List[Rule]

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
            logger.debug("loaded rule: '%s' with scope: %s", rule.name, rule.scope)

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


def collect_metadata(
    argv: List[str],
    sample_path: Path,
    format_: str,
    os_: str,
    rules_path: List[Path],
    extractor: capa.features.extractors.base_extractor.FeatureExtractor,
) -> rdoc.Metadata:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    buf = sample_path.read_bytes()

    md5.update(buf)
    sha1.update(buf)
    sha256.update(buf)

    rules = tuple(r.resolve().absolute().as_posix() for r in rules_path)
    format_ = get_format(sample_path) if format_ == FORMAT_AUTO else format_
    arch = get_arch(sample_path)
    os_ = get_os(sample_path) if os_ == OS_AUTO else os_

    return rdoc.Metadata(
        timestamp=datetime.datetime.now(),
        version=capa.version.__version__,
        argv=tuple(argv) if argv else None,
        sample=rdoc.Sample(
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
            path=sample_path.resolve().absolute().as_posix(),
        ),
        analysis=rdoc.Analysis(
            format=format_,
            arch=arch,
            os=os_,
            extractor=extractor.__class__.__name__,
            rules=rules,
            base_address=frz.Address.from_capa(extractor.get_base_address()),
            layout=rdoc.Layout(
                functions=(),
                # this is updated after capabilities have been collected.
                # will look like:
                #
                # "functions": { 0x401000: { "matched_basic_blocks": [ 0x401000, 0x401005, ... ] }, ... }
            ),
            feature_counts=rdoc.FeatureCounts(file=0, functions=()),
            library_functions=(),
        ),
    )


def compute_layout(rules, extractor, capabilities) -> rdoc.Layout:
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
        if rule.meta.get("scope") == capa.rules.BASIC_BLOCK_SCOPE:
            for addr, _ in matches:
                assert addr in functions_by_bb
                matched_bbs.add(addr)

    layout = rdoc.Layout(
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
            len(list(filter(lambda r: not r.is_subscope_rule(), rules.rules.values()))),
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

    for file_extractor in file_extractors:
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
        if has_file_limitation(rules, pure_file_capabilities):
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
            extractor = frz.load(Path(args.sample).read_bytes())
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
            except UnsupportedFormatError:
                log_unsupported_format_error()
                return E_INVALID_FILE_TYPE
            except UnsupportedArchError:
                log_unsupported_arch_error()
                return E_INVALID_FILE_ARCH
            except UnsupportedOSError:
                log_unsupported_os_error()
                return E_INVALID_FILE_OS

        meta = collect_metadata(argv, args.sample, args.format, args.os, args.rules, extractor)

        capabilities, counts = find_capabilities(rules, extractor, disable_progress=args.quiet)

        meta.analysis.feature_counts = counts["feature_counts"]
        meta.analysis.library_functions = counts["library_functions"]
        meta.analysis.layout = compute_layout(rules, extractor, capabilities)

        if has_file_limitation(rules, capabilities):
            # bail if capa encountered file limitation e.g. a packed binary
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
