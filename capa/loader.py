# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import os
import sys
import logging
import datetime
import contextlib
from typing import Set, Dict, List, Optional
from pathlib import Path

from rich.console import Console
from typing_extensions import assert_never

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
import capa.features.extractors.base_extractor
import capa.features.extractors.cape.extractor
from capa.rules import RuleSet
from capa.engine import MatchResults
from capa.exceptions import UnsupportedOSError, UnsupportedArchError, UnsupportedFormatError
from capa.features.common import (
    OS_AUTO,
    FORMAT_PE,
    FORMAT_ELF,
    FORMAT_AUTO,
    FORMAT_CAPE,
    FORMAT_SC32,
    FORMAT_SC64,
    FORMAT_VMRAY,
    FORMAT_DOTNET,
    FORMAT_DRAKVUF,
    FORMAT_BINEXPORT2,
)
from capa.features.address import Address
from capa.features.extractors.base_extractor import (
    SampleHashes,
    FeatureExtractor,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)

logger = logging.getLogger(__name__)

BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"
BACKEND_CAPE = "cape"
BACKEND_DRAKVUF = "drakvuf"
BACKEND_VMRAY = "vmray"
BACKEND_FREEZE = "freeze"
BACKEND_BINEXPORT2 = "binexport2"


class CorruptFile(ValueError):
    pass


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


def get_workspace(path: Path, input_format: str, sigpaths: List[Path]):
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

    # lazy import enables us to not require viv if user wants another backend.
    import viv_utils
    import viv_utils.flirt

    logger.debug("generating vivisect workspace for: %s", path)

    try:
        if input_format == FORMAT_AUTO:
            if not is_supported_format(path):
                raise UnsupportedFormatError()

            # don't analyze, so that we can add our Flirt function analyzer first.
            vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
        elif input_format in {FORMAT_PE, FORMAT_ELF}:
            vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
        elif input_format == FORMAT_SC32:
            # these are not analyzed nor saved.
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(path), arch="i386", analyze=False)
        elif input_format == FORMAT_SC64:
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(path), arch="amd64", analyze=False)
        else:
            raise ValueError("unexpected format: " + input_format)
    except Exception as e:
        # vivisect raises raw Exception instances, and we don't want
        # to do a subclass check via isinstance.
        if type(e) is Exception and "Couldn't convert rva" in e.args[0]:
            raise CorruptFile(e.args[0]) from e

    viv_utils.flirt.register_flirt_signature_analyzers(vw, [str(s) for s in sigpaths])

    with contextlib.suppress(Exception):
        # unfortuately viv raises a raw Exception (not any subclass).
        # This happens when the module isn't found, such as with a viv upgrade.
        #
        # Remove the symbolic switch case solver.
        # This is only enabled for ELF files, not PE files.
        # During the following performance investigation, this analysis module
        # had some terrible worst-case behavior.
        # We can put up with slightly worse CFG reconstruction in order to avoid this.
        # https://github.com/mandiant/capa/issues/1989#issuecomment-1948022767
        vw.delFuncAnalysisModule("vivisect.analysis.generic.symswitchcase")

    vw.analyze()

    logger.debug("%s", get_meta_str(vw))
    return vw


def get_extractor(
    input_path: Path,
    input_format: str,
    os_: str,
    backend: str,
    sigpaths: List[Path],
    should_save_workspace=False,
    disable_progress=False,
    sample_path: Optional[Path] = None,
) -> FeatureExtractor:
    """
    raises:
      UnsupportedFormatError
      UnsupportedArchError
      UnsupportedOSError
    """

    # stderr=True is used here to redirect the spinner banner to stderr, so that users can redirect capa's output.
    console = Console(stderr=True, quiet=disable_progress)

    if backend == BACKEND_CAPE:
        import capa.features.extractors.cape.extractor

        report = capa.helpers.load_json_from_path(input_path)
        return capa.features.extractors.cape.extractor.CapeExtractor.from_report(report)

    elif backend == BACKEND_DRAKVUF:
        import capa.features.extractors.drakvuf.extractor

        report = capa.helpers.load_jsonl_from_path(input_path)
        return capa.features.extractors.drakvuf.extractor.DrakvufExtractor.from_report(report)

    elif backend == BACKEND_VMRAY:
        import capa.features.extractors.vmray.extractor

        return capa.features.extractors.vmray.extractor.VMRayExtractor.from_zipfile(input_path)

    elif backend == BACKEND_DOTNET:
        import capa.features.extractors.dnfile.extractor

        if input_format not in (FORMAT_PE, FORMAT_DOTNET):
            raise UnsupportedFormatError()

        return capa.features.extractors.dnfile.extractor.DnfileFeatureExtractor(input_path)

    elif backend == BACKEND_BINJA:
        import capa.helpers
        from capa.features.extractors.binja.find_binja_api import find_binja_path

        # When we are running as a standalone executable, we cannot directly import binaryninja
        # We need to fist find the binja API installation path and add it into sys.path
        if capa.helpers.is_running_standalone():
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

        if input_format not in (FORMAT_SC32, FORMAT_SC64):
            if not is_supported_format(input_path):
                raise UnsupportedFormatError()

            if not is_supported_arch(input_path):
                raise UnsupportedArchError()

            if os_ == OS_AUTO and not is_supported_os(input_path):
                raise UnsupportedOSError()

        with console.status("analyzing program...", spinner="dots"):
            bv: BinaryView = binaryninja.load(str(input_path))
            if bv is None:
                raise RuntimeError(f"Binary Ninja cannot open file {input_path}")

        return capa.features.extractors.binja.extractor.BinjaFeatureExtractor(bv)

    elif backend == BACKEND_PEFILE:
        import capa.features.extractors.pefile

        return capa.features.extractors.pefile.PefileFeatureExtractor(input_path)

    elif backend == BACKEND_VIV:
        import capa.features.extractors.viv.extractor

        if input_format not in (FORMAT_SC32, FORMAT_SC64):
            if not is_supported_format(input_path):
                raise UnsupportedFormatError()

            if not is_supported_arch(input_path):
                raise UnsupportedArchError()

            if os_ == OS_AUTO and not is_supported_os(input_path):
                raise UnsupportedOSError()

        with console.status("analyzing program...", spinner="dots"):
            vw = get_workspace(input_path, input_format, sigpaths)

            if should_save_workspace:
                logger.debug("saving workspace")
                try:
                    vw.saveWorkspace()
                except IOError:
                    # see #168 for discussion around how to handle non-writable directories
                    logger.info("source directory is not writable, won't save intermediate workspace")
            else:
                logger.debug("CAPA_SAVE_WORKSPACE unset, not saving workspace")

        return capa.features.extractors.viv.extractor.VivisectFeatureExtractor(vw, input_path, os_)

    elif backend == BACKEND_FREEZE:
        return frz.load(input_path.read_bytes())

    elif backend == BACKEND_BINEXPORT2:
        import capa.features.extractors.binexport2
        import capa.features.extractors.binexport2.extractor

        be2 = capa.features.extractors.binexport2.get_binexport2(input_path)
        assert sample_path is not None
        buf = sample_path.read_bytes()

        return capa.features.extractors.binexport2.extractor.BinExport2FeatureExtractor(be2, buf)

    else:
        raise ValueError("unexpected backend: " + backend)


def _get_binexport2_file_extractors(input_file: Path) -> List[FeatureExtractor]:
    # I'm not sure this is where this logic should live, but it works for now.
    # we'll keep this a "private" routine until we're sure.
    import capa.features.extractors.binexport2

    be2 = capa.features.extractors.binexport2.get_binexport2(input_file)
    sample_path = capa.features.extractors.binexport2.get_sample_from_binexport2(
        input_file, be2, [Path(os.environ.get("CAPA_SAMPLES_DIR", "."))]
    )

    with sample_path.open("rb") as f:
        taste = f.read()

    if taste.startswith(capa.features.extractors.common.MATCH_PE):
        return get_file_extractors(sample_path, FORMAT_PE)
    elif taste.startswith(capa.features.extractors.common.MATCH_ELF):
        return get_file_extractors(sample_path, FORMAT_ELF)
    else:
        logger.warning("unsupported format")
        return []


def get_file_extractors(input_file: Path, input_format: str) -> List[FeatureExtractor]:
    file_extractors: List[FeatureExtractor] = []

    # we use lazy importing here to avoid eagerly loading dependencies
    # that some specialized environments may not have,
    # e.g., those that run capa without vivisect.

    if input_format == FORMAT_PE:
        import capa.features.extractors.pefile

        file_extractors.append(capa.features.extractors.pefile.PefileFeatureExtractor(input_file))

    elif input_format == FORMAT_DOTNET:
        import capa.features.extractors.pefile
        import capa.features.extractors.dotnetfile

        file_extractors.append(capa.features.extractors.pefile.PefileFeatureExtractor(input_file))
        file_extractors.append(capa.features.extractors.dotnetfile.DotnetFileFeatureExtractor(input_file))

    elif input_format == FORMAT_ELF:
        import capa.features.extractors.elffile

        file_extractors.append(capa.features.extractors.elffile.ElfFeatureExtractor(input_file))

    elif input_format == FORMAT_CAPE:
        import capa.features.extractors.cape.extractor

        report = capa.helpers.load_json_from_path(input_file)
        file_extractors.append(capa.features.extractors.cape.extractor.CapeExtractor.from_report(report))

    elif input_format == FORMAT_DRAKVUF:
        import capa.helpers
        import capa.features.extractors.drakvuf.extractor

        report = capa.helpers.load_jsonl_from_path(input_file)
        file_extractors.append(capa.features.extractors.drakvuf.extractor.DrakvufExtractor.from_report(report))

    elif input_format == FORMAT_VMRAY:
        import capa.features.extractors.vmray.extractor

        file_extractors.append(capa.features.extractors.vmray.extractor.VMRayExtractor.from_zipfile(input_file))

    elif input_format == FORMAT_BINEXPORT2:
        file_extractors = _get_binexport2_file_extractors(input_file)

    return file_extractors


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
    input_path: Path,
    input_format: str,
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

    input_format = (
        str(extractor_format[0]) if extractor_format else "unknown" if input_format == FORMAT_AUTO else input_format
    )
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
            path=input_path.resolve().as_posix(),
        ),
        analysis=get_sample_analysis(
            input_format,
            arch,
            os_,
            extractor,
            rules,
            counts,
        ),
    )


def compute_dynamic_layout(
    rules: RuleSet, extractor: DynamicFeatureExtractor, capabilities: MatchResults
) -> rdoc.DynamicLayout:
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
                ),  # this object is open to extension in the future,
                # such as with the function name, etc.
            )
            for p, threads in threads_by_process.items()
            if p in matched_processes
        )
    )

    return layout


def compute_static_layout(rules: RuleSet, extractor: StaticFeatureExtractor, capabilities) -> rdoc.StaticLayout:
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
                ),  # this object is open to extension in the future,
                # such as with the function name, etc.
            )
            for f, bbs in bbs_by_function.items()
            if len([bb for bb in bbs if bb in matched_bbs]) > 0
        )
    )

    return layout


def compute_layout(rules: RuleSet, extractor, capabilities) -> rdoc.Layout:
    if isinstance(extractor, StaticFeatureExtractor):
        return compute_static_layout(rules, extractor, capabilities)
    elif isinstance(extractor, DynamicFeatureExtractor):
        return compute_dynamic_layout(rules, extractor, capabilities)
    else:
        raise ValueError("extractor must be either a static or dynamic extracotr")
