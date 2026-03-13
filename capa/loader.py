# Copyright 2024 Google LLC
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

import os
import logging
import datetime
import contextlib
import threading
import signal
from typing import Optional
from pathlib import Path

from rich.console import Console
from typing_extensions import assert_never

import capa.rules
import capa.version
import capa.features.common
import capa.features.freeze as frz
import capa.features.extractors
import capa.render.result_document as rdoc
import capa.features.extractors.common
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
    FORMAT_BINJA_DB,
    FORMAT_BINEXPORT2,
)
from capa.features.address import Address
from capa.capabilities.common import Capabilities
from capa.features.extractors.base_extractor import (
    SampleHashes,
    FunctionFilter,
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
BACKEND_IDA = "ida"
BACKEND_GHIDRA = "ghidra"


class CorruptFile(ValueError):
    pass


class _AnalysisTimeoutError(RuntimeError):
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


def _is_probably_corrupt_pe(path: Path) -> bool:
    """
    Heuristic check for obviously malformed PE samples that provoke
    pathological behavior in vivisect (see GH-1989).

    We treat a PE as "probably corrupt" when any section declares an
    unrealistically large virtual size compared to the file size, e.g.
    hundreds of megabytes in a tiny file. Such cases lead vivisect to
    try to map enormous regions and can exhaust CPU/memory.
    """
    try:
        import pefile
    except Exception:
        # If pefile is unavailable, fall back to existing behavior.
        return False

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError:
        # Not a PE file (or badly formed); let existing checks handle it.
        return False
    except Exception:
        return False

    try:
        file_size = path.stat().st_size
    except OSError:
        return False

    if file_size <= 0:
        return False

    # Flag sections whose declared virtual size is wildly disproportionate
    # to the file size (e.g. 900MB section in a ~400KB sample).
    _VSIZE_FILE_RATIO = 128
    _MAX_REASONABLE_VSIZE = 512 * 1024 * 1024  # 512 MB
    max_reasonable = max(file_size * _VSIZE_FILE_RATIO, _MAX_REASONABLE_VSIZE)

    for section in getattr(pe, "sections", []):
        vsize = getattr(section, "Misc_VirtualSize", 0) or 0
        if vsize > max_reasonable:
            logger.debug(
                "detected unrealistic PE section virtual size: 0x%x (file size: 0x%x), treating as corrupt",
                vsize,
                file_size,
            )
            return True

    return False


def _get_elf_analysis_timeout_seconds() -> int:
    """
    Return timeout for viv ELF analysis in seconds.
    0 disables timeout.
    """
    value = os.environ.get("CAPA_ELF_ANALYSIS_TIMEOUT_SECONDS", "120").strip()
    try:
        return max(0, int(value))
    except ValueError:
        logger.warning("invalid CAPA_ELF_ANALYSIS_TIMEOUT_SECONDS=%r, using default 120", value)
        return 120


def _get_elf_max_functions() -> int:
    """
    Return max number of ELF functions to analyze with viv.
    0 disables capping.
    """
    value = os.environ.get("CAPA_ELF_MAX_FUNCTIONS", "1000").strip()
    try:
        return max(0, int(value))
    except ValueError:
        logger.warning("invalid CAPA_ELF_MAX_FUNCTIONS=%r, using default 1000", value)
        return 1000


@contextlib.contextmanager
def _timebox(seconds: int):
    """
    Timebox a block using SIGALRM on platforms that support it.
    """
    if (
        seconds <= 0
        or not hasattr(signal, "SIGALRM")
        or threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    def _handle_timeout(signum, frame):
        raise _AnalysisTimeoutError(f"analysis exceeded {seconds}s")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, float(seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)


@contextlib.contextmanager
def _temporarily_disable_viv_elf_section_symbols():
    """
    Disable viv's ELF section-symbol parsing while loading a workspace.

    The parser reads large .symtab/.strtab sections very inefficiently and can
    cause severe slowdowns on large real-world ELF binaries.
    """
    import Elf

    original = getattr(Elf.Elf, "_parseSectionSymbols", None)
    if original is None:
        yield
        return

    def _skip_section_symbols(self):
        logger.debug("skipping viv ELF section-symbol parsing")

    Elf.Elf._parseSectionSymbols = _skip_section_symbols
    try:
        yield
    finally:
        Elf.Elf._parseSectionSymbols = original


def get_workspace(path: Path, input_format: str, sigpaths: list[Path]):
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
    import envi.exc
    import viv_utils
    import viv_utils.flirt

    logger.debug("generating vivisect workspace for: %s", path)

    if input_format in (FORMAT_PE, FORMAT_AUTO) and _is_probably_corrupt_pe(path):
        raise CorruptFile(
            "PE file appears to contain unrealistically large sections and is likely corrupt"
            + " - skipping analysis to avoid excessive resource usage."
        )

    is_elf_input = False
    if input_format == FORMAT_ELF:
        is_elf_input = True
    elif input_format == FORMAT_AUTO:
        with path.open("rb") as f:
            is_elf_input = f.read(4).startswith(capa.features.extractors.common.MATCH_ELF)

    try:
        if input_format == FORMAT_AUTO:
            if not is_supported_format(path):
                raise UnsupportedFormatError()

            # don't analyze, so that we can add our Flirt function analyzer first.
            with _temporarily_disable_viv_elf_section_symbols() if is_elf_input else contextlib.nullcontext():
                vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
        elif input_format in {FORMAT_PE, FORMAT_ELF}:
            with _temporarily_disable_viv_elf_section_symbols() if is_elf_input else contextlib.nullcontext():
                vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
        elif input_format == FORMAT_SC32:
            # these are not analyzed nor saved.
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(path), arch="i386", analyze=False)
        elif input_format == FORMAT_SC64:
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(path), arch="amd64", analyze=False)
        else:
            raise ValueError("unexpected format: " + input_format)
    except envi.exc.SegmentationViolation as e:
        raise CorruptFile(f"Invalid memory access during binary parsing: {e}") from e
    except ModuleNotFoundError as e:
        # viv may fail while loading architecture-specific impapi modules.
        # treat this as unsupported architecture instead of crashing.
        if e.name and e.name.startswith("vivisect.impapi.posix."):
            raise UnsupportedArchError() from e
        raise
    except Exception as e:
        # vivisect raises raw Exception instances, and we don't want
        # to do a subclass check via isinstance.
        if type(e) is Exception and e.args:
            error_msg = str(e.args[0])

            if "Couldn't convert rva" in error_msg:
                raise CorruptFile(error_msg) from e
            elif "Unsupported Architecture" in error_msg:
                # Extract architecture number if available
                arch_info = e.args[1] if len(e.args) > 1 else "unknown"
                raise CorruptFile(f"Unsupported architecture: {arch_info}") from e
        raise

    viv_utils.flirt.register_flirt_signature_analyzers(vw, [str(s) for s in sigpaths])

    if is_elf_input:
        for module in (
            # During performance investigations we've observed pathological
            # behavior in several viv ELF function-analysis passes. prefer
            # slightly reduced CFG reconstruction over indefinite analysis.
            "vivisect.analysis.generic.symswitchcase",
            "vivisect.analysis.elf.elfplt",
            "vivisect.analysis.amd64.emulation",
            "vivisect.analysis.generic.emucode",
            "vivisect.analysis.generic.noret",
        ):
            with contextlib.suppress(Exception):
                # unfortunately viv raises raw Exception (not any subclass)
                # when a module isn't found (e.g. after viv upgrades).
                vw.delFuncAnalysisModule(module)

    try:
        timeout_s = _get_elf_analysis_timeout_seconds() if is_elf_input else 0
        with _timebox(timeout_s):
            vw.analyze()
    except _AnalysisTimeoutError as e:
        raise CorruptFile(
            f"analysis timed out after {timeout_s}s while processing ELF sample; refusing to hang indefinitely"
        ) from e
    except ModuleNotFoundError as e:
        # viv may fail late when it cannot load an architecture-specific impapi module.
        # treat this as an unsupported architecture instead of crashing with a traceback.
        if e.name and e.name.startswith("vivisect.impapi.posix."):
            raise UnsupportedArchError() from e
        raise

    logger.debug("%s", get_meta_str(vw))
    return vw


def get_extractor(
    input_path: Path,
    input_format: str,
    os_: str,
    backend: str,
    sigpaths: list[Path],
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
        import capa.features.extractors.binja.find_binja_api as finder

        if not finder.has_binaryninja():
            raise RuntimeError("cannot find Binary Ninja API module.")

        if not finder.load_binaryninja():
            raise RuntimeError("failed to load Binary Ninja API module.")

        import binaryninja

        import capa.features.extractors.binja.extractor

        if input_format not in (FORMAT_SC32, FORMAT_SC64, FORMAT_BINJA_DB):
            if not is_supported_format(input_path):
                raise UnsupportedFormatError()

            if not is_supported_arch(input_path):
                raise UnsupportedArchError()

            if os_ == OS_AUTO and not is_supported_os(input_path):
                raise UnsupportedOSError()

        with console.status("analyzing program...", spinner="dots"):
            bv: binaryninja.BinaryView = binaryninja.load(str(input_path))
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

        extractor: FeatureExtractor = capa.features.extractors.viv.extractor.VivisectFeatureExtractor(vw, input_path, os_)
        if input_format == FORMAT_ELF:
            max_functions = _get_elf_max_functions()
            if max_functions > 0:
                selected = []
                functions = extractor.get_functions()
                for i, f in enumerate(functions):
                    if i >= max_functions:
                        logger.warning(
                            "ELF function count exceeds CAPA_ELF_MAX_FUNCTIONS=%d, limiting analysis scope",
                            max_functions,
                        )
                        break
                    selected.append(f.address)
                if selected:
                    extractor = FunctionFilter(extractor, set(selected))

        return extractor

    elif backend == BACKEND_FREEZE:
        return frz.load(input_path.read_bytes())

    elif backend == BACKEND_BINEXPORT2:
        import capa.features.extractors.binexport2
        import capa.features.extractors.binexport2.extractor

        be2 = capa.features.extractors.binexport2.get_binexport2(input_path)
        assert sample_path is not None
        buf = sample_path.read_bytes()

        return capa.features.extractors.binexport2.extractor.BinExport2FeatureExtractor(be2, buf)

    elif backend == BACKEND_IDA:
        import capa.features.extractors.ida.idalib as idalib

        if not idalib.has_idalib():
            raise RuntimeError("cannot find IDA idalib module.")

        if not idalib.load_idalib():
            raise RuntimeError("failed to load IDA idalib module.")

        import idapro
        import ida_auto

        import capa.features.extractors.ida.extractor

        logger.debug("idalib: opening database...")
        idapro.enable_console_messages(False)
        with console.status("analyzing program...", spinner="dots"):
            # we set the primary and secondary Lumina servers to 0.0.0.0 to disable Lumina,
            # which sometimes provides bad names, including overwriting names from debug info.
            #
            # use -R to load resources, which can help us embedded PE files.
            #
            # return values from open_database:
            #   0 - Success
            #   2 - User cancelled or 32-64 bit conversion failed
            #   4 - Database initialization failed
            #   -1 - Generic errors (database already open, auto-analysis failed, etc.)
            #   -2 - User cancelled operation
            ret = idapro.open_database(
                str(input_path), run_auto_analysis=True, args="-Olumina:host=0.0.0.0 -Osecondary_lumina:host=0.0.0.0 -R"
            )
            if ret != 0:
                raise RuntimeError("failed to analyze input file")

            logger.debug("idalib: waiting for analysis...")
            ida_auto.auto_wait()
            logger.debug("idalib: opened database.")

        return capa.features.extractors.ida.extractor.IdaFeatureExtractor()

    elif backend == BACKEND_GHIDRA:
        import pyghidra

        with console.status("analyzing program...", spinner="dots"):
            if not pyghidra.started():
                pyghidra.start()

            import capa.ghidra.helpers

            if not capa.ghidra.helpers.is_supported_ghidra_version():
                raise RuntimeError("unsupported Ghidra version")

            import tempfile

            tmpdir = tempfile.TemporaryDirectory()

            project_cm = pyghidra.open_project(tmpdir.name, "CapaProject", create=True)
            project = project_cm.__enter__()
            try:
                from ghidra.util.task import TaskMonitor

                monitor = TaskMonitor.DUMMY

                # Import file
                loader = pyghidra.program_loader().project(project).source(str(input_path)).name(input_path.name)
                with loader.load() as load_results:
                    load_results.save(monitor)

                # Open program
                program, consumer = pyghidra.consume_program(project, "/" + input_path.name)

                # Analyze
                pyghidra.analyze(program, monitor)

                from ghidra.program.flatapi import FlatProgramAPI

                flat_api = FlatProgramAPI(program)

                import capa.features.extractors.ghidra.context as ghidra_context

                ghidra_context.set_context(program, flat_api, monitor)

                # Wrapper to handle cleanup of program (consumer) and project
                class GhidraContextWrapper:
                    def __init__(self, project_cm, program, consumer):
                        self.project_cm = project_cm
                        self.program = program
                        self.consumer = consumer

                    def __exit__(self, exc_type, exc_val, exc_tb):
                        self.program.release(self.consumer)
                        self.project_cm.__exit__(exc_type, exc_val, exc_tb)

                cm = GhidraContextWrapper(project_cm, program, consumer)

            except Exception:
                project_cm.__exit__(None, None, None)
                tmpdir.cleanup()
                raise

        import capa.features.extractors.ghidra.extractor

        return capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor(ctx_manager=cm, tmpdir=tmpdir)
    else:
        raise ValueError("unexpected backend: " + backend)


def _get_binexport2_file_extractors(input_file: Path) -> list[FeatureExtractor]:
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


def get_file_extractors(input_file: Path, input_format: str) -> list[FeatureExtractor]:
    file_extractors: list[FeatureExtractor] = []

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


def get_signatures(sigs_path: Path) -> list[Path]:
    if not sigs_path.exists():
        raise IOError(f"signatures path {sigs_path} does not exist or cannot be accessed")

    paths: list[Path] = []
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


def get_sample_analysis(format_, arch, os_, extractor, rules_path, feature_counts, library_functions):
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
            feature_counts=feature_counts,
            library_functions=library_functions,
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
            feature_counts=feature_counts,
        )
    else:
        raise ValueError("invalid extractor type")


def collect_metadata(
    argv: list[str],
    input_path: Path,
    input_format: str,
    os_: str,
    rules_path: list[Path],
    extractor: FeatureExtractor,
    capabilities: Capabilities,
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
            capabilities.feature_counts,
            capabilities.library_functions,
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

    matched_calls: set[Address] = set()

    def result_rec(result: capa.features.common.Result):
        for loc in result.locations:
            if isinstance(loc, capa.features.address.DynamicCallAddress):
                matched_calls.add(loc)
        for child in result.children:
            result_rec(child)

    for matches in capabilities.values():
        for _, result in matches:
            result_rec(result)

    names_by_process: dict[Address, str] = {}
    names_by_call: dict[Address, str] = {}

    matched_processes: set[Address] = set()
    matched_threads: set[Address] = set()

    threads_by_process: dict[Address, list[Address]] = {}
    calls_by_thread: dict[Address, list[Address]] = {}

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
    functions_by_bb: dict[Address, Address] = {}
    bbs_by_function: dict[Address, list[Address]] = {}
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
