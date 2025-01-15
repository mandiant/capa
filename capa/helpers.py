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
import gzip
import ctypes
import logging
import tempfile
import contextlib
import importlib.util
from typing import BinaryIO, Iterator, NoReturn
from pathlib import Path
from zipfile import ZipFile
from datetime import datetime

import msgspec.json
from rich.console import Console
from rich.progress import (
    Task,
    Text,
    Progress,
    BarColumn,
    TextColumn,
    SpinnerColumn,
    ProgressColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

from capa.exceptions import UnsupportedFormatError
from capa.features.common import (
    FORMAT_PE,
    FORMAT_CAPE,
    FORMAT_SC32,
    FORMAT_SC64,
    FORMAT_VMRAY,
    FORMAT_DOTNET,
    FORMAT_FREEZE,
    FORMAT_DRAKVUF,
    FORMAT_UNKNOWN,
    FORMAT_BINJA_DB,
    FORMAT_BINEXPORT2,
    Format,
)

EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")
# CAPE (.json, .json_, .json.gz)
# DRAKVUF (.log, .log.gz)
# VMRay (.zip)
EXTENSIONS_DYNAMIC = ("json", "json_", "json.gz", "log", ".log.gz", ".zip")
EXTENSIONS_BINEXPORT2 = ("BinExport", "BinExport2")
EXTENSIONS_ELF = "elf_"
EXTENSIONS_FREEZE = "frz"
EXTENSIONS_BINJA_DB = "bndb"

logger = logging.getLogger("capa")


# shared console used to redirect logging to stderr
log_console: Console = Console(stderr=True)


def hex(n: int) -> str:
    """render the given number using upper case hex, like: 0x123ABC"""
    if n < 0:
        return f"-0x{(-n):X}"
    else:
        return f"0x{(n):X}"


def get_file_taste(sample_path: Path) -> bytes:
    if not sample_path.exists():
        raise IOError(f"sample path {sample_path} does not exist or cannot be accessed")
    taste = sample_path.open("rb").read(8)
    return taste


def is_runtime_ida():
    return importlib.util.find_spec("idc") is not None


def is_runtime_ghidra():
    try:
        currentProgram  # type: ignore [name-defined] # noqa: F821
    except NameError:
        return False
    return True


def assert_never(value) -> NoReturn:
    # careful: python -O will remove this assertion.
    # but this is only used for type checking, so it's ok.
    assert False, f"Unhandled value: {value} ({type(value).__name__})"  # noqa: B011


@contextlib.contextmanager
def stdout_redirector(stream):
    """
    Redirect stdout at the C runtime level,
     which lets us handle native libraries that spam stdout.

    *But*, this only works on Linux! Otherwise will silently still write to stdout.
    So, try to upstream the fix when possible.

    Via: https://eli.thegreenplace.net/2015/redirecting-all-kinds-of-stdout-in-python/
    """
    if sys.platform not in ("linux", "linux2"):
        logger.warning("Unable to capture STDOUT on non-Linux (begin)")
        yield
        logger.warning("Unable to capture STDOUT on non-Linux (end)")
        return

    # libc is only on Linux
    LIBC = ctypes.CDLL(None)
    C_STDOUT = ctypes.c_void_p.in_dll(LIBC, "stdout")

    # The original fd stdout points to. Usually 1 on POSIX systems.
    original_stdout_fd = sys.stdout.fileno()

    def _redirect_stdout(to_fd):
        """Redirect stdout to the given file descriptor."""
        # Flush the C-level buffer stdout
        LIBC.fflush(C_STDOUT)
        # Flush and close sys.stdout - also closes the file descriptor (fd)
        sys.stdout.close()
        # Make original_stdout_fd point to the same file as to_fd
        os.dup2(to_fd, original_stdout_fd)
        # Create a new sys.stdout that points to the redirected fd
        sys.stdout = io.TextIOWrapper(os.fdopen(original_stdout_fd, "wb"))

    # Save a copy of the original stdout fd in saved_stdout_fd
    saved_stdout_fd = os.dup(original_stdout_fd)
    try:
        # Create a temporary file and redirect stdout to it
        tfile = tempfile.TemporaryFile(mode="w+b")
        _redirect_stdout(tfile.fileno())
        # Yield to caller, then redirect stdout back to the saved fd
        yield
        _redirect_stdout(saved_stdout_fd)
        # Copy contents of temporary file to the given stream
        tfile.flush()
        tfile.seek(0, io.SEEK_SET)
        stream.write(tfile.read())
    finally:
        tfile.close()
        os.close(saved_stdout_fd)


def load_json_from_path(json_path: Path):
    with gzip.open(json_path, "r") as compressed_report:
        try:
            report_json = compressed_report.read()
        except gzip.BadGzipFile:
            report = msgspec.json.decode(json_path.read_text(encoding="utf-8"))
        else:
            report = msgspec.json.decode(report_json)
    return report


def decode_json_lines(fd: BinaryIO | gzip.GzipFile):
    for line in fd:
        try:
            line_s = line.strip().decode()
            obj = msgspec.json.decode(line_s)
            yield obj
        except (msgspec.DecodeError, UnicodeDecodeError):
            # sometimes DRAKVUF reports bad method names and/or malformed JSON
            logger.debug("bad DRAKVUF log line: %s", line)


def load_jsonl_from_path(jsonl_path: Path) -> Iterator[dict]:
    try:
        with gzip.open(jsonl_path, "rb") as fg:
            yield from decode_json_lines(fg)
    except gzip.BadGzipFile:
        with jsonl_path.open(mode="rb") as f:
            yield from decode_json_lines(f)


def load_one_jsonl_from_path(jsonl_path: Path):
    # this loads one json line to avoid the overhead of loading the entire file
    try:
        with gzip.open(jsonl_path, "rb") as f:
            line = next(iter(f))
    except gzip.BadGzipFile:
        with jsonl_path.open(mode="rb") as f:
            line = next(iter(f))
    finally:
        line = msgspec.json.decode(line.decode(errors="ignore"))
    return line


def get_format_from_report(sample: Path) -> str:
    if sample.name.endswith((".log", "log.gz")):
        line = load_one_jsonl_from_path(sample)
        if "Plugin" in line:
            return FORMAT_DRAKVUF
    elif sample.name.endswith(".zip"):
        with ZipFile(sample, "r") as zipfile:
            namelist: list[str] = zipfile.namelist()
            if "logs/summary_v2.json" in namelist and "logs/flog.xml" in namelist:
                # assume VMRay zipfile at a minimum has these files
                return FORMAT_VMRAY
    elif sample.name.endswith(("json", "json_", "json.gz")):
        report = load_json_from_path(sample)
        if "CAPE" in report:
            return FORMAT_CAPE
        if "target" in report and "info" in report and "behavior" in report:
            # CAPE report that's missing the "CAPE" key,
            # which is not going to be much use, but its correct.
            return FORMAT_CAPE

    return FORMAT_UNKNOWN


def get_format_from_extension(sample: Path) -> str:
    format_ = FORMAT_UNKNOWN
    if sample.name.endswith(EXTENSIONS_SHELLCODE_32):
        format_ = FORMAT_SC32
    elif sample.name.endswith(EXTENSIONS_SHELLCODE_64):
        format_ = FORMAT_SC64
    elif sample.name.endswith(EXTENSIONS_DYNAMIC):
        format_ = get_format_from_report(sample)
    elif sample.name.endswith(EXTENSIONS_FREEZE):
        format_ = FORMAT_FREEZE
    elif sample.name.endswith(EXTENSIONS_BINEXPORT2):
        format_ = FORMAT_BINEXPORT2
    elif sample.name.endswith(EXTENSIONS_BINJA_DB):
        format_ = FORMAT_BINJA_DB
    return format_


def get_auto_format(path: Path) -> str:
    format_ = get_format(path)
    if format_ == FORMAT_UNKNOWN:
        format_ = get_format_from_extension(path)
    if format_ == FORMAT_UNKNOWN:
        raise UnsupportedFormatError()
    return format_


def get_format(sample: Path) -> str:
    # imported locally to avoid import cycle
    from capa.features.extractors.common import extract_format
    from capa.features.extractors.dotnetfile import DotnetFileFeatureExtractor

    buf = sample.read_bytes()

    for feature, _ in extract_format(buf):
        if feature == Format(FORMAT_PE):
            dnfile_extractor = DotnetFileFeatureExtractor(sample)
            if dnfile_extractor.is_dotnet_file():
                feature = Format(FORMAT_DOTNET)

        assert isinstance(feature.value, str)
        return feature.value

    return FORMAT_UNKNOWN


def log_unsupported_format_error():
    logger.error("-" * 80)
    logger.error(" Input file does not appear to be a supported file.")
    logger.error(" ")
    logger.error(" See all supported file formats via capa's help output (-h).")
    logger.error(" If you don't know the input file type,")
    logger.error(" you can try using the `file` utility to guess it.")
    logger.error("-" * 80)


def log_unsupported_cape_report_error(error: str):
    logger.error("-" * 80)
    logger.error(" Input file is not a valid CAPE report: %s", error)
    logger.error(" ")
    logger.error(" capa currently only supports analyzing standard CAPE reports in JSON format.")
    logger.error(
        " Please make sure your report file is in the standard format and contains both the static and dynamic sections."
    )
    logger.error("-" * 80)


def log_unsupported_drakvuf_report_error(error: str):
    logger.error("-" * 80)
    logger.error(" Input file is not a valid DRAKVUF output file: %s", error)
    logger.error(" ")
    logger.error(" capa currently only supports analyzing standard DRAKVUF outputs in JSONL format.")
    logger.error(
        " Please make sure your report file is in the standard format and contains both the static and dynamic sections."
    )
    logger.error("-" * 80)


def log_unsupported_vmray_report_error(error: str):
    logger.error("-" * 80)
    logger.error(" Input file is not a valid VMRay analysis archive: %s", error)
    logger.error(" ")
    logger.error(
        " capa only supports analyzing VMRay dynamic analysis archives containing summary_v2.json and flog.xml log files."
    )
    logger.error(" Please make sure you have downloaded a dynamic analysis archive from VMRay.")
    logger.error("-" * 80)


def log_empty_sandbox_report_error(error: str, sandbox_name: str):
    logger.error("-" * 80)
    logger.error(" %s report is empty or only contains little useful data: %s", sandbox_name, error)
    logger.error(" ")
    logger.error(" Please make sure the sandbox run captures useful behaviour of your sample.")
    logger.error("-" * 80)


def log_unsupported_os_error():
    logger.error("-" * 80)
    logger.error(" Input file does not appear to target a supported OS.")
    logger.error(" ")
    logger.error(" capa currently only analyzes executables for some operating systems")
    logger.error(" (including Windows, Linux, and Android).")
    logger.error("-" * 80)


def log_unsupported_arch_error():
    logger.error("-" * 80)
    logger.error(" Input file does not appear to target a supported architecture.")
    logger.error(" ")
    logger.error(" capa currently only supports analyzing x86 (32- and 64-bit).")
    logger.error("-" * 80)


def is_running_standalone() -> bool:
    """
    are we running from a PyInstaller'd executable?
    if so, then we'll be able to access `sys._MEIPASS` for the packaged resources.
    """
    # typically we only expect capa.main to be packaged via PyInstaller.
    # therefore, this *should* be in capa.main; however,
    # the Binary Ninja extractor uses this to resolve the BN API code,
    # so we keep this in a common area.
    # generally, other library code should not use this function.
    return hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS")


def is_dev_environment() -> bool:
    if is_running_standalone():
        return False

    if "site-packages" in __file__:
        # running from a site-packages installation
        return False

    capa_root = Path(__file__).resolve().parent.parent
    git_dir = capa_root / ".git"

    if not git_dir.is_dir():
        # .git directory doesn't exist
        return False

    return True


def is_cache_newer_than_rule_code(cache_dir: Path) -> bool:
    """
    basic check to prevent issues if the rules cache is older than relevant rules code

    args:
      cache_dir: the cache directory containing cache files

    returns:
      True if latest cache file is newer than relevant rule cache code
    """

    # retrieve the latest modified cache file
    cache_files = list(cache_dir.glob("*.cache"))
    if not cache_files:
        logger.debug("no rule cache files found")
        return False

    latest_cache_file = max(cache_files, key=os.path.getmtime)
    cache_timestamp = os.path.getmtime(latest_cache_file)

    # these are the relevant rules code files that could conflict with using an outdated cache
    # delayed import due to circular dependencies
    import capa.rules
    import capa.rules.cache

    latest_rule_code_file = max([Path(capa.rules.__file__), Path(capa.rules.cache.__file__)], key=os.path.getmtime)
    rule_code_timestamp = os.path.getmtime(latest_rule_code_file)

    if rule_code_timestamp > cache_timestamp:

        def ts_to_str(ts):
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

        logger.warning(
            "latest rule code file %s (%s) is newer than the latest rule cache file %s (%s)",
            latest_rule_code_file,
            ts_to_str(rule_code_timestamp),
            latest_cache_file,
            ts_to_str(cache_timestamp),
        )
        return False

    return True


class RateColumn(ProgressColumn):
    """Renders speed column in progress bar."""

    def render(self, task: "Task") -> Text:
        speed = f"{task.speed:>.1f}" if task.speed else "00.0"
        unit = task.fields.get("unit", "it")
        return Text.from_markup(f"[progress.data.speed]{speed} {unit}/s")


class PostfixColumn(ProgressColumn):
    """Renders a postfix column in progress bar."""

    def render(self, task: "Task") -> Text:
        return Text(task.fields.get("postfix", ""))


class MofNCompleteColumnWithUnit(MofNCompleteColumn):
    """Renders completed/total count column with a unit."""

    def render(self, task: "Task") -> Text:
        ret = super().render(task)
        unit = task.fields.get("unit")
        return ret.append(f" {unit}") if unit else ret


class CapaProgressBar(Progress):
    @classmethod
    def get_default_columns(cls):
        return (
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TaskProgressColumn(),
            BarColumn(),
            MofNCompleteColumnWithUnit(),
            "•",
            TimeElapsedColumn(),
            "<",
            TimeRemainingColumn(),
            "•",
            RateColumn(),
            PostfixColumn(),
        )
