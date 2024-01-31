# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import json
import inspect
import logging
import contextlib
import importlib.util
from typing import NoReturn
from pathlib import Path

import tqdm

from capa.exceptions import UnsupportedFormatError
from capa.features.common import (
    FORMAT_PE,
    FORMAT_CAPE,
    FORMAT_SC32,
    FORMAT_SC64,
    FORMAT_DOTNET,
    FORMAT_FREEZE,
    FORMAT_UNKNOWN,
    Format,
)

EXTENSIONS_SHELLCODE_32 = ("sc32", "raw32")
EXTENSIONS_SHELLCODE_64 = ("sc64", "raw64")
EXTENSIONS_DYNAMIC = ("json", "json_")
EXTENSIONS_ELF = "elf_"
EXTENSIONS_FREEZE = "frz"

logger = logging.getLogger("capa")


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


def get_format_from_report(sample: Path) -> str:
    report = json.load(sample.open(encoding="utf-8"))

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


@contextlib.contextmanager
def redirecting_print_to_tqdm(disable_progress):
    """
    tqdm (progress bar) expects to have fairly tight control over console output.
    so calls to `print()` will break the progress bar and make things look bad.
    so, this context manager temporarily replaces the `print` implementation
    with one that is compatible with tqdm.
    via: https://stackoverflow.com/a/42424890/87207
    """
    old_print = print  # noqa: T202 [reserved word print used]

    def new_print(*args, **kwargs):
        # If tqdm.tqdm.write raises error, use builtin print
        if disable_progress:
            old_print(*args, **kwargs)
        else:
            try:
                tqdm.tqdm.write(*args, **kwargs)
            except Exception:
                old_print(*args, **kwargs)

    try:
        # Globally replace print with new_print.
        # Verified this works manually on Python 3.11:
        #     >>> import inspect
        #     >>> inspect.builtins
        #     <module 'builtins' (built-in)>
        inspect.builtins.print = new_print  # type: ignore
        yield
    finally:
        inspect.builtins.print = old_print  # type: ignore


def log_unsupported_format_error():
    logger.error("-" * 80)
    logger.error(" Input file does not appear to be a supported file.")
    logger.error(" ")
    logger.error(" See all supported file formats via capa's help output (-h).")
    logger.error(" If you don't know the input file type, you can try using the `file` utility to guess it.")
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


def log_empty_cape_report_error(error: str):
    logger.error("-" * 80)
    logger.error(" CAPE report is empty or only contains little useful data: %s", error)
    logger.error(" ")
    logger.error(" Please make sure the sandbox run captures useful behaviour of your sample.")
    logger.error("-" * 80)


def log_unsupported_os_error():
    logger.error("-" * 80)
    logger.error(" Input file does not appear to target a supported OS.")
    logger.error(" ")
    logger.error(
        " capa currently only supports analyzing executables for some operating systems (including Windows and Linux)."
    )
    logger.error("-" * 80)


def log_unsupported_arch_error():
    logger.error("-" * 80)
    logger.error(" Input file does not appear to target a supported architecture.")
    logger.error(" ")
    logger.error(" capa currently only supports analyzing x86 (32- and 64-bit).")
    logger.error("-" * 80)


def log_unsupported_runtime_error():
    logger.error("-" * 80)
    logger.error(" Unsupported runtime or Python interpreter.")
    logger.error(" ")
    logger.error(" capa supports running under Python 3.8 and higher.")
    logger.error(" ")
    logger.error(
        " If you're seeing this message on the command line, please ensure you're running a supported Python version."
    )
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
