from typing import Iterator, Tuple, List
from pathlib import Path

from capa.helpers import is_runtime_ida, get_auto_format, is_runtime_ghidra
from capa.exceptions import UnsupportedFormatError
from capa.features.common import FORMAT_PE, FORMAT_ELF, FORMAT_CAPE, String
from capa.features.address import Address
from capa.features.extractors import (
    ida,
    ghidra,
    elffile,
    viv,
    pefile,
    binja,
    dnfile,
    cape,
)

from capa.render.result_document import ResultDocument
from capa.features.extractors.base_extractor import FeatureExtractor

CD = Path(__file__).resolve().parent.parent.parent

# these constants are also defined in capa.main
# defined here to avoid a circular import
BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"


def get_file_strings(doc: ResultDocument) -> Iterator[str]:
    """extract strings from a given file"""
    extractor = get_extractor_from_doc(doc)
    if is_runtime_ida():
        strings = fix_up(ida.helpers.extract_file_strings())
    elif is_runtime_ghidra():
        strings = fix_up(ghidra.helpers.extract_file_strings())
    else:
        file = get_file_path(doc)
        format_ = get_auto_format(file)
        buf = file.read_bytes()
        if format_ == FORMAT_ELF:
            strings = fix_up(elffile.extract_file_strings(buf))
        elif format_ == BACKEND_VIV:
            strings = fix_up(viv.file.extract_file_strings(buf))
        elif format_ == BACKEND_PEFILE or format_ == FORMAT_PE:
            strings = fix_up(pefile.extract_file_strings(buf))
        elif format_ == BACKEND_BINJA:
            strings = fix_up(binja.file.extract_file_strings(extractor.bv))
        elif format_ == BACKEND_DOTNET:
            strings = fix_up(dnfile.file.extract_file_strings(extractor.pe))
        elif format_ == FORMAT_CAPE:
            strings = fix_up(cape.file.extract_file_strings(extractor.report))
        else:
            raise UnsupportedFormatError(f"Unknown file format! Format: {format_}")

    return strings


def fix_up(obj: Iterator[Tuple[String, Address]]) -> List[str]:
    """
    basically a wrapper for 'extract_file_strings' calls
    to actually get list of strings
    """
    strings = []
    for tuple in obj:
            strings.append(tuple[0])
    
    return strings


def get_file_path(doc: ResultDocument) -> Path:
    return Path(doc.meta.sample.path)


def get_extractor_from_doc(doc: ResultDocument) -> FeatureExtractor:
    import capa.main

    path = get_file_path(doc)
    format = doc.meta.analysis.format
    os = doc.meta.analysis.os

    _ = get_auto_format(get_file_path(doc))
    if _ == BACKEND_VIV:
        backend = BACKEND_VIV
    elif _ == BACKEND_PEFILE:
        backend = BACKEND_PEFILE
    elif _ == BACKEND_BINJA:
        backend = BACKEND_BINJA
    elif _ == BACKEND_DOTNET:
        backend = BACKEND_DOTNET
    else:
        backend = BACKEND_VIV  # according to capa.main this is the default

    sigpaths = [
        CD / "tests" / "data" / "sigs" / "test_aulldiv.pat",
        CD / "tests" / "data" / "sigs" / "test_aullrem.pat.gz",
        CD / "sigs" / "1_flare_msvc_rtf_32_64.sig",
        CD / "sigs" / "2_flare_msvc_atlmfc_32_64.sig",
        CD / "sigs" / "3_flare_common_libs.sig",
    ]

    return capa.main.get_extractor(
        path=path,
        format_=format,
        os_=os,
        backend=backend,
        sigpaths=sigpaths,
    )