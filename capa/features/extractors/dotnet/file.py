from __future__ import annotations

from typing import TYPE_CHECKING, List, Tuple, Iterator
from itertools import chain

if TYPE_CHECKING:
    import dnfile
    from capa.features.common import Feature

import capa.features.extractors.helpers
from capa.features.file import Import
from capa.features.common import FORMAT_DOTNET, Format
from capa.features.extractors.dotnet.helpers import get_dotnet_managed_imports, get_dotnet_unmanaged_imports


def extract_file_import_names(pe: dnfile.dnPE) -> Iterator[Tuple[Import, int]]:
    """extract file imports"""
    for (token, imp) in chain(get_dotnet_managed_imports(pe), get_dotnet_unmanaged_imports(pe)):
        if "::" in imp:
            # like System.IO.File::OpenRead
            yield Import(imp), token
        else:
            # like kernel32.CreateFileA
            dll, _, symbol = imp.rpartition(".")
            for symbol_variant in capa.features.extractors.helpers.generate_symbols(dll, symbol):
                yield Import(symbol_variant), token


def extract_file_format(pe: dnfile.dnPE) -> Iterator[Tuple[Format, int]]:
    yield Format(FORMAT_DOTNET), 0x0


def extract_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, int]]:
    for file_handler in FILE_HANDLERS:
        for (feature, token) in file_handler(pe):
            yield feature, token


FILE_HANDLERS = (
    extract_file_import_names,
    # TODO extract_file_strings,
    # TODO extract_file_function_names,
    extract_file_format,
)
