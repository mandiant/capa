from __future__ import annotations

from typing import TYPE_CHECKING, Tuple, Iterator

if TYPE_CHECKING:
    import dnfile
    from capa.features.common import Feature, Format
    from capa.features.file import Import

import capa.features.extractors


def extract_file_import_names(pe: dnfile.dnPE) -> Iterator[Tuple[Import, int]]:
    yield from capa.features.extractors.dnfile_.extract_file_import_names(pe)


def extract_file_format(pe: dnfile.dnPE) -> Iterator[Tuple[Format, int]]:
    yield from capa.features.extractors.dnfile_.extract_file_format(pe=pe)


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
