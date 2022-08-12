from typing import Tuple, Iterator

import capa.features.extractors.script
from capa.features.common import Feature
from capa.features.address import Address


def extract_arch() -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_arch()


def extract_os() -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_os()


def extract_file_format() -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_format()


def extract_features() -> Iterator[Tuple[Feature, Address]]:
    for glob_handler in GLOBAL_HANDLERS:
        for feature, addr in glob_handler():
            yield feature, addr


GLOBAL_HANDLERS = (extract_arch, extract_os, extract_file_format)
