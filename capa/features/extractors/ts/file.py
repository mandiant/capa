from typing import Tuple, Iterator

import capa.features.extractors.script
import capa.features.extractors.ts.integer
from capa.features.common import Feature, Namespace
from capa.features.address import Address
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine


def extract_language(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_language(engine.language, engine.get_default_address())


def extract_namespaces(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_namespaces():
        yield Namespace(engine.get_range(node)), engine.get_address(node)


def extract_features(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(engine):
            yield feature, addr


FILE_HANDLERS = (
    extract_language,
    extract_namespaces,
)
