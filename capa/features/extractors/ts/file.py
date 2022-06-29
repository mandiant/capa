from typing import Tuple, Iterator

import capa.features.extractors.script
from capa.features.file import Import, FunctionName
from capa.features.common import String, Feature, Namespace
from capa.features.address import Address
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine


def extract_file_format(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_format()


def extract_language(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_language(engine.get_language(), engine.get_default_address())


def extract_file_strings(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_all_string_literals():
        yield String(engine.get_range(node).strip('"')), engine.get_address(node)


def extract_namespaces(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_all_namespaces():
        yield Namespace(engine.get_range(node)), engine.get_address(node)


def extract_file_function_names(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, name in engine.get_all_function_names():
        yield FunctionName(name), engine.get_address(node)


def extract_file_import_names(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, name in engine.get_all_import_names():
        yield Import(name), engine.get_address(node)


def extract_features(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(engine):
            yield feature, addr


FILE_HANDLERS = (
    extract_file_strings,
    extract_file_function_names,
    extract_file_import_names,
    extract_file_format,
    extract_language,
)
