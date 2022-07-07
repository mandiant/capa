from typing import Tuple, Iterator

import capa.features.extractors.script
from capa.features.file import Import, FunctionName
from capa.features.insn import Number
from capa.features.common import String, Feature, Namespace
from capa.features.address import Address
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine


def extract_language(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_language(engine.language, engine.get_default_address())


def extract_file_strings(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for global_node, _ in engine.get_global_statements():
        for node, _ in engine.get_string_literals(global_node):
            yield String(engine.get_range(node).strip('"')), engine.get_address(node)


def extract_file_integer_literals(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for global_node, _ in engine.get_global_statements():
        for node, _ in engine.get_integer_literals(global_node):
            yield Number(int(engine.get_range(node))), engine.get_address(node)


def extract_namespaces(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_namespaces():
        yield Namespace(engine.get_range(node)), engine.get_address(node)


def extract_file_function_names(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for global_node, _ in engine.get_global_statements():
        for node, name in engine.get_function_names(global_node):
            yield FunctionName(name), engine.get_address(node)


def extract_file_import_names(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for global_node, _ in engine.get_global_statements():
        for node, name in engine.get_import_names(global_node):
            yield Import(name), engine.get_address(node)


def extract_features(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(engine):
            yield feature, addr


FILE_HANDLERS = (
    extract_file_function_names,
    extract_file_import_names,
    extract_file_integer_literals,
    extract_file_strings,
    extract_language,
    extract_namespaces,
)
