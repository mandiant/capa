from typing import Tuple, Iterator
from dataclasses import dataclass

from tree_sitter import Node

import capa.features.extractors.ts.integer
from capa.features.file import Import, FunctionName
from capa.features.insn import Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine
from capa.features.extractors.base_extractor import FunctionHandle


@dataclass
class TSFunctionInner:
    node: Node
    name: str


def extract_strings(fh: FunctionHandle, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_string_literals(fh.inner.node):
        yield String(engine.get_range(node).strip('"')), engine.get_address(node)


def extract_integer_literals(
    fh: FunctionHandle, engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_integer_literals(fh.inner.node):
        parsed_int = capa.features.extractors.ts.integer.parse_integer(engine.get_range(node), engine.language)
        if parsed_int is not None:
            yield Number(parsed_int), engine.get_address(node)


def extract_function_names(fh: FunctionHandle, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, name in engine.get_function_names(fh.inner.node):
        yield FunctionName(name), engine.get_address(node)


def extract_import_names(fh: FunctionHandle, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, name in engine.get_import_names(fh.inner.node):
        yield Import(name), engine.get_address(node)


def extract_features(fh: FunctionHandle, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FUNCTION_HANDLERS:
        for feature, addr in file_handler(fh=fh, engine=engine):
            yield feature, addr


FUNCTION_HANDLERS = (
    extract_function_names,
    extract_import_names,
    extract_integer_literals,
    extract_strings,
)
