import functools
import itertools
from os import extsep
from typing import Tuple, Callable, Iterator
from dataclasses import dataclass

from tree_sitter import Node

import capa.features.extractors.ts.integer
from capa.features.insn import API, Number, Property
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine
from capa.features.extractors.base_extractor import FunctionHandle

PSEUDO_MAIN = "PSEUDO MAIN"


@dataclass
class TSFunctionInner:
    node: Node
    name: str
    engine: TreeSitterExtractorEngine


def is_pseudo_main_function(fh: FunctionHandle, engine: TreeSitterExtractorEngine) -> bool:
    return (
        fh.address == engine.get_default_address()
        and fh.inner.node == engine.tree.root_node
        and fh.inner.name == PSEUDO_MAIN
    )


def extract_strings(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_string_literals(fn_node):
        yield String(engine.get_range(node).strip('"')), engine.get_address(node)


def extract_integer_literals(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_integer_literals(fn_node):
        parsed_int = capa.features.extractors.ts.integer.parse_integer(engine.get_range(node), engine.language)
        if parsed_int is not None:
            yield Number(parsed_int), engine.get_address(node)


def extract_imports_(name: str, engine: TreeSitterExtractorEngine) -> Iterator[str]:
    for namespace in itertools.chain([""], engine.namespaces):
        joined_name = engine.language_toolkit.join_names(namespace, name)
        if engine.language_toolkit.is_import(joined_name):
            yield joined_name


def extract_classes(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_new_object_names(fn_node):
        for name in extract_imports_(engine.get_range(node), engine):
            yield API(engine.language_toolkit.format_imported_class(name)), engine.get_address(node)


def extract_properties(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_assigned_property_names(fn_node):
        for name in extract_imports_(engine.get_range(node), engine):
            yield Property(engine.language_toolkit.format_imported_property(name)), engine.get_address(node)


def extract_static_methods_(node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for name in extract_imports_(engine.get_range(node), engine):
        yield API(engine.language_toolkit.format_imported_function(name)), engine.get_address(node)


def extract_regular_methods_(node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    qualified_names = engine.language_toolkit.split_name(engine.get_range(node))
    if len(qualified_names) > 1:
        for name in extract_imports_(engine.language_toolkit.join_names(*qualified_names[1:]), engine):
            yield API(engine.language_toolkit.format_imported_function(name)), engine.get_address(node)


def extract_function_calls(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_function_call_names(fn_node):
        yield from extract_static_methods_(node, engine)
        yield from extract_regular_methods_(node, engine)


def extract_pseudo_main_features(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_global_statements():
        yield from extract_features_(node, engine)


def extract_features_(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for function_handler in FUNCTION_HANDLERS:
        for feature, addr in function_handler(fn_node, engine):
            yield feature, addr


def extract_features(fh: FunctionHandle, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    if is_pseudo_main_function(fh, engine):
        yield from extract_pseudo_main_features(engine)
    else:
        yield from extract_features_(fh.inner.node, engine)


FUNCTION_HANDLERS = (
    extract_classes,
    extract_properties,
    extract_function_calls,
    extract_integer_literals,
    extract_strings,
)
