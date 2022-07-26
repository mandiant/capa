from typing import Tuple, Iterator
from dataclasses import dataclass

from tree_sitter import Node

from capa.features.insn import API, Number, Property
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.ts.tools import BaseNamespace
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine
from capa.features.extractors.base_extractor import FunctionHandle

PSEUDO_MAIN = "PSEUDO MAIN"  # all global statements in one function scope


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
        parsed_str = engine.language_toolkit.parse_string(engine.get_range(node))
        if parsed_str is not None:
            yield String(parsed_str), engine.get_address(node)


def extract_integers(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_integer_literals(fn_node):
        parsed_int = engine.language_toolkit.parse_integer(engine.get_range(node))
        if parsed_int is not None:
            yield Number(parsed_int), engine.get_address(node)


def get_imports(name: str, namespaces: set[BaseNamespace], engine: TreeSitterExtractorEngine) -> Iterator[str]:
    if engine.language_toolkit.is_import(name):
        yield name
    for namespace in namespaces:
        namespace_join_name = namespace.get_join_name()
        if not namespace_join_name:
            continue
        joined_name = engine.language_toolkit.join_names(namespace_join_name, name)
        if engine.language_toolkit.is_import(joined_name):
            yield joined_name


def get_properties(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Node, str]]:
    for node, _ in engine.get_assigned_property_names(fn_node):
        qualified_names = engine.language_toolkit.split_name(engine.get_range(node))
        if len(qualified_names) > 1:
            yield node, engine.language_toolkit.join_names(*qualified_names[1:])


def get_classes(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[str]:
    for node, _ in engine.get_new_object_names(fn_node):
        for name in get_imports(engine.get_range(node), engine.namespaces, engine):
            yield name


def extract_classes_(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_new_object_names(fn_node):
        for name in get_imports(engine.get_range(node), engine.namespaces, engine):
            yield API(engine.language_toolkit.format_imported_class(name)), engine.get_address(node)


def extract_properties_(
    fn_node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for node, property_name in get_properties(fn_node, engine):
        for name in get_imports(property_name, classes, engine):
            yield Property(engine.language_toolkit.format_imported_property(name)), engine.get_address(node)


def extract_static_methods_(node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for name in get_imports(engine.get_range(node), engine.namespaces, engine):
        yield API(engine.language_toolkit.format_imported_function(name)), engine.get_address(node)


def extract_regular_methods_(
    node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    direct_method_call_node = engine.get_direct_method_call(node)
    if direct_method_call_node is not None:
        node = direct_method_call_node
    qualified_names = engine.language_toolkit.split_name(engine.get_range(node))
    property_name = (
        qualified_names[0] if len(qualified_names) == 1 else engine.language_toolkit.join_names(*qualified_names[1:])
    )
    for name in get_imports(property_name, classes, engine):
        yield API(engine.language_toolkit.format_imported_function(name)), engine.get_address(node)


def extract_api(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    classes = {engine.language_toolkit.create_namespace(cls) for cls in get_classes(fn_node, engine)}
    yield from extract_classes_(fn_node, engine)
    yield from extract_function_calls_(fn_node, classes, engine)
    yield from extract_properties_(fn_node, classes, engine)


def extract_function_calls_(
    fn_node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for node, _ in engine.get_function_call_names(fn_node):
        yield from extract_static_methods_(node, engine)
        yield from extract_regular_methods_(node, classes, engine)


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
    extract_api,
    extract_integers,
    extract_strings,
)
