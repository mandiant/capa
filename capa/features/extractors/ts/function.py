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
    for node in engine.get_string_literals(fn_node):
        yield String(engine.language_toolkit.parse_string(engine.get_str(node))), engine.get_address(node)


def extract_integers(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node in engine.get_integer_literals(fn_node):
        try:
            yield Number(engine.language_toolkit.parse_integer(engine.get_str(node))), engine.get_address(node)
        except ValueError:
            continue


def get_imports(name: str, namespaces: set[BaseNamespace], engine: TreeSitterExtractorEngine) -> Iterator[str]:
    if engine.language_toolkit.is_builtin(name):
        yield name
    if engine.language_toolkit.is_import(name):
        yield name
    for namespace in namespaces:
        if engine.language_toolkit.is_import(name, namespace):
            yield namespace.join(name)


def get_classes(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[str]:
    for node in engine.get_new_object_names(fn_node):
        for name in get_imports(engine.get_str(node), engine.namespaces, engine):
            yield name


def _extract_classes(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node in engine.get_new_object_names(fn_node):
        for name in get_imports(engine.get_str(node), engine.namespaces, engine):
            yield API(engine.language_toolkit.format_imported_class(name)), engine.get_address(node)


def _extract_properties(
    fn_node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for pt_node, pt_name in engine.get_processed_property_names(fn_node):
        for name in get_imports(pt_name, classes, engine):
            yield Property(engine.language_toolkit.format_imported_property(name)), engine.get_address(pt_node)


def _extract_static_methods(node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for name in get_imports(engine.get_str(node), engine.namespaces, engine):
        yield API(engine.language_toolkit.format_imported_function(name)), engine.get_address(node)


def get_property_name(node: Node, engine: TreeSitterExtractorEngine) -> str:
    qualified_names = engine.language_toolkit.split_name(engine.get_str(node))
    if len(qualified_names) == 1:
        return qualified_names[0]
    return engine.language_toolkit.join_names(*qualified_names[1:])


def _extract_instance_methods(
    node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    direct_method_call_node = engine.get_direct_method_call(node)
    node = node if direct_method_call_node is None else direct_method_call_node
    property_name = get_property_name(node, engine)
    for name in get_imports(property_name, classes, engine):
        yield API(engine.language_toolkit.format_imported_function(name)), engine.get_address(node)


def extract_api(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    classes = {engine.language_toolkit.create_namespace(cls) for cls in get_classes(fn_node, engine)}
    yield from _extract_classes(fn_node, engine)
    yield from _extract_imported_constants(fn_node, engine)
    yield from _extract_function_calls(fn_node, classes, engine)
    yield from _extract_properties(fn_node, classes, engine)


def _extract_function_calls(
    fn_node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for node in engine.get_function_call_names(fn_node):
        yield from _extract_static_methods(node, engine)
        yield from _extract_instance_methods(node, classes, engine)


def _extract_imported_constants(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for ic_node, ic_name in engine.get_processed_imported_constants(fn_node):
        for name in get_imports(ic_name, engine.namespaces, engine):
            yield API(engine.language_toolkit.format_imported_constant(name)), engine.get_address(ic_node)


def _extract_pseudo_main_features(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for node in engine.get_global_statements():
        yield from _extract_features(node, engine)


def _extract_features(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for function_handler in FUNCTION_HANDLERS:
        for feature, addr in function_handler(fn_node, engine):
            yield feature, addr


def extract_features(fh: FunctionHandle, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    if is_pseudo_main_function(fh, engine):
        yield from _extract_pseudo_main_features(engine)
    else:
        yield from _extract_features(fh.inner.node, engine)


FUNCTION_HANDLERS = (
    extract_api,
    extract_integers,
    extract_strings,
)
