import itertools
from typing import Tuple, Iterator
from dataclasses import dataclass

from tree_sitter import Node

from capa.features.insn import API, Number, Property
from capa.features.common import Class, String, Feature, Namespace
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


def get_possible_full_names(name: str, namespaces: set[BaseNamespace]) -> Iterator[str]:
    yield name
    for namespace in namespaces:
        yield namespace.join(name)


def get_default_constructor(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[str]:
    for name_node in engine.get_new_object_names(fn_node):
        for full_name in get_possible_full_names(engine.get_str(name_node), engine.namespaces):
            if engine.language_toolkit.is_imported_class(full_name):
                yield full_name


def get_custom_constructor(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[str]:
    for name_node in engine.get_function_call_names(fn_node):
        for full_name in get_possible_full_names(engine.get_str(name_node), engine.namespaces):
            if engine.language_toolkit.is_imported_constructor(full_name):
                yield full_name


def get_classes(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[str]:
    yield from get_default_constructor(fn_node, engine)
    yield from get_custom_constructor(fn_node, engine)


def _extract_default_constructor(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for name_node in engine.get_new_object_names(fn_node):
        for full_name in get_possible_full_names(engine.get_str(name_node), engine.namespaces):
            if engine.language_toolkit.is_imported_class(full_name):
                yield Namespace(full_name), engine.get_address(name_node)
                yield Class(engine.language_toolkit.format_imported_class(full_name)), engine.get_address(name_node)
                yield API(engine.language_toolkit.format_imported_default_constructor(full_name)), engine.get_address(
                    name_node
                )


def _extract_custom_constructor(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for name_node in engine.get_function_call_names(fn_node):
        for full_name in get_possible_full_names(engine.get_str(name_node), engine.namespaces):
            if engine.language_toolkit.is_imported_constructor(full_name):
                yield Namespace(full_name), engine.get_address(name_node)
                yield Class(engine.language_toolkit.format_imported_class(full_name)), engine.get_address(name_node)
                yield API(engine.language_toolkit.format_imported_custom_constructor(full_name)), engine.get_address(
                    name_node
                )


def _extract_classes(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    yield from _extract_default_constructor(fn_node, engine)
    yield from _extract_custom_constructor(fn_node, engine)


def _extract_constants(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for ic_node, ic_name in engine.get_processed_imported_constants(fn_node):
        for full_name in get_possible_full_names(ic_name, engine.namespaces):
            if engine.language_toolkit.is_imported_constant(full_name):
                yield API(engine.language_toolkit.format_imported_constant(full_name)), engine.get_address(ic_node)


def _extract_properties(
    fn_node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for pt_node, pt_name in engine.get_processed_property_names(fn_node):
        for full_name in get_possible_full_names(pt_name, classes):
            if engine.language_toolkit.is_imported_property(full_name):
                yield Property(engine.language_toolkit.format_imported_property(full_name)), engine.get_address(pt_node)


def _extract_static_methods(node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    if engine.language_toolkit.is_builtin(engine.get_str(node)):
        yield API(engine.language_toolkit.get_builtin_name(engine.get_str(node))), engine.get_address(node)
    for full_name in get_possible_full_names(engine.get_str(node), engine.namespaces):
        if engine.language_toolkit.is_imported_function(full_name):
            yield API(engine.language_toolkit.format_imported_function(full_name)), engine.get_address(node)


def _do_extract_instance_methods(
    node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for full_name in get_possible_full_names(
        engine.language_toolkit.get_member_from_name(engine.get_str(node)), classes
    ):
        if engine.language_toolkit.is_imported_function(full_name):
            yield API(engine.language_toolkit.format_imported_function(full_name)), engine.get_address(node)


def _extract_instance_methods(
    node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    direct_method_call_node = engine.get_direct_method_call(node)  # eg new Foo.Bar().direct_method_call(x, y, 3)
    if direct_method_call_node:
        yield from _do_extract_instance_methods(direct_method_call_node, classes, engine)
    else:
        yield from _do_extract_instance_methods(node, classes, engine)


def _extract_function_calls(
    fn_node: Node, classes: set[BaseNamespace], engine: TreeSitterExtractorEngine
) -> Iterator[Tuple[Feature, Address]]:
    for node in engine.get_function_call_names(fn_node):
        yield from _extract_static_methods(node, engine)
        yield from _extract_instance_methods(node, classes, engine)


def extract_imports(fn_node: Node, engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    classes = {engine.language_toolkit.create_namespace(cls) for cls in get_classes(fn_node, engine)}
    yield from _extract_classes(fn_node, engine)
    yield from _extract_constants(fn_node, engine)
    yield from _extract_properties(fn_node, classes, engine)
    yield from _extract_function_calls(fn_node, classes, engine)


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
    extract_imports,
    extract_integers,
    extract_strings,
)
