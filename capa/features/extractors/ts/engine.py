from typing import List, Tuple, Iterator

from tree_sitter import Node, Tree, Parser

import capa.features.extractors.ts.sig
import capa.features.extractors.ts.build
import capa.features.extractors.ts.query
from capa.features.address import FileOffsetRangeAddress
from capa.features.extractors.ts.query import QueryBinding


class TreeSitterExtractorEngine:
    query: QueryBinding
    path: str
    buf: bytes
    tree: Tree
    import_signatures: set

    def __init__(self, language: str, path: str):
        capa.features.extractors.ts.build.ts_build()
        self.language = language
        self.query = capa.features.extractors.ts.query.QueryBinding(language)
        self.import_signatures = capa.features.extractors.ts.sig.load_import_signatures(language)
        self.path = path
        with open(self.path, "rb") as f:
            self.buf = f.read()
        self.parse()

    def get_language(self):
        return self.language

    def get_ts_language(self):
        return self.query.language

    def parse(self):
        self.parser = Parser()
        self.parser.set_language(self.get_ts_language())
        self.tree = self.parser.parse(self.buf)

    def get_new_objects(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.new_object.captures(node)

    def get_object_id(self, node: Node) -> Node:
        return node.child_by_field_name(self.query.new_object_field_name)

    def get_new_object_ids(self, node: Node) -> Iterator[Node]:
        for obj_node, _ in self.get_new_objects(node):
            yield self.get_object_id(obj_node)

    def get_import_names(self, node: Node) -> List[Tuple[Node, str]]:
        join_names = capa.features.extractors.ts.sig.get_name_joiner(self.language)
        import_names = []
        namespaces = set([self.get_range(node) for node, _ in self.get_all_namespaces()])
        for node, _ in self.get_new_object_ids(node):
            for namespace in namespaces:
                name = join_names(namespace, self.get_range(node))
                if name in self.import_signatures:
                    import_names.append(name)
        return import_names

    def get_function_definitions(self, node: Node = None) -> List[Tuple[Node, str]]:
        return self.query.function_definition.captures(node if node is not None else self.tree.root_node)

    def get_function_definition_id(self, node: Node) -> Node:
        return node.child_by_field_name(self.query.function_definition_field_name)

    def get_function_definition_ids(self, node: Node) -> Iterator[Node]:
        for fn_node, _ in self.get_function_definitions(node):
            yield self.get_function_definition_id(fn_node)

    def get_function_calls(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.function_call.captures(node)

    def get_function_call_id(self, node: Node) -> Node:
        return node.child_by_field_name(self.query.function_call_field_name)

    def get_function_call_ids(self, node: Node) -> Iterator[Node]:
        for fn_node, _ in self.get_function_calls(node):
            yield self.get_function_call_id(fn_node)

    def get_function_names(self, node: Node) -> List[Tuple[Node, str]]:
        join_names = capa.features.extractors.ts.sig.get_name_joiner(self.language)
        function_names = []
        namespaces = set([self.get_range(node) for node, _ in self.get_all_namespaces()])
        for node, _ in self.get_function_call_ids(node):
            for namespace in namespaces:
                name = join_names(namespace, self.get_range(node))
                if name in self.import_signatures:
                    function_names.append(name)
        return function_names

    def get_string_literals(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.string_literal.captures(node)

    def get_integer_literals(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.integer_literal.captures(node)

    def get_namespaces(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.namespace.captures(node)

    def get_all_namespaces(self) -> List[Tuple[Node, str]]:
        return self.get_namespaces(self.tree.root_node)

    def get_global_statements(self) -> List[Tuple[Node, str]]:
        return self.query.global_statement.captures(self.tree.root_node)

    def get_range(self, node: Node) -> str:
        return self.buf[node.start_byte : node.end_byte].decode()

    def get_address(self, node: Node):
        return FileOffsetRangeAddress(node.start_byte, node.end_byte)

    def get_default_address(self):
        return self.get_address(self.tree.root_node)
