import re
from typing import Dict, List, Tuple, Union, Iterator
from collections import defaultdict
from dataclasses import dataclass

from tree_sitter import Node, Tree, Parser

import capa.features.extractors.ts.sig
import capa.features.extractors.ts.build
from capa.features.address import FileOffsetRangeAddress
from capa.features.extractors.script import LANG_CS, LANG_JS
from capa.features.extractors.ts.query import (
    QueryBinding,
    HTMLQueryBinding,
    ScriptQueryBinding,
    QueryBindingFactory,
    TemplateQueryBinding,
)


class TreeSitterBaseEngine:
    buf: bytes
    language: str
    path: str
    query: QueryBinding
    tree: Tree

    def __init__(self, language: str, path: str):
        capa.features.extractors.ts.build.ts_build()
        self.language = language
        self.query = QueryBindingFactory.from_language(language)
        self.import_signatures = capa.features.extractors.ts.sig.load_import_signatures(language)
        self.path = path
        with open(self.path, "rb") as f:
            self.buf = f.read()
        self.tree = self.parse()

    def parse(self) -> Tree:
        parser = Parser()
        parser.set_language(self.query.language)
        return parser.parse(self.buf)

    def get_byte_range(self, node: Node) -> bytes:
        return self.buf[node.start_byte : node.end_byte]

    def get_range(self, node: Node) -> str:
        return self.get_byte_range(node).decode()

    def get_address(self, node: Node):
        return FileOffsetRangeAddress(node.start_byte, node.end_byte)

    def get_default_address(self):
        return self.get_address(self.tree.root_node)


class TreeSitterExtractorEngine(TreeSitterBaseEngine):
    query: ScriptQueryBinding
    import_signatures: set

    def __init__(self, language: str, path: str):
        super().__init__(language, path)

    def get_new_objects(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.new_object.captures(node)

    def get_object_id(self, node: Node) -> Node:
        return node.child_by_field_name(self.query.new_object_field_name)

    def get_new_object_ids(self, node: Node) -> Iterator[Node]:
        for obj_node, _ in self.get_new_objects(node):
            yield self.get_object_id(obj_node)

    # TODO: move this elsewhere, does not fit this class
    def get_import_names(self, node: Node) -> Iterator[Tuple[Node, str]]:
        join_names = capa.features.extractors.ts.sig.get_name_joiner(self.language)
        namespaces = set([self.get_range(ns_node) for ns_node, _ in self.get_namespaces()])
        for obj_node in self.get_new_object_ids(node):
            obj_name = self.get_range(obj_node)
            if obj_name in self.import_signatures:
                yield (obj_node, obj_name)
                continue
            for namespace in namespaces:
                obj_name = join_names(namespace, obj_name)
                if obj_name in self.import_signatures:
                    yield (obj_node, obj_name)

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

    # TODO: move this elsewhere, does not fit this class
    def get_function_names(self, node: Node) -> Iterator[Tuple[Node, str]]:
        join_names = capa.features.extractors.ts.sig.get_name_joiner(self.language)
        namespaces = set([self.get_range(ns_node) for ns_node, _ in self.get_namespaces()])
        for fn_node in self.get_function_call_ids(node):
            fn_name = self.get_range(fn_node)
            if fn_name in self.import_signatures:
                yield (fn_node, fn_name)
                continue
            for namespace in namespaces:
                fn_name = join_names(namespace, fn_name)
                if fn_name in self.import_signatures:
                    yield (fn_node, fn_name)

    def get_string_literals(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.string_literal.captures(node)

    def get_integer_literals(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.integer_literal.captures(node)

    def get_namespaces(self, node: Node = None) -> List[Tuple[Node, str]]:
        return self.query.namespace.captures(node if node is not None else self.tree.root_node)

    def get_global_statements(self) -> List[Tuple[Node, str]]:
        return self.query.global_statement.captures(self.tree.root_node)


@dataclass
class ASPXPseudoNode:
    start_byte: int
    end_byte: int


class TreeSitterTemplateEngine(TreeSitterBaseEngine):
    query: TemplateQueryBinding

    def __init__(self, language: str, path: str):
        super().__init__(language, path)

    def get_code_sections(self) -> List[Tuple[Node, str]]:
        return self.query.code.captures(self.tree.root_node)

    def get_content_sections(self) -> List[Tuple[Node, str]]:
        return self.query.content.captures(self.tree.root_node)

    def get_template_namespaces(self) -> Iterator[ASPXPseudoNode]:
        for node, _ in self.get_code_sections():
            if self.is_aspx_import_directive:
                ns = self.get_aspx_namespace(node)
                if ns is not None:
                    yield ns

    def is_aspx(self, node: Node) -> bool:
        return self.get_byte_range(node).startswith(b"@")

    def is_aspx_import_directive(self, node: Node) -> bool:
        return self.get_byte_range(node).startswith(b"@ Import namespace=")

    def get_aspx_namespace(self, node: Node) -> Union[ASPXPseudoNode, None]:
        match = re.search(r'@ Import namespace="(.*?)"'.encode(), self.get_byte_range(node))
        if match is None:
            return None
        return ASPXPseudoNode(node.start_byte + match.span()[0], node.start_byte + match.span()[1])


class TreeSitterHTMLEngine(TreeSitterBaseEngine):
    query: HTMLQueryBinding

    def __init__(self, language: str, path: str):
        super().__init__(language, path)

    def get_scripts(self) -> List[Tuple[Node, str]]:
        return self.query.script_element.captures(self.tree.root_node)

    def get_attributes(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.attribute.captures(self.tree.root_node)

    def get_code_sections_by_language(self) -> Dict[str, List[Node]]:
        code_sections = defaultdict(list)
        for script_node, _ in self.get_scripts():
            for attribute_node, _ in self.get_attributes(script_node):
                script_language = self.identify_script_language(attribute_node)
                code_sections[script_language].append(attribute_node)
        return code_sections

    def identify_script_language(self, node: Node) -> str:
        if self.is_server_side_c_sharp(node):
            return LANG_CS
        return LANG_JS

    def is_server_side_c_sharp(self, node: Node) -> bool:
        return len(re.findall(r'runat\s*=\s*"server"'.encode(), self.get_byte_range(node))) > 0
