import re
from typing import List, Tuple, Iterator, Optional

from tree_sitter import Node, Tree, Parser

import capa.features.extractors.ts.build
from capa.features.address import FileOffsetRangeAddress
from capa.features.extractors.script import LANG_CS, LANG_JS, LANG_TEM, LANG_HTML
from capa.features.extractors.ts.query import (
    BINDINGS,
    QueryBinding,
    HTMLQueryBinding,
    ScriptQueryBinding,
    TemplateQueryBinding,
)
from capa.features.extractors.ts.tools import LANGUAGE_TOOLKITS, LanguageToolkit


class TreeSitterBaseEngine:
    buf: bytes
    language: str
    query: QueryBinding
    tree: Tree

    def __init__(self, language: str, buf: bytes):
        capa.features.extractors.ts.build.ts_build()
        self.language = language
        self.query = BINDINGS[language]
        self.buf = buf
        self.tree = self.parse()

    def parse(self) -> Tree:
        parser = Parser()
        parser.set_language(self.query.language)
        return parser.parse(self.buf)

    def get_byte_range(self, node: Node) -> bytes:
        return self.buf[node.start_byte : node.end_byte]

    def get_range(self, node: Node) -> str:
        return self.get_byte_range(node).decode()

    def get_address(self, node: Node) -> FileOffsetRangeAddress:
        return FileOffsetRangeAddress(node.start_byte, node.end_byte)

    def get_default_address(self) -> FileOffsetRangeAddress:
        return self.get_address(self.tree.root_node)


class TreeSitterExtractorEngine(TreeSitterBaseEngine):
    query: ScriptQueryBinding
    language_toolkit: LanguageToolkit
    buf_offset: int
    namespaces: set[str]

    def __init__(
        self,
        language: str,
        buf: bytes,
        buf_offset: int = 0,
        additional_namespaces: set[str] = None,
    ):
        super().__init__(language, buf)
        self.buf_offset = buf_offset
        self.language_toolkit = LANGUAGE_TOOLKITS[language]
        self.namespaces = set(self.get_range(ns_node) for ns_node, _ in self.get_namespaces())
        if additional_namespaces:
            self.namespaces = self.namespaces.union(additional_namespaces)

    def get_address(self, node: Node) -> FileOffsetRangeAddress:
        return FileOffsetRangeAddress(self.buf_offset + node.start_byte, self.buf_offset + node.end_byte)

    def get_new_object_names(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.new_object_name.captures(node)

    def get_assigned_property_names(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.assigned_property_name.captures(node)

    def get_function_definitions(self, node: Node = None) -> List[Tuple[Node, str]]:
        return self.query.function_definition.captures(node if node is not None else self.tree.root_node)

    def get_function_definition_name(self, node: Node) -> Node:
        return node.child_by_field_name(self.query.function_definition_field_name)

    def get_function_definition_names(self, node: Node) -> Iterator[Node]:
        for fn_node, _ in self.get_function_definitions(node):
            yield self.get_function_definition_name(fn_node)

    def get_function_call_names(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.function_call_name.captures(node)

    def get_string_literals(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.string_literal.captures(node)

    def get_integer_literals(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.integer_literal.captures(node)

    def get_namespaces(self, node: Node = None) -> List[Tuple[Node, str]]:
        return self.query.namespace.captures(node if node is not None else self.tree.root_node)

    def get_global_statements(self) -> List[Tuple[Node, str]]:
        return self.query.global_statement.captures(self.tree.root_node)

    def get_direct_method_call(self, node: Node) -> Node:
        return node.child_by_field_name(self.query.direct_method_call_field_name)

    def is_object_creation_expression(self, node: Node) -> bool:
        captures = self.get_new_object_names(node)
        if not captures:
            return False
        new_object_name_node, _ = captures[0]
        return new_object_name_node.parent.parent == node


class TreeSitterTemplateEngine(TreeSitterBaseEngine):
    query: TemplateQueryBinding
    language_toolkit: LanguageToolkit
    embedded_language: str

    def __init__(self, buf: bytes):
        super().__init__(LANG_TEM, buf)
        self.embedded_language = self.identify_language()
        self.language_toolkit = LANGUAGE_TOOLKITS[self.embedded_language]
        self.template_namespaces = set(name for _, name in self.get_template_namespaces())

    def get_code_sections(self) -> List[Tuple[Node, str]]:
        return self.query.code.captures(self.tree.root_node)

    def get_parsed_code_sections(self) -> Iterator[TreeSitterExtractorEngine]:
        for node, _ in self.get_code_sections():
            # TODO: support JS
            if self.embedded_language == LANG_CS:
                yield TreeSitterExtractorEngine(
                    self.embedded_language,
                    self.get_byte_range(node),
                    node.start_byte,
                    self.template_namespaces,
                )

    def get_content_sections(self) -> List[Tuple[Node, str]]:
        return self.query.content.captures(self.tree.root_node)

    def identify_language(self) -> str:
        for node, _ in self.get_code_sections():
            if self.is_c_sharp(node):
                return LANG_CS
        return LANG_JS

    def get_imported_namespaces(self) -> Iterator[Tuple[Node, str]]:
        for node, _ in self.get_code_sections():
            if self.is_aspx_import_directive(node):
                namespace = self.get_aspx_namespace(node)
                if namespace is not None:
                    yield node, namespace

    def get_template_namespaces(self) -> Iterator[Tuple[Optional[Node], str]]:
        for namespace in self.language_toolkit.get_default_namespaces(True):
            yield None, namespace
        for node, namespace in self.get_imported_namespaces():
            yield node, namespace

    def is_c_sharp(self, node: Node) -> bool:
        return bool(
            re.match(
                r'@ .*Page Language\s*=\s*"C#".*'.encode(),
                self.get_byte_range(node),
                re.IGNORECASE,
            )
        )

    def is_aspx_import_directive(self, node: Node) -> bool:
        return bool(
            re.match(
                r"@\s*Import Namespace=".encode(),
                self.get_byte_range(node),
                re.IGNORECASE,
            )
        )

    def get_aspx_namespace(self, node: Node) -> Optional[str]:
        match = re.search(
            r'@\s*Import namespace="(.*?)"'.encode(),
            self.get_byte_range(node),
            re.IGNORECASE,
        )
        return match.group(1).decode() if match is not None else None


class TreeSitterHTMLEngine(TreeSitterBaseEngine):
    query: HTMLQueryBinding
    namespaces: set[str]

    def __init__(self, buf: bytes, additional_namespaces: set[str] = None):
        super().__init__(LANG_HTML, buf)
        self.namespaces = additional_namespaces if additional_namespaces is not None else set()

    def get_scripts(self) -> List[Tuple[Node, str]]:
        return self.query.script_element.captures(self.tree.root_node)

    def get_attributes(self, node: Node) -> List[Tuple[Node, str]]:
        return self.query.attribute.captures(node)

    def get_identified_scripts(self) -> Iterator[Tuple[Node, str]]:
        for node, _ in self.get_scripts():
            for content_node, _ in self.get_script_contents(node):
                yield content_node, self.identify_language(node)

    def get_script_contents(self, node: Node) -> Iterator[Tuple[Node, str]]:
        return self.query.script_content.captures(node)

    def get_parsed_code_sections(self) -> Iterator[TreeSitterExtractorEngine]:
        for node, language in self.get_identified_scripts():
            # TODO: support JS
            if language == LANG_CS:
                yield TreeSitterExtractorEngine(language, self.get_byte_range(node), node.start_byte, self.namespaces)

    def identify_language(self, node: Node) -> str:
        for attribute_node, _ in self.get_attributes(node):
            if self.is_server_side_c_sharp(attribute_node):
                return LANG_CS
        return LANG_JS

    def is_server_side_c_sharp(self, node: Node) -> bool:
        return len(re.findall(r'runat\s*=\s*"server"'.encode(), self.get_byte_range(node))) > 0
