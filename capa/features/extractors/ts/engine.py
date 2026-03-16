# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
from typing import List, Tuple, Iterator, Optional

from tree_sitter import Node, Tree, Parser, QueryCursor

import capa.features.extractors.ts.autodetect
from capa.features.address import FileOffsetRangeAddress
from capa.features.extractors.script import LANG_CS, LANG_JS, LANG_TEM, LANG_HTML
from capa.features.extractors.ts.query import (
    BINDINGS,
    QueryBinding,
    HTMLQueryBinding,
    ScriptQueryBinding,
    TemplateQueryBinding,
)
from capa.features.extractors.ts.tools import LANGUAGE_TOOLKITS, BaseNamespace, CSharpNamespace, LanguageToolkit


class TreeSitterBaseEngine:
    buf: bytes
    language: str
    query: QueryBinding
    tree: Tree

    def __init__(self, language: str, buf: bytes):
        self.language = language
        self.query = BINDINGS[language]
        self.buf = buf
        self.tree = self.parse()

    def parse(self) -> Tree:
        parser = Parser(self.query.language)
        return parser.parse(self.buf)

    def get_byte_range(self, node: Node) -> bytes:
        return self.buf[node.start_byte : node.end_byte]

    def get_str(self, node: Node) -> str:
        return self.get_byte_range(node).decode("utf-8")

    def get_address(self, node: Node) -> FileOffsetRangeAddress:
        return FileOffsetRangeAddress(node.start_byte, node.end_byte)

    def get_default_address(self) -> FileOffsetRangeAddress:
        return self.get_address(self.tree.root_node)


class TreeSitterExtractorEngine(TreeSitterBaseEngine):
    query: ScriptQueryBinding
    language_toolkit: LanguageToolkit
    buf_offset: int
    namespaces: set[BaseNamespace]

    def __init__(
        self,
        language: str,
        buf: bytes,
        buf_offset: int = 0,
        additional_namespaces: set[BaseNamespace] | None = None,
    ):
        super().__init__(language, buf)
        self.buf_offset = buf_offset
        self.language_toolkit = LANGUAGE_TOOLKITS[language]

        if additional_namespaces is None:
            additional_namespaces = set()

        self.namespaces = set(self.get_processed_namespaces())
        self.namespaces = self.namespaces.union(additional_namespaces)

    def get_address(self, node: Node) -> FileOffsetRangeAddress:
        return FileOffsetRangeAddress(self.buf_offset + node.start_byte, self.buf_offset + node.end_byte)

    def get_new_object_names(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.new_object_name)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_property_names(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.property_name)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_processed_property_names(self, node: Node) -> Iterator[Tuple[Node, str]]:
        """Generates captured property name nodes and their associated proper names (see process_property
        for details), e.g.: [(node0, "StartInfo"), (node1, "RedirectStandardOutput")]."""
        for pt_node in self.get_property_names(node):
            pt_name = self.language_toolkit.process_property(pt_node, self.get_str(pt_node))
            if pt_name:
                yield pt_node, pt_name

    def get_function_definitions(self, node: Optional[Node] = None) -> Iterator[Node]:
        node = self.tree.root_node if node is None else node
        cursor = QueryCursor(self.query.function_definition)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_function_definition_name(self, node: Node) -> Node | None:
        return node.child_by_field_name(self.query.function_definition_field_name)

    def get_function_definition_names(self, node: Node) -> Iterator[Node]:
        for fd_node in self.get_function_definitions(node):
            name_node = self.get_function_definition_name(fd_node)
            if name_node is not None:
                yield name_node

    def get_function_call_names(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.function_call_name)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_imported_constants(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.imported_constant_name)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_processed_imported_constants(self, node: Node) -> Iterator[Tuple[Node, str]]:
        """Generates captured imported constant nodes and their associated proper names (see process_imported_constant
        for details), e.g.: [(node0, "ssl.CERT_NONE"), (node1, "win32con.FILE_ATTRIBUTE_HIDDEN")]."""
        for ic_node in self.get_imported_constants(node):
            ic_name = self.language_toolkit.process_imported_constant(ic_node, self.get_str(ic_node))
            if ic_name:
                yield ic_node, ic_name

    def get_string_literals(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.string_literal)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_integer_literals(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.integer_literal)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_namespaces(self, node: Optional[Node] = None) -> List[Tuple[Node, str]]:
        cursor = QueryCursor(self.query.namespace)
        captures = cursor.captures(self.tree.root_node if node is None else node)
        return [(ns_node, query_name) for query_name, nodes in captures.items() for ns_node in nodes]

    def get_processed_namespaces(self, node: Optional[Node] = None) -> Iterator[BaseNamespace]:
        for ns_node, query_name in self.get_namespaces(node):
            yield from self.language_toolkit.process_namespace(ns_node, query_name, self.get_str)

    def get_global_statements(self) -> Iterator[Node]:
        cursor = QueryCursor(self.query.global_statement)
        for nodes in cursor.captures(self.tree.root_node).values():
            yield from nodes

    def get_direct_method_call(self, node: Node) -> Optional[Node]:
        cursor = QueryCursor(self.query.direct_method_call)
        captures = cursor.captures(node)
        for nodes in captures.values():
            if nodes:
                return nodes[0]
        return None


class TreeSitterTemplateEngine(TreeSitterBaseEngine):
    query: TemplateQueryBinding
    language_toolkit: LanguageToolkit
    embedded_language: str
    namespaces: set[BaseNamespace]

    def __init__(self, buf: bytes):
        super().__init__(LANG_TEM, buf)
        self.embedded_language = self.identify_language()
        self.language_toolkit = LANGUAGE_TOOLKITS[self.embedded_language]
        self.namespaces = set(self.get_namespaces())

    def get_code_sections(self) -> Iterator[Node]:
        cursor = QueryCursor(self.query.code)
        for nodes in cursor.captures(self.tree.root_node).values():
            yield from nodes

    def get_parsed_code_sections(self) -> Iterator[TreeSitterExtractorEngine]:
        for node in self.get_code_sections():
            # TODO(EdoardoAllegrini): support JS
            # https://github.com/mandiant/capa/issues/1092
            if self.embedded_language == LANG_CS:
                yield TreeSitterExtractorEngine(
                    self.embedded_language,
                    self.get_byte_range(node),
                    node.start_byte,
                    self.namespaces,
                )
            else:
                raise ValueError(f"parsing of {self.embedded_language} is not supported")

    def get_content_sections(self) -> Iterator[Node]:
        cursor = QueryCursor(self.query.content)
        for nodes in cursor.captures(self.tree.root_node).values():
            yield from nodes

    def identify_language(self) -> str:
        for node in self.get_code_sections():
            if self.is_c_sharp(node):
                return LANG_CS
            try:
                return capa.features.extractors.ts.autodetect.get_template_language_ts(self.get_byte_range(node))
            except ValueError:
                continue
        raise ValueError("failed to identify the template language")

    def get_imported_namespaces(self) -> Iterator[BaseNamespace]:
        for node in self.get_code_sections():
            if self.is_aspx_import_directive(node):
                namespace = self.get_aspx_namespace(node)
                if namespace is not None:
                    yield namespace

    def get_namespaces(self) -> Iterator[BaseNamespace]:
        yield from self.language_toolkit.get_default_namespaces(True)
        yield from self.get_imported_namespaces()

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

    def get_aspx_namespace(self, node: Node) -> Optional[BaseNamespace]:
        match = re.search(
            r'@\s*Import namespace="(.*?)"'.encode(),
            self.get_byte_range(node),
            re.IGNORECASE,
        )
        return CSharpNamespace(match.group(1).decode("utf-8"), node) if match is not None else None


class TreeSitterHTMLEngine(TreeSitterBaseEngine):
    query: HTMLQueryBinding
    namespaces: set[BaseNamespace]

    def __init__(self, buf: bytes, namespaces: set[BaseNamespace] | None = None):
        super().__init__(LANG_HTML, buf)
        self.namespaces = namespaces if namespaces is not None else set()

    def get_scripts(self) -> Iterator[Node]:
        cursor = QueryCursor(self.query.script_element)
        for nodes in cursor.captures(self.tree.root_node).values():
            yield from nodes

    def get_attributes(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.attribute)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_identified_scripts(self) -> Iterator[Tuple[Node, str]]:
        for node in self.get_scripts():
            for content_node in self.get_script_contents(node):
                yield content_node, self.identify_language(node)

    def get_script_contents(self, node: Node) -> Iterator[Node]:
        cursor = QueryCursor(self.query.script_content)
        for nodes in cursor.captures(node).values():
            yield from nodes

    def get_parsed_code_sections(self) -> Iterator[TreeSitterExtractorEngine]:
        for node, language in self.get_identified_scripts():
            # TODO(EdoardoAllegrini): support JS
            # # https://github.com/mandiant/capa/issues/1092
            if language == LANG_CS:
                yield TreeSitterExtractorEngine(language, self.get_byte_range(node), node.start_byte, self.namespaces)

    def identify_language(self, node: Node) -> str:
        for att_node in self.get_attributes(node):
            if self.is_server_side_c_sharp(att_node):
                return LANG_CS
        return LANG_JS

    def is_server_side_c_sharp(self, node: Node) -> bool:
        return bool(re.findall(r'runat\s*=\s*"server"'.encode(), self.get_byte_range(node)))
