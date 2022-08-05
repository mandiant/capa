import re
from typing import List, Tuple, Iterator, Optional

from tree_sitter import Node, Tree, Parser

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
        parser = Parser()
        parser.set_language(self.query.language)
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
        additional_namespaces: set[BaseNamespace] = set(),
    ):
        super().__init__(language, buf)
        self.buf_offset = buf_offset
        self.language_toolkit = LANGUAGE_TOOLKITS[language]
        self.namespaces = set(self.get_processed_namespaces())
        self.namespaces = self.namespaces.union(additional_namespaces)

    def get_address(self, node: Node) -> FileOffsetRangeAddress:
        return FileOffsetRangeAddress(self.buf_offset + node.start_byte, self.buf_offset + node.end_byte)

    def get_new_object_names(self, node: Node) -> Iterator[Node]:
        for obj_node, _ in self.query.new_object_name.captures(node):
            yield obj_node

    def get_property_names(self, node: Node) -> Iterator[Node]:
        for pt_node, _ in self.query.property_name.captures(node):
            yield pt_node

    def get_processed_property_names(self, node: Node) -> Iterator[Tuple[Node, str]]:
        """Generates captured property name nodes and their associated proper names (see process_property
        for details), e.g.: [(node0, "StartInfo"), (node1, "RedirectStandardOutput")]."""
        for pt_node in self.get_property_names(node):
            pt_name = self.language_toolkit.process_property(pt_node, self.get_str(pt_node))
            if pt_name:
                yield pt_node, pt_name

    def get_function_definitions(self, node: Optional[Node] = None) -> Iterator[Node]:
        node = self.tree.root_node if node is None else node
        for fd_node, _ in self.query.function_definition.captures(node):
            yield fd_node

    def get_function_definition_name(self, node: Node) -> Node:
        return node.child_by_field_name(self.query.function_definition_field_name)

    def get_function_definition_names(self, node: Node) -> Iterator[Node]:
        for fd_node in self.get_function_definitions(node):
            yield self.get_function_definition_name(fd_node)

    def get_function_call_names(self, node: Node) -> Iterator[Node]:
        for fcn_node, _ in self.query.function_call_name.captures(node):
            yield fcn_node

    def get_imported_constants(self, node: Node) -> Iterator[Node]:
        for ic_node, _ in self.query.imported_constant_name.captures(node):
            yield ic_node

    def get_processed_imported_constants(self, node: Node) -> Iterator[Tuple[Node, str]]:
        """Generates captured imported constant nodes and their associated proper names (see process_imported_constant
        for details), e.g.: [(node0, "ssl.CERT_NONE"), (node1, "win32con.FILE_ATTRIBUTE_HIDDEN")]."""
        for ic_node in self.get_imported_constants(node):
            ic_name = self.language_toolkit.process_imported_constant(ic_node, self.get_str(ic_node))
            if ic_name:
                yield ic_node, ic_name

    def get_string_literals(self, node: Node) -> Iterator[Node]:
        for str_node, _ in self.query.string_literal.captures(node):
            yield str_node

    def get_integer_literals(self, node: Node) -> Iterator[Node]:
        for int_node, _ in self.query.integer_literal.captures(node):
            yield int_node

    def get_namespaces(self, node: Optional[Node] = None) -> List[Tuple[Node, str]]:
        return self.query.namespace.captures(self.tree.root_node if node is None else node)

    def get_processed_namespaces(self, node: Optional[Node] = None) -> Iterator[BaseNamespace]:
        for ns_node, query_name in self.get_namespaces(node):
            for namespace in self.language_toolkit.process_namespace(ns_node, query_name, self.get_str):
                yield namespace

    def get_global_statements(self) -> Iterator[Node]:
        for node, _ in self.query.global_statement.captures(self.tree.root_node):
            yield node

    def get_direct_method_call(self, node: Node) -> Optional[Node]:
        captures = self.query.direct_method_call.captures(node)
        if captures:
            return captures[0][0]
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
        for node, _ in self.query.code.captures(self.tree.root_node):
            yield node

    def get_parsed_code_sections(self) -> Iterator[TreeSitterExtractorEngine]:
        for node in self.get_code_sections():
            # TODO: support JS
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
        for node, _ in self.query.content.captures(self.tree.root_node):
            yield node

    def identify_language(self) -> str:
        for node in self.get_code_sections():
            if self.is_c_sharp(node):
                return LANG_CS
        return LANG_JS

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

    def __init__(self, buf: bytes, namespaces: set[BaseNamespace] = set()):
        super().__init__(LANG_HTML, buf)
        self.namespaces = namespaces

    def get_scripts(self) -> Iterator[Node]:
        for node, _ in self.query.script_element.captures(self.tree.root_node):
            yield node

    def get_attributes(self, node: Node) -> Iterator[Node]:
        for att_node, _ in self.query.attribute.captures(node):
            yield att_node

    def get_identified_scripts(self) -> Iterator[Tuple[Node, str]]:
        for node in self.get_scripts():
            for content_node in self.get_script_contents(node):
                yield content_node, self.identify_language(node)

    def get_script_contents(self, node: Node) -> Iterator[Node]:
        for sc_node, _ in self.query.script_content.captures(node):
            yield sc_node

    def get_parsed_code_sections(self) -> Iterator[TreeSitterExtractorEngine]:
        for node, language in self.get_identified_scripts():
            # TODO: support JS
            if language == LANG_CS:
                yield TreeSitterExtractorEngine(language, self.get_byte_range(node), node.start_byte, self.namespaces)

    def identify_language(self, node: Node) -> str:
        for att_node in self.get_attributes(node):
            if self.is_server_side_c_sharp(att_node):
                return LANG_CS
        return LANG_JS

    def is_server_side_c_sharp(self, node: Node) -> bool:
        return bool(re.findall(r'runat\s*=\s*"server"'.encode(), self.get_byte_range(node)))
