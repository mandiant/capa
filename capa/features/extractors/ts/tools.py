import abc
import json
import importlib.resources
from typing import Dict, List, Tuple, Union, Callable, Iterator, Optional
from dataclasses import dataclass

from tree_sitter import Node

import capa.features.extractors.ts.signatures
from capa.features.extractors.script import LANG_CS, LANG_PY


@dataclass(frozen=True)
class BaseNamespace(abc.ABC):
    """Abstract class for internal representation of the namespace concept, including aliases."""

    name: str
    node: Node = None
    alias: str = ""

    def __hash__(self):
        return hash(self.name)

    def get_join_name(self) -> Optional[str]:
        raise NotImplementedError()


class CSharpNamespace(BaseNamespace):
    def get_join_name(self) -> Optional[str]:
        """using System; Diagnostics.ProcessStartInfo => System.Diagnostics.ProcessStartInfo"""
        return self.name


class PythonImport(BaseNamespace):
    def get_join_name(self) -> Optional[str]:
        """import subprocess ; subprocess.Popen => subprocess.Popen
        from threading import Timer (threading.Timer) => Timer
        """
        toolkit = LANGUAGE_TOOLKITS[LANG_CS]
        qualified_names = toolkit.split_name(self.name)
        if len(qualified_names) < 2:
            return None
        return toolkit.join_names(*qualified_names[:-1])


class LanguageToolkit:
    signature_file: str
    import_signatures: Dict[str, set[str]]
    method_call_query_type: str
    property_query_type: str
    string_delimiters: str
    integer_prefixes: List[
        Tuple[Union[str, Tuple[str, ...]], int]
    ]  # Tends to indicate a number system, e.g. (("0x", "0X"), 16)
    integer_suffixes: Tuple[str, ...]  # Tends to indicate unsigned (100u) or long (100l) integer literal

    def __init__(self):
        self.import_signatures = self.load_import_signatures(self.signature_file)

    def load_import_signatures(self, signature_file: str) -> Dict[str, set[str]]:
        signatures = json.loads(importlib.resources.read_text(capa.features.extractors.ts.signatures, signature_file))
        return {category: set(namespaces) for category, namespaces in signatures.items()}

    def is_import(self, import_: str) -> bool:
        return import_ in self.import_signatures["imports"]

    def is_builtin(self, func: str) -> bool:
        return func in self.import_signatures["builtins"]

    def join_names(self, *args: str) -> str:
        return ".".join(args)

    def split_name(self, name: str) -> List[str]:
        return name.split(".")

    def process_property(self, node: Node, name: str) -> Optional[str]:
        if self.is_method_call(node):  # yield only p.StartInfo but not p.Start()
            return None
        if self.is_recursive_property(node):  # yield only Current.Server.ClearError but not Current.Server and Current
            return None
        return self.join_names(*self.split_name(name)[1:])

    def process_imported_constant(self, node: Node, name: str) -> Optional[str]:
        if self.is_method_call(node):  # yield only ssl.CERT_NONE and not ssl.wrap_socket()
            return None
        if self.is_recursive_property(node):  # yield foo.foo.bar and not foo.bar or bar
            return None
        return name

    def format_imported_class(self, name: str) -> str:
        return name

    def format_imported_class_members(self, name: str) -> str:
        qualified_names = self.split_name(name)
        if len(qualified_names) < 2:
            raise ValueError(f"{name} does not have an associated class or namespace")
        if len(qualified_names) == 2:
            classname, membername = qualified_names[0], qualified_names[1]
            return f"{classname}::{membername}"
        namespace, classname, membername = qualified_names[:-2], qualified_names[-2], qualified_names[-1]
        return f"{'.'.join(namespace)}.{classname}::{membername}"

    def format_imported_function(self, name: str) -> str:
        return self.format_imported_class_members(name)

    def format_imported_property(self, name: str) -> str:
        return self.format_imported_class_members(name)

    def format_imported_constant(self, name: str) -> str:
        return self.format_imported_class_members(name)

    def parse_integer(self, integer: str) -> Optional[int]:
        for suffix in self.integer_suffixes:
            if integer.endswith(suffix):
                integer = integer[:-1]
        try:
            for prefix, base in self.integer_prefixes:
                if integer.startswith(prefix):
                    return int(integer, base)
            return int(integer)
        except:
            return None

    def parse_string(self, string: str) -> str:
        return string.strip(self.string_delimiters)

    def is_method_call(self, node: Node) -> bool:
        return node.parent.type == self.method_call_query_type

    def is_recursive_property(self, node: Node) -> bool:
        return node.parent.type == self.property_query_type

    @abc.abstractmethod
    def create_namespace(self, name: str, node: Node = None, alias: str = "") -> BaseNamespace:
        raise NotImplementedError()

    @abc.abstractmethod
    def process_namespace(self, node: Node, query_name: str, get_range: Callable) -> Iterator[BaseNamespace]:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_default_namespaces(self, embedded: bool) -> set[BaseNamespace]:
        raise NotImplementedError()


class CSharpToolkit(LanguageToolkit):
    signature_file: str = "cs.json"
    method_call_query_type: str = "invocation_expression"
    property_query_type: str = "member_access_expression"
    string_delimiters: str = '"'
    integer_prefixes: List[Tuple[Union[str, Tuple[str, ...]], int]] = [(("0x", "0X"), 16)]
    integer_suffixes: Tuple[str, ...] = ("u", "l")

    def create_namespace(self, name: str, node: Node = None, alias: str = "") -> BaseNamespace:
        return CSharpNamespace(name, node, alias)

    def process_namespace(self, node: Node, query_name: str, get_range: Callable) -> Iterator[BaseNamespace]:
        yield CSharpNamespace(get_range(node), node, "")

    def get_default_namespaces(self, embedded: bool) -> set[BaseNamespace]:
        if embedded:
            return {CSharpNamespace(name) for name in self.import_signatures["aspx_default_namespaces"]}
        return set()


class PythonToolkit(LanguageToolkit):
    signature_file: str = "py.json"
    method_call_query_type: str = "call"
    property_query_type: str = "attribute"
    string_delimiters: str = "\"'"
    integer_prefixes: List[Tuple[Union[str, Tuple[str, ...]], int]] = [
        (("0b, 0B"), 2),
        (("0o, 0O"), 8),
        (("0x", "0X"), 16),
    ]
    integer_suffixes: Tuple[str, ...] = tuple()

    def create_namespace(self, name: str, node: Node = None, alias: str = "") -> BaseNamespace:
        return PythonImport(name, node, alias)

    def get_import_name(self, name: str, module_name: Optional[str] = None) -> str:
        return self.join_names(module_name, name) if module_name else name

    def process_simple_import(
        self, node: Node, get_range: Callable, module_name: Optional[str] = None
    ) -> BaseNamespace:
        return PythonImport(self.get_import_name(get_range(node), module_name), node)

    def process_aliased_import(
        self, node: Node, get_range: Callable, module_name: Optional[str] = None
    ) -> BaseNamespace:
        name = self.get_import_name(get_range(node.get_child_by_field_name("name")), module_name)
        alias = get_range(node.get_child_by_field_name("alias"))
        return PythonImport(name, node, alias)

    def process_imports(
        self, nodes: List[Node], get_range: Callable, module_name: Optional[str] = None
    ) -> Iterator[BaseNamespace]:
        for import_node in nodes:
            if import_node.type == "dotted_name":
                yield self.process_simple_import(import_node, get_range, module_name)
            elif import_node.type == "aliased_import":
                yield self.process_aliased_import(import_node, get_range, module_name)

    def get_wildcard_import(self, node: Node) -> Optional[Node]:
        for child_node in node.children:
            if child_node.type == "wildcard_import":
                return child_node
        return None

    def process_import_from(self, node: Node, import_nodes: List[Node], get_range: Callable) -> Iterator[BaseNamespace]:
        module_name, import_nodes = get_range(import_nodes[0]), import_nodes[1:]
        wildcard_import = self.get_wildcard_import(node)
        if wildcard_import:
            yield self.process_simple_import(wildcard_import, get_range, module_name)
        else:
            yield from self.process_imports(import_nodes, get_range, module_name)

    def process_namespace(self, node: Node, query_name: str, get_range: Callable) -> Iterator[BaseNamespace]:
        import_nodes = [child_node for child_node in node.children if child_node.is_named]
        if query_name == "import_from":
            yield from self.process_import_from(node, import_nodes, get_range)
        elif query_name == "import":
            yield from self.process_imports(import_nodes, get_range)

    def get_default_namespaces(self, embedded: bool) -> set[BaseNamespace]:
        return set()


LANGUAGE_TOOLKITS: dict[str, LanguageToolkit] = {LANG_CS: CSharpToolkit(), LANG_PY: PythonToolkit()}
