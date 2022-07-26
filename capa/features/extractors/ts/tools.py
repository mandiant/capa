import abc
import json
import importlib.resources
from typing import Dict, List, Callable, Iterator, Optional
from dataclasses import dataclass

from tree_sitter import Node

import capa.features.extractors.ts.signatures
from capa.features.extractors.script import LANG_CS, LANG_PY


@dataclass(frozen=True)
class BaseNamespace(abc.ABC):
    name: str
    node: Node = None
    alias: str = ""

    def __hash__(self):
        return hash(self.name)

    def get_join_name(self) -> Optional[str]:
        raise NotImplementedError()


class CSharpNamespace(BaseNamespace):
    def get_join_name(self) -> Optional[str]:
        return self.name


class PythonNamespace(BaseNamespace):
    def get_join_name(self) -> Optional[str]:
        toolkit = LANGUAGE_TOOLKITS[LANG_CS]
        qualified_names = toolkit.split_name(self.name)
        if len(qualified_names) < 2:
            return None
        return toolkit.join_names(*qualified_names[:-1])


class LanguageToolkit:
    import_signatures: Dict[str, set[str]]

    def __init__(self, signature_file: str):
        self.import_signatures = self.load_import_signatures(signature_file)

    def load_import_signatures(self, signature_file: str) -> Dict[str, set[str]]:
        signatures = json.loads(importlib.resources.read_text(capa.features.extractors.ts.signatures, signature_file))
        return {category: set(namespaces) for category, namespaces in signatures.items()}

    def is_import(self, import_: str) -> bool:
        return import_ in self.import_signatures["namespaces"]

    @abc.abstractmethod
    def create_namespace(self, name: str, node: Node = None, alias: str = "") -> BaseNamespace:
        raise NotImplementedError()

    @abc.abstractmethod
    def join_names(self, *args: str) -> str:
        raise NotImplementedError()

    @abc.abstractmethod
    def split_name(self, name: str) -> List[str]:
        raise NotImplementedError()

    @abc.abstractmethod
    def format_imported_class(self, name: str) -> str:
        raise NotImplementedError()

    @abc.abstractmethod
    def format_imported_function(self, name: str) -> str:
        raise NotImplementedError()

    @abc.abstractmethod
    def format_imported_property(self, name: str) -> str:
        raise NotImplementedError()

    @abc.abstractmethod
    def process_namespace(self, node: Node, query_name: str, get_range: Callable) -> Iterator[BaseNamespace]:
        raise NotImplementedError()

    @abc.abstractmethod
    def get_default_namespaces(self, embedded: bool) -> set[BaseNamespace]:
        raise NotImplementedError()

    @abc.abstractmethod
    def parse_integer(self, integer: str) -> Optional[int]:
        raise NotImplementedError()

    @abc.abstractmethod
    def parse_string(self, string: str) -> Optional[str]:
        raise NotImplementedError()


class CSharpToolkit(LanguageToolkit):
    def join_names(self, *args: str) -> str:
        return ".".join(args)

    def split_name(self, name: str) -> List[str]:
        return name.split(".")

    def format_imported_class(self, name: str) -> str:
        return name

    def create_namespace(self, name: str, node: Node = None, alias: str = "") -> BaseNamespace:
        return CSharpNamespace(name, node, alias)

    def format_imported_function(self, name: str) -> str:
        qualified_names = self.split_name(name)
        if len(qualified_names) < 2:
            raise ValueError(f"function {name} does not have an associated class or namespace")
        if len(qualified_names) == 2:
            classname, functionname = qualified_names[0], qualified_names[1]
            return f"{classname}::{functionname}"
        namespace, classname, functionname = qualified_names[:-2], qualified_names[-2], qualified_names[-1]
        return f"{'.'.join(namespace)}.{classname}::{functionname}"

    def format_imported_property(self, name: str) -> str:
        qualified_names = self.split_name(name)
        if len(qualified_names) < 2:
            raise ValueError(f"property {name} does not have an associated class")
        if len(qualified_names) == 2:
            classname, propertyname = qualified_names[0], qualified_names[1]
            return f"{classname}::{propertyname}"
        namespace, classname, propertyname = qualified_names[:-2], qualified_names[-2], qualified_names[-1]
        return f"{'.'.join(namespace)}.{classname}::{propertyname}"

    def process_namespace(self, node: Node, query_name: str, get_range: Callable) -> Iterator[BaseNamespace]:
        yield CSharpNamespace(get_range(node), node, "")

    def get_default_namespaces(self, embedded: bool) -> set[BaseNamespace]:
        if embedded:
            return {CSharpNamespace(name) for name in self.import_signatures["aspx_default_namespaces"]}
        return set()

    def parse_integer(self, integer: str) -> Optional[int]:
        if integer.endswith(("u", "l")):
            integer = integer[:-1]
        try:
            if integer.startswith(("0x", "0X")):
                return int(integer, 16)
            return int(integer)
        except:
            return None

    def parse_string(self, string: str) -> Optional[str]:
        return string.strip('"')


class PythonToolkit(LanguageToolkit):
    def join_names(self, *args: str) -> str:
        return ".".join(args)

    def split_name(self, name: str) -> List[str]:
        return name.split(".")

    def format_imported_class(self, name: str) -> str:
        return name

    def create_namespace(self, name: str, node: Node = None, alias: str = "") -> BaseNamespace:
        return PythonNamespace(name, node, alias)

    def format_imported_function(self, name: str) -> str:
        qualified_names = self.split_name(name)
        if len(qualified_names) < 2:
            raise ValueError(f"function {name} does not have an associated class or namespace")
        if len(qualified_names) == 2:
            classname, functionname = qualified_names[0], qualified_names[1]
            return f"{classname}::{functionname}"
        namespace, classname, functionname = qualified_names[:-2], qualified_names[-2], qualified_names[-1]
        return f"{'.'.join(namespace)}.{classname}::{functionname}"

    def format_imported_property(self, name: str) -> str:
        qualified_names = self.split_name(name)
        if len(qualified_names) < 2:
            raise ValueError(f"property {name} does not have an associated class")
        if len(qualified_names) == 2:
            classname, propertyname = qualified_names[0], qualified_names[1]
            return f"{classname}::{propertyname}"
        namespace, classname, propertyname = qualified_names[:-2], qualified_names[-2], qualified_names[-1]
        return f"{'.'.join(namespace)}.{classname}::{propertyname}"

    def get_import_name(self, name: str, module_name: Optional[str] = None) -> str:
        return self.join_names(module_name, name) if module_name else name

    def process_simple_import(
        self, node: Node, get_range: Callable, module_name: Optional[str] = None
    ) -> BaseNamespace:
        return PythonNamespace(self.get_import_name(get_range(node), module_name), node)

    def process_aliased_import(
        self, node: Node, get_range: Callable, module_name: Optional[str] = None
    ) -> BaseNamespace:
        name = self.get_import_name(get_range(node.get_child_by_field_name("name")), module_name)
        alias = get_range(node.get_child_by_field_name("alias"))
        return PythonNamespace(name, node, alias)

    def process_imports(
        self, nodes: List[Node], get_range: Callable, module_name: Optional[str] = None
    ) -> Iterator[BaseNamespace]:
        for import_node in nodes:
            if import_node.type == "dotted_name":
                yield self.process_simple_import(import_node, get_range, module_name)
            elif import_node.type == "aliased_import":
                yield self.process_aliased_import(import_node, get_range, module_name)

    def process_namespace(self, node: Node, query_name: str, get_range: Callable) -> Iterator[BaseNamespace]:
        import_nodes = [child_node for child_node in node.children if child_node.is_named]
        if query_name == "import_from":
            yield from self.process_imports(import_nodes[1:], get_range, get_range(import_nodes[0]))
        elif query_name == "import":
            yield from self.process_imports(import_nodes, get_range)

    def get_default_namespaces(self, embedded: bool) -> set[BaseNamespace]:
        return set()

    def parse_integer(self, integer: str) -> Optional[int]:
        try:
            if integer.startswith(("0b, 0B")):
                return int(integer, 2)
            if integer.startswith(("0o, 0O")):
                return int(integer, 8)
            if integer.startswith(("0x", "0X")):
                return int(integer, 16)
            return int(integer)
        except:
            return None

    def parse_string(self, string: str) -> Optional[str]:
        return string.strip('"')


LANGUAGE_TOOLKITS: dict[str, LanguageToolkit] = {LANG_CS: CSharpToolkit("cs.json"), LANG_PY: PythonToolkit("py.json")}
