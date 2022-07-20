import abc
import json
import importlib.resources
from typing import List, Optional

import capa.features.extractors.ts.signatures
from capa.features.extractors.script import LANG_CS


class LanguageToolkit:
    import_signatures: set

    def __init__(self, signature_file: str):
        self.import_signatures = self.load_import_signatures(signature_file)

    def load_import_signatures(self, signature_file: str) -> set:
        return set(json.loads(importlib.resources.read_text(capa.features.extractors.ts.signatures, signature_file)))

    def is_import(self, import_: str) -> bool:
        return import_ in self.import_signatures

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
        raise NotImplementedError

    @abc.abstractmethod
    def format_imported_property(self, name: str) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_default_namespaces(self, embedded: bool) -> set:
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

    def get_default_namespaces(self, embedded: bool) -> set:
        if embedded:
            return {
                "System",
                "System.Collections",
                "System.Collections.Specialized",
                "System.Configuration",
                "System.Text",
                "System.Text.RegularExpressions",
                "System.Web",
                "System.Web.Caching",
                "System.Web.Profile",
                "System.Web.Security",
                "System.Web.SessionState",
                "System.Web.UI",
                "System.Web.UI.HtmlControls",
                "System.Web.UI.WebControls",
                "System.Web.UI.WebControls.WebParts",
            }
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


LANGUAGE_TOOLKITS: dict[str, LanguageToolkit] = {LANG_CS: CSharpToolkit("cs.json")}
