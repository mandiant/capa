from dataclasses import dataclass

from tree_sitter import Language
from tree_sitter.binding import Query

import capa.features.extractors.ts.build
from capa.features.extractors.script import LANG_CS, LANG_TEM, LANG_HTML

CS_BINDING = {
    "query": {
        "new_object": "(object_creation_expression) @object.new",
        "function_definition": "(local_function_statement) @function.definition",
        "function_call": "(invocation_expression) @function.call",
        "string_literal": "(string_literal) @string-literal",
        "integer_literal": "(integer_literal) @integer-literal",
        "namespace": "(using_directive [(identifier) @namespace (qualified_name) @namespace])",
        "global_statement": "(global_statement [(expression_statement) @global-statement (local_declaration_statement) @global-statement])",
    },
    "field_name": {"new_object": "type", "function_definition": "name", "function_call": "function"},
}

TEM_BINDING = {
    "code": "(code) @code",
    "content": "(content) @content",
}

HTML_BINDING = {
    "script_element": "(script_element) @script-element",
    "attribute": "(attribute) @attribute",
}


@dataclass
class QueryBinding:
    language: Language


@dataclass
class ScriptQueryBinding(QueryBinding):
    new_object: Query
    new_object_field_name: str
    function_definition: Query
    function_definition_field_name: str
    function_call: Query
    function_call_field_name: str
    string_literal: Query
    integer_literal: Query
    namespace: Query
    global_statement: Query


@dataclass
class TemplateQueryBinding(QueryBinding):
    code: Query
    content: Query


@dataclass
class HTMLQueryBinding(QueryBinding):
    script_element: Query
    attribute: Query


class QueryBindingFactory:
    @staticmethod
    def from_language(language: str) -> QueryBinding:
        ts_language = Language(capa.features.extractors.ts.build.build_dir, language)
        if language == LANG_CS:
            return ScriptQueryBinding(language=ts_language, **QueryBindingFactory.deserialize(ts_language, CS_BINDING))
        if language in LANG_TEM:
            return TemplateQueryBinding(language=ts_language, **TEM_BINDING)
        if language == LANG_HTML:
            return HTMLQueryBinding(language=ts_language, **HTML_BINDING)
        raise NotImplementedError(f"Tree-sitter queries for {language} are not implemented.")

    @staticmethod
    def deserialize(language: Language, binding: dict) -> dict:
        deserialized_binding = {}
        for construct, query in binding["query"].items():
            deserialized_binding[construct] = language.query(query)
        for construct, field_name in binding["field_name"].items():
            deserialized_binding[f"{construct}_field_name"] = field_name
        return deserialized_binding

    def __init__(self):
        self.language = Language(capa.features.extractors.ts.build.build_dir, "embedded_template")
        self.content = self.language.query("(content) @content")
        self.code = self.language.query("(code) @code")
