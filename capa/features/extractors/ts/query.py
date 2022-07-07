from dataclasses import dataclass

from tree_sitter import Language
from tree_sitter.binding import Query

import capa.features.extractors.ts.build
from capa.features.extractors.script import LANG_CS, LANG_JS, LANG_TEM, LANG_HTML


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


def deserialize(language: str, binding: dict) -> dict:
    deserialized_binding = {}
    if "query" in binding:
        for construct, query in binding["query"].items():
            deserialized_binding[construct] = TS_LANGUAGES[language].query(query)
    if "field_name" in binding:
        for construct, field_name in binding["field_name"].items():
            deserialized_binding[f"{construct}_field_name"] = field_name
    return deserialized_binding


TS_LANGUAGES: dict[str, Language] = {
    LANG_CS: Language(capa.features.extractors.ts.build.build_dir, LANG_CS),
    LANG_TEM: Language(capa.features.extractors.ts.build.build_dir, LANG_TEM),
    LANG_HTML: Language(capa.features.extractors.ts.build.build_dir, LANG_HTML),
    LANG_JS: Language(capa.features.extractors.ts.build.build_dir, LANG_JS),
}

BINDINGS: dict[str, QueryBinding] = {
    LANG_CS: ScriptQueryBinding(
        TS_LANGUAGES[LANG_CS],
        **deserialize(
            LANG_CS,
            {
                "query": {
                    "new_object": "(object_creation_expression) @object.new",
                    "function_definition": "(local_function_statement) @function.definition",
                    "function_call": "(invocation_expression) @function.call",
                    "string_literal": "(string_literal) @string-literal",
                    "integer_literal": "(integer_literal) @integer-literal",
                    "namespace": "(using_directive [(identifier) @namespace (qualified_name) @namespace])",
                    "global_statement": "(global_statement [(expression_statement) @global-statement (local_declaration_statement) @global-statement])",
                },
                "field_name": {
                    "new_object": "type",
                    "function_definition": "name",
                    "function_call": "function",
                },
            },
        ),
    ),
    LANG_TEM: TemplateQueryBinding(
        TS_LANGUAGES[LANG_TEM],
        **deserialize(
            LANG_TEM,
            {
                "query": {
                    "code": "(code) @code",
                    "content": "(content) @content",
                },
            },
        ),
    ),
    LANG_HTML: HTMLQueryBinding(
        TS_LANGUAGES[LANG_HTML],
        **deserialize(
            LANG_HTML,
            {
                "query": {
                    "script_element": "(script_element) @script-element",
                    "attribute": "(attribute) @attribute",
                },
            },
        ),
    ),
}
