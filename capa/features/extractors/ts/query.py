from dataclasses import dataclass

from tree_sitter import Language
from tree_sitter.binding import Query

import capa.features.extractors.ts.build
from capa.features.extractors.script import LANG_CS, LANG_JS, LANG_PY, LANG_TEM, LANG_HTML


@dataclass
class QueryBinding:
    language: Language


@dataclass
class ScriptQueryBinding(QueryBinding):
    new_object_name: Query
    function_definition: Query
    function_definition_field_name: str
    direct_method_call: Query
    function_call_name: Query
    property_name: Query
    imported_constant_name: Query
    string_literal: Query
    integer_literal: Query
    namespace: Query
    global_statement: Query  # except function definitions


@dataclass
class TemplateQueryBinding(QueryBinding):
    code: Query
    content: Query


@dataclass
class HTMLQueryBinding(QueryBinding):
    script_element: Query
    script_content: Query
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


capa.features.extractors.ts.build.TSBuilder()

TS_LANGUAGES: dict[str, Language] = {
    LANG_CS: Language(capa.features.extractors.ts.build.build_dir, LANG_CS),
    LANG_PY: Language(capa.features.extractors.ts.build.build_dir, LANG_PY),
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
                    "new_object_name": "(object_creation_expression type: [(qualified_name) @new-object (identifier) @new-object])",
                    "function_definition": "(local_function_statement) @function-definition",
                    "function_call_name": "(invocation_expression function: [(member_access_expression name: (identifier)) @function-call (identifier) @function-call])",
                    "property_name": "(member_access_expression) @property",
                    "imported_constant_name": "(member_access_expression) @constant (equals_value_clause (identifier) @constant)",
                    "string_literal": "(string_literal) @string-literal",
                    "integer_literal": "(integer_literal) @integer-literal",
                    "namespace": "(using_directive [(identifier) @namespace (qualified_name) @namespace])",
                    "global_statement": "(global_statement [(if_statement) @global-statement (expression_statement) @global-statement (local_declaration_statement) @global-statement])",
                    "direct_method_call": "(member_access_expression expression: (object_creation_expression) name: (identifier) @direct-method-call)",
                },
                "field_name": {
                    "function_definition": "name",
                },
            },
        ),
    ),
    LANG_PY: ScriptQueryBinding(
        TS_LANGUAGES[LANG_PY],
        **deserialize(
            LANG_PY,
            {
                "query": {
                    "new_object_name": "(call function: [(attribute) @new-object (identifier) @new-object])",  # Python makes no distinction between new object creation and a function call
                    "function_definition": "(function_definition) @function-definition",
                    "function_call_name": "(call function: [(attribute) @function-call (identifier) @function-call])",
                    "property_name": "(attribute) @property",
                    "imported_constant_name": "(attribute) @constant (expression_statement (assignment right: (identifier) @constant))",
                    "string_literal": "(string) @string-literal",
                    "integer_literal": "(integer) @integer-literal",
                    "namespace": "(import_from_statement) @import_from (import_statement) @import",
                    "global_statement": "(module [(if_statement) @global-statement (expression_statement) @global-statement])",
                    "direct_method_call": "(attribute object: (call) attribute: (identifier) @direct-method-call)",
                },
                "field_name": {
                    "function_definition": "name",
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
                    "script_content": "(raw_text) @script-content",
                },
            },
        ),
    ),
}
