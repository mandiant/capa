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

from dataclasses import dataclass

import tree_sitter_html
import tree_sitter_python
import tree_sitter_c_sharp
import tree_sitter_javascript
import tree_sitter_embedded_template
from tree_sitter import Query, Language

from capa.features.extractors.script import (
    LANG_CS,
    LANG_JS,
    LANG_PY,
    LANG_TEM,
    LANG_HTML,
)


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
    global_statement: Query


@dataclass
class TemplateQueryBinding(QueryBinding):
    code: Query
    content: Query


@dataclass
class HTMLQueryBinding(QueryBinding):
    script_element: Query
    script_content: Query
    attribute: Query


TS_LANGUAGES: dict[str, Language] = {
    LANG_CS: Language(tree_sitter_c_sharp.language()),
    LANG_PY: Language(tree_sitter_python.language()),
    LANG_JS: Language(tree_sitter_javascript.language()),
    LANG_TEM: Language(tree_sitter_embedded_template.language()),
    LANG_HTML: Language(tree_sitter_html.language()),
}


def deserialize(language: str, binding: dict) -> dict:
    result = {}

    if "query" in binding:
        for name, query in binding["query"].items():
            result[name] = TS_LANGUAGES[language].query(query)

    if "field_name" in binding:
        for name, field in binding["field_name"].items():
            result[f"{name}_field_name"] = field

    return result


BINDINGS: dict[str, QueryBinding] = {
    LANG_CS: ScriptQueryBinding(
        TS_LANGUAGES[LANG_CS],
        **deserialize(
            LANG_CS,
            {
                "query": {
                    # new Foo()
                    "new_object_name": """
                    (object_creation_expression
                        type: [
                            (qualified_name) @new-object
                            (identifier) @new-object
                        ])
                    """,
                    # local functions
                    "function_definition": """
                    (local_function_statement) @function-definition
                    """,
                    # foo() or obj.foo()
                    "function_call_name": """
                    (invocation_expression
                        function: [
                            (member_access_expression
                                name: (identifier) @function-call)
                            (identifier) @function-call
                        ])
                    """,
                    # obj.property
                    "property_name": """
                    (member_access_expression) @property
                    """,
                    # SomeClass.CONSTANT
                    "imported_constant_name": """
                    (member_access_expression
                        name: (identifier) @constant)
                    """,
                    "string_literal": """
                    (string_literal) @string-literal
                    """,
                    "integer_literal": """
                    (integer_literal) @integer-literal
                    """,
                    # using System.Text;
                    "namespace": """
                    (using_directive
                        [
                            (identifier) @namespace
                            (qualified_name) @namespace
                        ])
                    """,
                    # global statements
                    "global_statement": """
                    (global_statement
                        [
                            (if_statement) @global-statement
                            (expression_statement) @global-statement
                            (local_declaration_statement) @global-statement
                        ])
                    """,
                    # new Foo().Bar()
                    "direct_method_call": """
                    (member_access_expression
                        expression: (object_creation_expression)
                        name: (identifier) @direct-method-call)
                    """,
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
                    # Python: constructor == call
                    "new_object_name": """
                    (call
                        function: [
                            (attribute) @new-object
                            (identifier) @new-object
                        ])
                    """,
                    "function_definition": """
                    (function_definition) @function-definition
                    """,
                    "function_call_name": """
                    (call
                        function: [
                            (attribute) @function-call
                            (identifier) @function-call
                        ])
                    """,
                    "property_name": """
                    (attribute) @property
                    """,
                    # obj.CONSTANT
                    "imported_constant_name": """
                    (attribute
                        attribute: (identifier) @constant)
                    """,
                    "string_literal": """
                    (string) @string-literal
                    """,
                    "integer_literal": """
                    (integer) @integer-literal
                    """,
                    "namespace": """
                    [
                        (import_statement) @import
                        (import_from_statement) @import-from
                    ]
                    """,
                    "global_statement": """
                    (module
                        [
                            (if_statement) @global-statement
                            (expression_statement) @global-statement
                        ])
                    """,
                    "direct_method_call": """
                    (attribute
                        object: (call)
                        attribute: (identifier) @direct-method-call)
                    """,
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
                }
            },
        ),
    ),
    LANG_HTML: HTMLQueryBinding(
        TS_LANGUAGES[LANG_HTML],
        **deserialize(
            LANG_HTML,
            {
                "query": {
                    "script_element": """
                    (script_element) @script-element
                    """,
                    "script_content": """
                    (raw_text) @script-content
                    """,
                    "attribute": """
                    (attribute) @attribute
                    """,
                }
            },
        ),
    ),
}
