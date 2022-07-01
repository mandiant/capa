from dataclasses import dataclass

from tree_sitter import Language
from tree_sitter.binding import Query

import capa.features.extractors.ts.build
from capa.features.extractors.script import LANG_CS


@dataclass
class QueryBinding:
    language: Language
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

    def __init__(self, language: str):
        self.language = Language(capa.features.extractors.ts.build.build_dir, language)
        if language == LANG_CS:
            self.new_object = self.language.query("(object_creation_expression) @object.new")
            self.new_object_field_name = "type"
            self.function_definition = self.language.query("(local_function_statement) @function.definition")
            self.function_definition_field_name = "name"
            self.function_call = self.language.query("(invocation_expression) @function.call")
            self.function_call_field_name = "function"
            self.string_literal = self.language.query("(string_literal) @string-literal")
            self.integer_literal = self.language.query("(integer_literal) @integer-literal")
            self.namespace = self.language.query(
                "(using_directive [(identifier) @namespace (qualified_name) @namespace])"
            )
            self.global_statement = self.language.query("(global_statement) @global-statement")
        else:
            raise NotImplementedError(f"Tree-sitter queries for {language} are not implemented.")
