from tree_sitter import Node, Tree, Parser

import capa.features.extractors.ts.query


class TreeSitterExtractorEngine:
    def __init__(self, language):
        self.query = capa.features.extractors.ts.query.QueryBinding(language)

    def get_ts_language(self):
        return self.query.language

    def parse(self, source: bytes) -> Tree:
        parser = Parser()
        parser.set_language(self.get_ts_language())
        return parser.parse(source)

    def get_new_objects(self, node: Node):
        return self.query.new_object.captures(node)

    def get_object_id(self, node: Node):
        return node.child_by_field_name(self.query.new_object_field_name)

    def get_functions(self, node: Node):
        return self.query.function_def.captures(node)

    def get_function_definition_id(self, node: Node):
        return node.child_by_field_name(self.query.function_def_field_name)

    def get_function_calls(self, node: Node):
        return self.query.function_call.captures(node)

    def get_function_call_id(self, node: Node):
        return node.child_by_field_name(self.query.function_call_field_name)

    def extract_string_literals(self, node: Node):
        return self.query.string_literal.captures(node)

    def extract_integer_literals(self, node: Node):
        return self.query.integer_literal.captures(node)

    def extract_namespaces(self, node: Node):
        return self.query.namespace.captures(node)

    def extract_blocks(self, node: Node):
        return self.query.block.captures(node)

    def extract_node(self, tree, tgt_node_name):
        cursor = tree.walk()
        while True:
            if cursor.node.type == tgt_node_name:
                yield cursor.node
            if cursor.goto_first_child() or cursor.goto_next_sibling():
                continue
            while cursor.goto_parent() and not cursor.goto_next_sibling():
                continue
            if cursor.node.parent is None:
                break
