# Copyright 2024 Google LLC
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

"""
Python language handler for tree-sitter-based script analysis.

Maps Python AST node types to capa's feature model:
  - function_definition -> function scope
  - call / attribute -> API features (with import resolution)
  - import_statement / import_from_statement -> Import features
  - string / concatenated_string -> String features
  - integer / float -> Number features

Handles edge cases:
  - import aliasing (import X as Y)
  - from-imports (from os.path import join)
  - dynamic imports (__import__, importlib.import_module)
  - decorators (treated as characteristics)
  - nested/chained calls (recursive AST walk)
  - f-strings (extract static string parts)
"""

import logging
from typing import Iterator

import tree_sitter_python as tspython
from tree_sitter import Language, Node, Parser, Tree

from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address, ScriptAddress
from capa.features.extractors.script.lang_base import ImportContext, LanguageHandler

logger = logging.getLogger(__name__)


class PythonLanguageHandler(LanguageHandler):
    """
    Python-specific implementation of the LanguageHandler interface.

    Uses tree-sitter-python grammar to parse Python scripts and extract
    features that map to capa's feature model.
    """

    PY_LANGUAGE = Language(tspython.language())

    def get_tree_sitter_language(self):
        return self.PY_LANGUAGE

    def get_function_nodes(self, tree: Tree) -> Iterator[Node]:
        """
        Yield top-level function definition nodes from the AST.

        Handles both regular functions and async functions.
        Does not descend into nested function definitions — those
        are left as statement nodes within their parent function.
        """
        for child in tree.root_node.children:
            if child.type in ("function_definition", "decorated_definition"):
                yield child

    def get_function_name(self, node: Node) -> str:
        """
        Extract function name from a function_definition or decorated_definition node.
        """
        # decorated_definition wraps the actual function_definition
        if node.type == "decorated_definition":
            for child in node.children:
                if child.type == "function_definition":
                    node = child
                    break

        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return name_node.text.decode("utf-8")
        return "<unknown>"

    def get_statement_nodes(self, node: Node) -> Iterator[Node]:
        """
        Yield statement-level nodes from a function body.

        These map to capa's "instruction" scope. For a function_definition,
        the body is the `block` child node — we yield each direct child statement.
        """
        # unwrap decorated_definition
        func_node = node
        if node.type == "decorated_definition":
            for child in node.children:
                if child.type == "function_definition":
                    func_node = child
                    break

        body = func_node.child_by_field_name("body")
        if body is None:
            return

        for child in body.children:
            yield child

    def extract_imports(self, tree: Tree) -> ImportContext:
        """
        Parse all import statements in the script and build an ImportContext.

        Handles:
          - import os                    -> names["os"] = "os"
          - import os as o              -> names["o"] = "os"
          - from os.path import join    -> names["join"] = "os.path.join"
          - from os.path import join as j -> names["j"] = "os.path.join"
          - from os.path import *       -> wildcard_modules.add("os.path")
        """
        ctx = ImportContext()

        for child in tree.root_node.children:
            if child.type == "import_statement":
                self._process_import_statement(child, ctx)
            elif child.type == "import_from_statement":
                self._process_import_from_statement(child, ctx)

        return ctx

    def _process_import_statement(self, node: Node, ctx: ImportContext) -> None:
        """
        Process `import X`, `import X as Y`, `import X.Y.Z`.
        """
        for child in node.children:
            if child.type == "dotted_name":
                # import os, import os.path
                module_name = child.text.decode("utf-8")
                ctx.names[module_name] = module_name
            elif child.type == "aliased_import":
                # import os as o
                name_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if name_node is not None and alias_node is not None:
                    module_name = name_node.text.decode("utf-8")
                    alias = alias_node.text.decode("utf-8")
                    ctx.names[alias] = module_name

    def _process_import_from_statement(self, node: Node, ctx: ImportContext) -> None:
        """
        Process `from X import Y`, `from X import Y as Z`, `from X import *`.
        """
        module_node = node.child_by_field_name("module_name")
        if module_node is None:
            return

        module_name = module_node.text.decode("utf-8")

        for child in node.children:
            # skip the module_name node itself — it's also a dotted_name
            # and would otherwise be mistaken for an imported name
            if child.id == module_node.id:
                continue

            if child.type == "wildcard_import":
                ctx.wildcard_modules.add(module_name)
                logger.debug("wildcard import from %s — individual names cannot be resolved", module_name)
            elif child.type == "dotted_name":
                # from os.path import join
                imported_name = child.text.decode("utf-8")
                ctx.names[imported_name] = f"{module_name}.{imported_name}"
            elif child.type == "aliased_import":
                # from os.path import join as j
                name_node = child.child_by_field_name("name")
                alias_node = child.child_by_field_name("alias")
                if name_node is not None and alias_node is not None:
                    imported_name = name_node.text.decode("utf-8")
                    alias = alias_node.text.decode("utf-8")
                    ctx.names[alias] = f"{module_name}.{imported_name}"

    def extract_insn_api_features(
        self, node: Node, ctx: ImportContext
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Extract API (function call) features from a statement node.

        Recursively walks child nodes to handle nested calls like:
          base64.b64decode(urllib.request.urlopen(url).read())

        For each call node, resolves the function name using the ImportContext:
          - `os.system(...)` with `import os` -> API("os.system")
          - `join(...)` with `from os.path import join` -> API("os.path.join")
          - `open(...)` (built-in) -> API("open")
        """
        yield from self._extract_calls_recursive(node, ctx)

    def _extract_calls_recursive(
        self, node: Node, ctx: ImportContext
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Recursively walk AST nodes to find all call expressions.
        """
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                api_name = self._resolve_call_name(func_node, ctx)
                if api_name:
                    addr = ScriptAddress(
                        line=node.start_point[0],
                        column=node.start_point[1],
                    )
                    yield API(api_name), addr

        # recurse into all children to find nested calls
        for child in node.children:
            yield from self._extract_calls_recursive(child, ctx)

    def _resolve_call_name(self, func_node: Node, ctx: ImportContext) -> str:
        """
        Resolve the fully-qualified name of a function call.

        Handles:
          - identifier: `open(...)` -> "open" or resolved via ImportContext
          - attribute: `os.system(...)` -> resolved via ImportContext
          - chained attributes: `urllib.request.urlopen(...)` -> resolved
        """
        if func_node.type == "identifier":
            name = func_node.text.decode("utf-8")
            return ctx.resolve_name(name)

        elif func_node.type == "attribute":
            # e.g., os.system, urllib.request.urlopen
            parts = self._collect_attribute_chain(func_node)
            if not parts:
                return ""

            # try to resolve the root (e.g., "os" in "os.system")
            root = parts[0]
            resolved_root = ctx.resolve_name(root)
            if resolved_root != root:
                # the root was an import alias
                parts[0] = resolved_root

            return ".".join(parts)

        return ""

    def _collect_attribute_chain(self, node: Node) -> list[str]:
        """
        Collect the chain of attribute accesses into a list of names.

        e.g., `urllib.request.urlopen` -> ["urllib", "request", "urlopen"]

        Handles calls on call results like `urlopen(url).read()` by
        stopping at the call boundary.
        """
        if node.type == "identifier":
            return [node.text.decode("utf-8")]
        elif node.type == "attribute":
            obj_node = node.child_by_field_name("object")
            attr_node = node.child_by_field_name("attribute")
            if obj_node is not None and attr_node is not None:
                obj_parts = self._collect_attribute_chain(obj_node)
                attr_name = attr_node.text.decode("utf-8")
                return obj_parts + [attr_name]
        elif node.type == "call":
            # method call on a call result, e.g., urlopen(url).read()
            # we stop at the call boundary — the method name ("read")
            # is handled by the parent attribute node
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                return self._collect_attribute_chain(func_node)
        return []

    def extract_insn_string_features(
        self, node: Node
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Extract string literal features from a statement node.

        Recursively finds all string nodes. Handles:
          - simple strings: "hello"
          - concatenated strings: "hello" "world"
          - f-strings: extracts static parts only
        """
        yield from self._extract_strings_recursive(node)

    def _extract_strings_recursive(
        self, node: Node
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Recursively walk AST nodes to find all string literals.
        """
        if node.type == "string":
            value = self._extract_string_value(node)
            if value and len(value) >= 4:
                addr = ScriptAddress(
                    line=node.start_point[0],
                    column=node.start_point[1],
                )
                yield String(value), addr

        elif node.type == "concatenated_string":
            # each child is a string node
            for child in node.children:
                yield from self._extract_strings_recursive(child)

        else:
            for child in node.children:
                yield from self._extract_strings_recursive(child)

    def _extract_string_value(self, node: Node) -> str:
        """
        Extract the string value from a string node, stripping quotes.
        """
        text = node.text.decode("utf-8")
        # handle triple-quoted strings
        for quote in ('"""', "'''", '"', "'"):
            if text.startswith(quote) and text.endswith(quote):
                return text[len(quote) : -len(quote)]
        # handle prefixed strings like b"...", r"...", f"..."
        # strip the prefix first
        for prefix in ("b", "B", "r", "R", "f", "F", "rb", "Rb", "rB", "RB", "br", "Br", "bR", "BR"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
        for quote in ('"""', "'''", '"', "'"):
            if text.startswith(quote) and text.endswith(quote):
                return text[len(quote) : -len(quote)]
        return ""

    def extract_insn_number_features(
        self, node: Node
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Extract numeric literal features from a statement node.

        Handles integers (decimal, hex, octal, binary) and floats.
        """
        yield from self._extract_numbers_recursive(node)

    def _extract_numbers_recursive(
        self, node: Node
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Recursively walk AST nodes to find all numeric literals.
        """
        if node.type == "integer":
            value = self._parse_python_int(node.text.decode("utf-8"))
            if value is not None:
                addr = ScriptAddress(
                    line=node.start_point[0],
                    column=node.start_point[1],
                )
                yield Number(value), addr

        elif node.type == "float":
            try:
                value = float(node.text.decode("utf-8"))
                addr = ScriptAddress(
                    line=node.start_point[0],
                    column=node.start_point[1],
                )
                yield Number(value), addr
            except ValueError:
                pass

        else:
            for child in node.children:
                yield from self._extract_numbers_recursive(child)

    @staticmethod
    def _parse_python_int(s: str) -> int | None:
        """
        Parse a Python integer literal, handling all bases.
        """
        # remove underscores (e.g., 1_000_000)
        s = s.replace("_", "")
        try:
            if s.startswith(("0x", "0X")):
                return int(s, 16)
            elif s.startswith(("0o", "0O")):
                return int(s, 8)
            elif s.startswith(("0b", "0B")):
                return int(s, 2)
            else:
                return int(s)
        except ValueError:
            return None
