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
Abstract base for language handlers.

Each supported scripting language implements a LanguageHandler subclass
that knows how to walk its specific AST node types and extract capa features.

The core extractor (ScriptFeatureExtractor) delegates to these handlers,
keeping language-specific logic isolated.
"""

import abc
import logging
from typing import Iterator
from dataclasses import field, dataclass

from tree_sitter import Node, Tree

from capa.features.common import Feature
from capa.features.address import Address

logger = logging.getLogger(__name__)


@dataclass
class ImportContext:
    """
    Tracks import statements and their aliases within a script.

    Used to resolve function calls to their fully-qualified module paths.

    examples:
      `import os`           -> names = {"os": "os"}
      `import os as o`      -> names = {"o": "os"}
      `from os.path import join` -> names = {"join": "os.path.join"}
      `from os.path import *`    -> wildcard_modules = {"os.path"}

    When resolving a call like `o.system(...)`, the handler looks up
    "o" in names to get "os", then constructs "os.system".
    """

    # mapping from local name -> fully-qualified module/attribute name
    names: dict[str, str] = field(default_factory=dict)

    # modules imported via wildcard (from X import *)
    # we can't resolve individual names from these, but we track them
    wildcard_modules: set[str] = field(default_factory=set)

    def resolve_name(self, name: str) -> str:
        """
        Resolve a local name to its fully-qualified import path.

        args:
          name: the local name used in the script (e.g., "o" for `import os as o`).

        returns:
          the resolved name (e.g., "os"), or the original name if not found.
        """
        return self.names.get(name, name)


class LanguageHandler(abc.ABC):
    """
    Plugin interface for language-specific AST feature extraction.

    Each supported scripting language (Python, Bash, PowerShell, etc.)
    implements this interface. The core ScriptFeatureExtractor uses it
    to walk the AST and extract features without knowing any
    language-specific details.

    To add a new language:
      1. Subclass LanguageHandler
      2. Implement all abstract methods
      3. Register in the LANGUAGE_HANDLERS dict in __init__.py
    """

    @abc.abstractmethod
    def get_tree_sitter_language(self):
        """
        Return the tree-sitter Language object for this language.

        returns:
          tree_sitter.Language: the language grammar object.
        """
        ...

    @abc.abstractmethod
    def get_function_nodes(self, tree: Tree) -> Iterator[Node]:
        """
        Yield top-level AST nodes that represent function definitions.

        args:
          tree: the parsed tree-sitter Tree.

        yields:
          Node: each function definition node.
        """
        ...

    @abc.abstractmethod
    def get_function_name(self, node: Node) -> str:
        """
        Extract the function name from a function definition node.

        args:
          node: a function definition AST node.

        returns:
          str: the function name.
        """
        ...

    @abc.abstractmethod
    def get_statement_nodes(self, node: Node) -> Iterator[Node]:
        """
        Yield statement-level AST nodes within a function body.

        These map to capa's "instruction" scope.

        args:
          node: a function definition AST node.

        yields:
          Node: each statement node within the function body.
        """
        ...

    @abc.abstractmethod
    def extract_imports(self, tree: Tree) -> ImportContext:
        """
        Parse import statements and build an ImportContext.

        args:
          tree: the parsed tree-sitter Tree.

        returns:
          ImportContext: the resolved import context.
        """
        ...

    @abc.abstractmethod
    def extract_insn_api_features(
        self, node: Node, ctx: ImportContext
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Extract API/function-call features from a statement node.

        args:
          node: a statement-level AST node.
          ctx: the script's import context for name resolution.

        yields:
          (Feature, Address): API features and their script addresses.
        """
        ...

    @abc.abstractmethod
    def extract_insn_string_features(
        self, node: Node
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Extract string literal features from a statement node.

        args:
          node: a statement-level AST node.

        yields:
          (Feature, Address): String features and their script addresses.
        """
        ...

    @abc.abstractmethod
    def extract_insn_number_features(
        self, node: Node
    ) -> Iterator[tuple[Feature, Address]]:
        """
        Extract numeric literal features from a statement node.

        args:
          node: a statement-level AST node.

        yields:
          (Feature, Address): Number features and their script addresses.
        """
        ...
