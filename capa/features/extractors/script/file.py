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
File-scope feature extraction for scripts.

Extracts features that apply to the entire script file:
  - Import features (from import statements)
  - String features (from file-level string scanning)
"""

import logging
from typing import Callable, Iterator

from tree_sitter import Tree

import capa.features.extractors.common
from capa.features.file import Import
from capa.features.common import String, Feature
from capa.features.address import NO_ADDRESS, Address, ScriptAddress
from capa.features.extractors.script.lang_base import LanguageHandler

logger = logging.getLogger(__name__)


def extract_file_import_features(
    tree: Tree, handler: LanguageHandler, buf: bytes
) -> Iterator[tuple[Feature, Address]]:
    """
    Extract Import features from the script's import statements.

    Each import statement yields an Import feature with the module name.
    """
    ctx = handler.extract_imports(tree)
    for local_name, qualified_name in ctx.names.items():
        yield Import(qualified_name), NO_ADDRESS

    for module_name in ctx.wildcard_modules:
        yield Import(module_name), NO_ADDRESS


def extract_file_string_features(
    tree: Tree, handler: LanguageHandler, buf: bytes
) -> Iterator[tuple[Feature, Address]]:
    """
    Extract string features from the file using byte-level string scanning.

    This uses capa's existing string extraction (ASCII + UTF-16 LE),
    which provides coverage even for strings not visible in the AST
    (e.g., in comments, docstrings, or encoded data).
    """
    yield from capa.features.extractors.common.extract_file_strings(buf)


FILE_HANDLERS: tuple[
    Callable[[Tree, LanguageHandler, bytes], Iterator[tuple[Feature, Address]]],
    ...,
] = (
    extract_file_import_features,
    extract_file_string_features,
)


def extract_features(
    tree: Tree, handler: LanguageHandler, buf: bytes
) -> Iterator[tuple[Feature, Address]]:
    """
    Extract file-scope features from the script.

    args:
      tree: the parsed tree-sitter Tree.
      handler: the language handler for this script.
      buf: raw bytes of the file.

    yields:
      (Feature, Address): file-scope features.
    """
    for handler_func in FILE_HANDLERS:
        for feature, addr in handler_func(tree, handler, buf):
            yield feature, addr
