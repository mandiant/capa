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
Statement-scope (instruction) feature extraction for scripts.

Extracts features from individual statement-level AST nodes:
  - API features (function calls)
  - String features (string literals)
  - Number features (numeric literals)

Follows the same INSTRUCTION_HANDLERS tuple pattern used in
viv/insn.py and dnfile/insn.py.
"""

import logging
from typing import Callable, Iterator

from tree_sitter import Node

from capa.features.common import Feature
from capa.features.address import Address
from capa.features.extractors.script.lang_base import ImportContext, LanguageHandler
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle

logger = logging.getLogger(__name__)


def extract_insn_api_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """
    Extract API (function call) features from the given statement.

    Delegates to the language handler's extract_insn_api_features,
    which handles language-specific call resolution and import context.
    """
    handler: LanguageHandler = fh.ctx["handler"]
    ctx: ImportContext = fh.ctx["import_ctx"]
    node: Node = ih.inner
    yield from handler.extract_insn_api_features(node, ctx)


def extract_insn_string_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """
    Extract string literal features from the given statement.
    """
    handler: LanguageHandler = fh.ctx["handler"]
    node: Node = ih.inner
    yield from handler.extract_insn_string_features(node)


def extract_insn_number_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """
    Extract numeric literal features from the given statement.
    """
    handler: LanguageHandler = fh.ctx["handler"]
    node: Node = ih.inner
    yield from handler.extract_insn_number_features(node)


INSTRUCTION_HANDLERS: tuple[
    Callable[[FunctionHandle, BBHandle, InsnHandle], Iterator[tuple[Feature, Address]]],
    ...,
] = (
    extract_insn_api_features,
    extract_insn_string_features,
    extract_insn_number_features,
)


def extract_features(
    fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
) -> Iterator[tuple[Feature, Address]]:
    """
    Extract features from the given statement (instruction scope).

    args:
      fh: the function handle containing the statement.
      bbh: the basic block handle (function body).
      ih: the instruction handle (statement node).

    yields:
      (Feature, Address): instruction-scope features.
    """
    for handler in INSTRUCTION_HANDLERS:
        for feature, addr in handler(fh, bbh, ih):
            yield feature, addr
