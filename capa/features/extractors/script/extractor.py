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
ScriptFeatureExtractor — the main extractor for script analysis.

Implements capa's StaticFeatureExtractor interface using tree-sitter
for AST-based feature extraction. Language-specific logic is delegated
to LanguageHandler instances (e.g., PythonLanguageHandler).

Scope mapping for scripts:
  - File scope:     entire script (imports, global strings, etc.)
  - Function scope: each function definition in the script
  - Basic block:    one BB per function (like dnfile for .NET)
  - Instruction:    each statement-level AST node
"""

import hashlib
import logging
from typing import Iterator
from pathlib import Path

from tree_sitter import Parser

import capa.features.extractors.script.file
import capa.features.extractors.script.insn
from capa.features.insn import API
from capa.features.common import OS, ARCH_ANY, OS_ANY, FORMAT_SCRIPT, Arch, Format, Feature, String
from capa.features.address import NO_ADDRESS, Address, ScriptAddress
from capa.features.extractors.script import detect_script_language
from capa.features.extractors.script.lang_base import ImportContext, LanguageHandler
from capa.features.extractors.script.languages.python import PythonLanguageHandler
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)

logger = logging.getLogger(__name__)


# registry of language handlers
LANGUAGE_HANDLERS: dict[str, LanguageHandler] = {
    "python": PythonLanguageHandler(),
}


class ScriptFeatureExtractor(StaticFeatureExtractor):
    """
    Feature extractor for scripting languages using tree-sitter.

    This extractor:
      1. Detects the script language (via extension/shebang)
      2. Parses the script with the appropriate tree-sitter grammar
      3. Delegates feature extraction to a LanguageHandler plugin
      4. Yields features following capa's scope hierarchy

    The design mirrors existing backends (dnfile, vivisect):
      - Global features: format, OS, arch
      - File features: imports, strings
      - Function features: one per function definition
      - Basic block: one per function body (like dnfile)
      - Instruction features: one per statement in function body
    """

    def __init__(self, path: Path, language: str = ""):
        buf = path.read_bytes()
        self.path = path
        self.buf = buf

        md5 = hashlib.md5(buf).hexdigest()
        sha1 = hashlib.sha1(buf).hexdigest()
        sha256 = hashlib.sha256(buf).hexdigest()
        super().__init__(
            hashes=SampleHashes(
                md5=md5,
                sha1=sha1,
                sha256=sha256,
            )
        )

        # detect language
        if not language:
            language = detect_script_language(path, buf)
        if not language:
            raise ValueError(f"unable to detect script language for: {path}")

        self.language = language

        # get the language handler
        if language not in LANGUAGE_HANDLERS:
            raise ValueError(f"unsupported script language: {language}")
        self.handler: LanguageHandler = LANGUAGE_HANDLERS[language]

        # parse the script with tree-sitter
        parser = Parser(self.handler.get_tree_sitter_language())
        self.tree = parser.parse(buf)

        # pre-compute import context for API name resolution
        self.import_ctx: ImportContext = self.handler.extract_imports(self.tree)

        # pre-compute global features (yielded at every scope)
        self.global_features: list[tuple[Feature, Address]] = []
        self.global_features.append((Format(FORMAT_SCRIPT), NO_ADDRESS))
        self.global_features.append((OS(OS_ANY), NO_ADDRESS))
        self.global_features.append((Arch(ARCH_ANY), NO_ADDRESS))

    def get_base_address(self) -> Address:
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from self.global_features

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.script.file.extract_features(
            self.tree, self.handler, self.buf
        )

    def get_functions(self) -> Iterator[FunctionHandle]:
        """
        Yield a FunctionHandle for each function definition in the script.

        The inner object is the tree-sitter Node for the function definition.
        Context stores the import context for name resolution.
        """
        for node in self.handler.get_function_nodes(self.tree):
            name = self.handler.get_function_name(node)
            addr = ScriptAddress(
                line=node.start_point[0],
                column=node.start_point[1],
            )
            yield FunctionHandle(
                address=addr,
                inner=node,
                ctx={"handler": self.handler, "import_ctx": self.import_ctx, "name": name},
            )

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
        # no function-scope features in the skeleton
        # future: call count, decorator characteristics, etc.
        yield from ()

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        """
        Yield one basic block per function (like dnfile).

        Scripts don't have basic blocks in the traditional sense,
        so we treat the entire function body as a single block.
        """
        yield BBHandle(
            address=fh.address,
            inner=fh.inner,
        )

    def extract_basic_block_features(
        self, fh: FunctionHandle, bbh: BBHandle
    ) -> Iterator[tuple[Feature, Address]]:
        # no basic-block-scope features in the skeleton
        yield from ()

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        """
        Yield an InsnHandle for each statement in the function body.

        Each statement-level AST node maps to one "instruction" in capa's model.
        """
        handler: LanguageHandler = fh.ctx["handler"]
        for node in handler.get_statement_nodes(fh.inner):
            addr = ScriptAddress(
                line=node.start_point[0],
                column=node.start_point[1],
            )
            yield InsnHandle(
                address=addr,
                inner=node,
            )

    def extract_insn_features(
        self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
    ) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.script.insn.extract_features(fh, bbh, ih)

    def is_library_function(self, addr: Address) -> bool:
        # scripts don't have library functions in the traditional sense
        return False

    def get_function_name(self, addr: Address) -> str:
        # not used in the current pipeline for script analysis
        return ""
