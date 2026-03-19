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
Script analysis backend for capa.

Uses tree-sitter to parse scripts into ASTs and extract features
for capability detection. The architecture is modular: core
infrastructure is language-agnostic, and each supported language
implements a LanguageHandler plugin.

Supported languages:
  - Python (via tree-sitter-python)

To add a new language:
  1. Create a handler in capa/features/extractors/script/languages/
  2. Register it in LANGUAGE_HANDLERS below
"""

import re
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# mapping from language name to file extensions (without dot)
SCRIPT_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python": ("py", "py3"),
}

# shebang patterns: compiled regex -> language name
SHEBANG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(rb"^#!.*\bpython[23]?\b"), "python"),
]


def detect_script_language(path: Path, buf: bytes) -> str:
    """
    Detect the scripting language of the given file.

    Checks in order:
      1. File extension
      2. Shebang line

    args:
      path: path to the script file.
      buf: raw bytes of the file.

    returns:
      the language name (e.g., "python"), or empty string if unknown.
    """
    # 1. check file extension
    suffix = path.suffix.lstrip(".")
    for language, extensions in SCRIPT_EXTENSIONS.items():
        if suffix in extensions:
            return language

    # 2. check shebang line
    first_line = buf.split(b"\n", 1)[0]
    for pattern, language in SHEBANG_PATTERNS:
        if pattern.match(first_line):
            return language

    return ""
