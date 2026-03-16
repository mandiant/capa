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

from typing import Tuple, Iterator

from capa.features.common import OS, OS_ANY, ARCH_ANY, FORMAT_SCRIPT, Arch, Format, Feature, ScriptLanguage
from capa.features.address import NO_ADDRESS, Address, FileOffsetRangeAddress

# Can be used to instantiate tree_sitter Language objects (see ts/query.py)
LANG_CS = "c_sharp"
LANG_HTML = "html"
LANG_JS = "javascript"
LANG_PY = "python"
LANG_TEM = "embedded_template"

EXT_ASPX = ("aspx", "aspx_")
EXT_CS = ("cs", "cs_")
EXT_HTML = ("html", "html_")
EXT_PY = ("py", "py_")


LANGUAGE_FEATURE_FORMAT = {
    LANG_CS: "C#",
    LANG_HTML: "HTML",
    LANG_JS: "JavaScript",
    LANG_PY: "Python",
    LANG_TEM: "Embedded Template",
}


def extract_arch() -> Iterator[Tuple[Feature, Address]]:
    yield Arch(ARCH_ANY), NO_ADDRESS


def extract_language(language: str, addr: FileOffsetRangeAddress) -> Iterator[Tuple[Feature, Address]]:
    yield ScriptLanguage(LANGUAGE_FEATURE_FORMAT[language]), addr


def extract_os() -> Iterator[Tuple[Feature, Address]]:
    yield OS(OS_ANY), NO_ADDRESS


def extract_format() -> Iterator[Tuple[Feature, Address]]:
    yield Format(FORMAT_SCRIPT), NO_ADDRESS
