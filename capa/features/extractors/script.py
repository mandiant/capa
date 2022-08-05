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
