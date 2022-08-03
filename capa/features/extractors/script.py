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


def extract_arch() -> Iterator[Tuple[Feature, Address]]:
    yield Arch(ARCH_ANY), NO_ADDRESS


def extract_language(language: str, addr: FileOffsetRangeAddress) -> Iterator[Tuple[Feature, Address]]:
    yield ScriptLanguage(language), addr


def extract_os() -> Iterator[Tuple[Feature, Address]]:
    yield OS(OS_ANY), NO_ADDRESS


def extract_format() -> Iterator[Tuple[Feature, Address]]:
    yield Format(FORMAT_SCRIPT), NO_ADDRESS


def get_language_from_ext(path: str) -> str:
    if path.endswith(EXT_ASPX):
        return LANG_TEM
    if path.endswith(EXT_CS):
        return LANG_CS
    if path.endswith(EXT_HTML):
        return LANG_HTML
    if path.endswith(EXT_PY):
        return LANG_PY
    raise ValueError(f"{path} has an unrecognized or an unsupported extension.")
