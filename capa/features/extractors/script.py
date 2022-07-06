import os
from typing import Tuple, Iterator

from capa.features.common import OS, OS_ANY, ARCH_ANY, FORMAT_SCRIPT, Arch, Format, Feature, ScriptLanguage
from capa.features.address import NO_ADDRESS, Address, FileOffsetRangeAddress

LANG_ASPX = "aspx"
LANG_CS = "c_sharp"


def extract_arch() -> Iterator[Tuple[Feature, Address]]:
    yield Arch(ARCH_ANY), NO_ADDRESS


def extract_language(language: str, addr: FileOffsetRangeAddress) -> Iterator[Tuple[Feature, Address]]:
    yield ScriptLanguage(language), addr


def extract_os() -> Iterator[Tuple[Feature, Address]]:
    yield OS(OS_ANY), NO_ADDRESS


def extract_format() -> Iterator[Tuple[Feature, Address]]:
    yield Format(FORMAT_SCRIPT), NO_ADDRESS


def get_language_from_ext(path: str):
    if path.endswith((".aspx", "aspx_")):
        return LANG_ASPX
    if path.endswith((".cs", ".cs_")):
        return LANG_CS
    raise ValueError(f"{path} has an unrecognized or an unsupported extension.")
