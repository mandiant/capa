from typing import Tuple, Iterator

from capa.features.common import OS, OS_ANY, ARCH_ANY, FORMAT_CS, Arch, Feature
from capa.features.address import NO_ADDRESS, Address

LANG_CS = "c_sharp"


def extract_arch() -> Iterator[Tuple[Feature, Address]]:
    yield Arch(ARCH_ANY), NO_ADDRESS


def extract_os() -> Iterator[Tuple[Feature, Address]]:
    yield OS(OS_ANY), NO_ADDRESS


def get_language_from_format(format_: str) -> str:
    if format_ == FORMAT_CS:
        return LANG_CS
    return "unknown"
