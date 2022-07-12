from typing import Optional

from capa.features.extractors.script import LANG_CS


def parse_integer(integer: str, language: str) -> Optional[int]:
    try:
        if language == LANG_CS:
            if integer.endswith(("u", "l")):
                integer = integer[:-1]
            if integer.startswith(("0x", "0X")):
                return int(integer, 16)
        return int(integer)
    except:
        return None
