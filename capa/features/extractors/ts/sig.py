import json
import importlib.resources
from typing import Callable

import capa.features.extractors.ts.signatures
from capa.features.extractors.script import LANG_CS


def get_sig_file(language: str) -> str:
    if language == LANG_CS:
        return "cs.json"
    raise ValueError("Language {language} does not have an import signature file")


def load_import_signatures(language: str) -> set:
    sig_file = get_sig_file(language)
    return set(json.loads(importlib.resources.read_text(capa.features.extractors.ts.signatures, sig_file)))


def get_name_joiner(language: str) -> Callable:
    if language == LANG_CS:
        return lambda qualified_name, identifier: qualified_name + "." + identifier
    raise ValueError("Language {language} does not have a name joiner")
