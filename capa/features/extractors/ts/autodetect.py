from typing import Optional

from tree_sitter import Node, Tree, Parser, Language

from capa.features.extractors.script import EXT_CS, EXT_PY, LANG_CS, LANG_PY, EXT_ASPX, EXT_HTML, LANG_TEM, LANG_HTML
from capa.features.extractors.ts.query import TS_LANGUAGES


def is_script(buf: bytes) -> bool:
    try:
        return bool(get_language_ts(buf))
    except ValueError:
        return False


def _parse(ts_language: Language, buf: bytes) -> Optional[Tree]:
    try:
        parser = Parser()
        parser.set_language(ts_language)
        return parser.parse(buf)
    except ValueError:
        return None


def _contains_errors(ts_language, node: Node) -> bool:
    return ts_language.query("(ERROR) @error").captures(node)


def get_language_ts(buf: bytes) -> str:
    for language, ts_language in TS_LANGUAGES.items():
        tree = _parse(ts_language, buf)
        if tree and not _contains_errors(ts_language, tree.root_node):
            return language
    raise ValueError("failed to parse the language")


def get_template_language_ts(buf: bytes) -> str:
    for language, ts_language in TS_LANGUAGES.items():
        if language in [LANG_TEM, LANG_HTML]:
            continue
        tree = _parse(ts_language, buf)
        if tree and not _contains_errors(ts_language, tree.root_node):
            return language
    raise ValueError("failed to parse the language")


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


def get_language(path: str) -> str:
    try:
        with open(path, "rb") as f:
            buf = f.read()
        return get_language_ts(buf)
    except ValueError:
        return get_language_from_ext(path)
