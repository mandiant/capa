from dataclasses import dataclass

from tree_sitter import Tree

import capa.features.extractors.script
from capa.features.address import FileOffsetRangeAddress


@dataclass
class GlobalScriptContext:
    language: str
    tree: Tree


def extract_arch(ctx: GlobalScriptContext):
    yield from capa.features.extractors.script.extract_arch()


def extract_language(ctx: GlobalScriptContext):
    node = ctx.tree.root_node
    addr = FileOffsetRangeAddress(node.start_byte, node.end_byte)
    yield from capa.features.extractors.script.extract_language(ctx.language, addr)


def extract_os(ctx: GlobalScriptContext):
    yield from capa.features.extractors.script.extract_os()


def extract_features(ctx: GlobalScriptContext):
    for glob_handler in GLOBAL_HANDLERS:
        yield glob_handler(ctx)


GLOBAL_HANDLERS = (extract_arch, extract_os, extract_language)
