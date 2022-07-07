from tree_sitter import Language

build_dir = "build/my-languages.so"
languages = [
    "vendor/tree-sitter-c-sharp",
    "vendor/tree-sitter-embedded-template",
    "vendor/tree-sitter-html",
    "vendor/tree-sitter-javascript",
]


def ts_build():
    Language.build_library(build_dir, languages)
