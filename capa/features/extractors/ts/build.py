from tree_sitter import Language

build_dir = "build/my-languages.so"
languages = [
    "vendor/tree-sitter-c-sharp",
]


def ts_build():
    Language.build_library(build_dir, languages)
