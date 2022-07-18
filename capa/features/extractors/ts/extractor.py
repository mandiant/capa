from typing import List, Tuple, Union, Iterator

from tree_sitter import Node

import capa.features.extractors.script
import capa.features.extractors.ts.file
import capa.features.extractors.ts.engine
import capa.features.extractors.ts.global_
import capa.features.extractors.ts.function
from capa.features.common import Namespace
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress, FileOffsetRangeAddress
from capa.features.extractors.script import LANG_TEM, LANG_HTML
from capa.features.extractors.ts.engine import TreeSitterHTMLEngine, TreeSitterTemplateEngine, TreeSitterExtractorEngine
from capa.features.extractors.ts.function import PSEUDO_MAIN, TSFunctionInner
from capa.features.extractors.base_extractor import Feature, BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class TreeSitterFeatureExtractor(FeatureExtractor):
    code_sections: List[TreeSitterExtractorEngine]
    template_namespaces: List[Tuple[Node, str]]
    language: str
    path: str

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        with open(self.path, "rb") as f:
            buf = f.read()

        self.language = capa.features.extractors.script.get_language_from_ext(path)
        if self.language == LANG_TEM:
            (
                self.code_sections,
                self.template_namespaces,
            ) = self.extract_code_from_template(buf)
        elif self.language == LANG_HTML:
            self.code_sections = list(self.extract_code_from_html(buf))
        else:
            self.code_sections = [TreeSitterExtractorEngine(self.language, buf)]

    def extract_code_from_template(self, buf: bytes) -> Tuple[List[TreeSitterExtractorEngine], List[Tuple[Node, str]]]:
        template_engine = TreeSitterTemplateEngine(buf)
        template_namespaces = list(template_engine.get_template_namespaces())
        code_sections = list(template_engine.get_parsed_code_sections())

        additional_namespaces = set(name for _, name in template_namespaces)
        for node, _ in template_engine.get_content_sections():
            section_buf = template_engine.get_byte_range(node)
            code_sections.extend(list(self.extract_code_from_html(section_buf, additional_namespaces)))
        return code_sections, template_namespaces

    def extract_code_from_html(
        self, buf: bytes, additional_namespaces: set[str] = None
    ) -> Iterator[TreeSitterExtractorEngine]:
        yield from TreeSitterHTMLEngine(buf, additional_namespaces).get_parsed_code_sections()

    def get_base_address(
        self,
    ) -> Union[AbsoluteVirtualAddress, capa.features.address._NoAddress]:
        return NO_ADDRESS

    def extract_template_namespaces(self) -> Iterator[Tuple[Feature, Address]]:
        for node, name in self.template_namespaces:
            if node is None:
                yield Namespace(name), NO_ADDRESS
            else:
                yield Namespace(name), FileOffsetRangeAddress(node.start_byte, node.end_byte)

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ts.global_.extract_features()

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        if self.language == LANG_TEM:
            yield from self.extract_template_namespaces()
        for engine in self.code_sections:
            yield from capa.features.extractors.ts.file.extract_features(engine)

    def get_pseudo_main_function(self, engine: TreeSitterExtractorEngine) -> FunctionHandle:
        return FunctionHandle(
            address=engine.get_default_address(), inner=TSFunctionInner(engine.tree.root_node, PSEUDO_MAIN, engine)
        )

    def get_functions(self) -> Iterator[FunctionHandle]:
        for engine in self.code_sections:
            yield self.get_pseudo_main_function(engine)
            for node, _ in engine.get_function_definitions():
                name = engine.get_range(engine.get_function_definition_name(node))
                yield FunctionHandle(address=engine.get_address(node), inner=TSFunctionInner(node, name, engine))

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ts.function.extract_features(f, f.inner.engine)

    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        yield from []

    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from []

    def get_instructions(self, f: FunctionHandle, bb: BBHandle) -> Iterator[InsnHandle]:
        yield from []

    def extract_insn_features(
        self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        yield from []
