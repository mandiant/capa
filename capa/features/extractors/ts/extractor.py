from typing import List, Tuple, Union, Iterator

import capa.features.extractors.script
import capa.features.extractors.ts.file
import capa.features.extractors.ts.engine
import capa.features.extractors.ts.global_
import capa.features.extractors.ts.function
from capa.features.common import Namespace
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress, FileOffsetRangeAddress
from capa.features.extractors.script import LANG_TEM, LANG_HTML
from capa.features.extractors.ts.tools import BaseNamespace
from capa.features.extractors.ts.engine import TreeSitterHTMLEngine, TreeSitterTemplateEngine, TreeSitterExtractorEngine
from capa.features.extractors.ts.function import PSEUDO_MAIN, TSFunctionInner
from capa.features.extractors.base_extractor import Feature, BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class TreeSitterFeatureExtractor(FeatureExtractor):
    engines: List[TreeSitterExtractorEngine]
    template_engine: TreeSitterTemplateEngine
    language: str
    path: str

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        with open(self.path, "rb") as f:
            buf = f.read()

        self.language = capa.features.extractors.script.get_language_from_ext(path)
        if self.language == LANG_TEM:
            self.template_engine = TreeSitterTemplateEngine(buf)
            self.engines = self.extract_code_from_template()
        elif self.language == LANG_HTML:
            self.engines = self.extract_code_from_html(buf)
        else:
            self.engines = [TreeSitterExtractorEngine(self.language, buf)]

    def extract_code_from_template(self) -> List[TreeSitterExtractorEngine]:
        engines = list(self.template_engine.get_parsed_code_sections())
        for node, _ in self.template_engine.get_content_sections():
            section_buf = self.template_engine.get_byte_range(node)
            engines.extend(list(self.extract_code_from_html(section_buf, self.template_engine.namespaces)))
        return engines

    def extract_code_from_html(
        self, buf: bytes, namespaces: set[BaseNamespace] = set()
    ) -> List[TreeSitterExtractorEngine]:
        return list(TreeSitterHTMLEngine(buf, namespaces).get_parsed_code_sections())

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, capa.features.address._NoAddress]:
        return NO_ADDRESS

    def extract_template_namespaces(self) -> Iterator[Tuple[Feature, Address]]:
        for ns in self.template_engine.get_namespaces():
            address = NO_ADDRESS if ns.node is None else FileOffsetRangeAddress(ns.node.start_byte, ns.node.end_byte)
            yield Namespace(ns.name), address

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ts.global_.extract_features()

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        if self.language == LANG_TEM:
            yield from self.extract_template_namespaces()
        for engine in self.engines:
            yield from capa.features.extractors.ts.file.extract_features(engine)

    def get_pseudo_main_function_inner(self, engine: TreeSitterExtractorEngine) -> TSFunctionInner:
        return TSFunctionInner(engine.tree.root_node, PSEUDO_MAIN, engine)

    def get_pseudo_main_function(self, engine: TreeSitterExtractorEngine) -> FunctionHandle:
        return FunctionHandle(engine.get_default_address(), self.get_pseudo_main_function_inner(engine))

    def get_functions(self) -> Iterator[FunctionHandle]:
        for engine in self.engines:
            yield self.get_pseudo_main_function(engine)
            for node, _ in engine.get_function_definitions():
                name = engine.get_range(engine.get_function_definition_name(node))
                yield FunctionHandle(engine.get_address(node), TSFunctionInner(node, name, engine))

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
