from typing import Tuple, Union, Iterator

import capa.features.extractors.script
import capa.features.extractors.ts.file
import capa.features.extractors.ts.engine
import capa.features.extractors.ts.global_
import capa.features.extractors.ts.function
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress
from capa.features.extractors.ts.engine import TreeSitterExtractorEngine
from capa.features.extractors.base_extractor import Feature, BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class TreeSitterFeatureExtractor(FeatureExtractor):
    engine: TreeSitterExtractorEngine

    def __init__(self, path: str):
        super().__init__()
        self.engine = TreeSitterExtractorEngine(capa.features.extractors.script.get_language_from_ext(path), path)

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, capa.features.address._NoAddress]:
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ts.global_.extract_features()

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ts.file.extract_features(self.engine)

    def get_functions(self) -> Iterator[FunctionHandle]:
        for node, _ in self.engine.get_function_definitions():
            yield FunctionHandle(address=self.engine.get_address(node), inner=node)

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.ts.function.extract_features(f, self.engine)

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

    def is_library_function(self, addr) -> bool:
        return False

    def get_function_name(self, addr) -> str:
        return self.engine.tree.buf[addr.start_byte : addr.end_byte].decode()
