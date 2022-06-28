from typing import List, Tuple, Union, Iterator

import capa.features.extractors.script
import capa.features.extractors.ts.engine
import capa.features.extractors.ts.global_
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress, FileOffsetRangeAddress
from capa.features.extractors.base_extractor import Feature, BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class TreeSitterFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self.language = capa.features.extractors.script.get_language_from_ext(path)
        with open(self.path, "rb") as f:
            self.buf = f.read()
        self.engine = capa.features.extractors.ts.engine.TreeSitterExtractorEngine(self.language)
        self.tree = self.engine.parse(self.buf)

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, capa.features.address._NoAddress]:
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        ctx = capa.features.extractors.ts.global_.GlobalScriptContext(self.language, self.tree)
        yield from capa.features.extractors.ts.global_.extract_features(ctx)

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from []

    def get_functions(self) -> Iterator[FunctionHandle]:
        for node, _ in self.engine.get_functions(self.tree):
            yield FunctionHandle(address=FileOffsetRangeAddress(node.start_byte, node.end_byte), inner=node)

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        yield from []

    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from []

    def get_instructions(self, f: FunctionHandle, bb: BBHandle) -> Iterator[InsnHandle]:
        yield from []

    def extract_insn_features(
        self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def is_library_function(self, addr) -> bool:
        return False

    def get_function_name(self, addr) -> str:
        return self.buf[addr.start_byte : addr.end_byte].decode()
