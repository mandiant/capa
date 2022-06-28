from typing import List, Tuple, Union, Iterator

import capa.features.extractors.scripts
import capa.features.extractors.ts.engine
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress, FileOffsetRangeAddress
from capa.features.extractors.base_extractor import Feature, BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class TreeSitterFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str, format_: str):
        super().__init__()
        self.path = path
        self.language = capa.features.extractors.scripts.get_language_from_format(format_)
        with open(self.path, "rb") as f:
            self.buf = f.read()
        self.engine = capa.features.extractors.ts.engine.TreeSitterExtractorEngine(self.language)
        self.tree = self.engine.parse(self.buf)

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features: List[Tuple[Feature, Address]] = []
        self.global_features.extend(
            capa.features.extractors.scripts.extract_language(self.language, FileOffsetRangeAddress(0, len(self.buf)))
        )
        self.global_features.extend(capa.features.extractors.scripts.extract_os())
        self.global_features.extend(capa.features.extractors.scripts.extract_arch())

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, capa.features.address._NoAddress]:
        return NO_ADDRESS

    def extract_global_features(self):
        yield from self.global_features

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def get_functions(self) -> Iterator[FunctionHandle]:
        for node, _ in self.engine.get_functions(self.tree):
            yield FunctionHandle(address=FileOffsetRangeAddress(node.start_byte, node.end_byte), inner=node)

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        yield from []

    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

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
