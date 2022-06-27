from typing import Tuple, Union, Iterator

import capa.features.extractors.scripts
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import Feature, BBHandle, InsnHandle, FunctionHandle, FeatureExtractor


class TreeSitterFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str, format_: str):
        super().__init__()
        self.path = path
        self.languages = [capa.features.extractors.scripts.get_language_from_format(format_)]

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, capa.features.address._NoAddress]:
        return NO_ADDRESS

    def extract_global_features(self):
        raise NotImplementedError("not implemented")

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def get_functions(self) -> Iterator[FunctionHandle]:
        raise NotImplementedError("not implemented")

    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        raise NotImplementedError("not implemented")

    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def get_instructions(self, f: FunctionHandle, bb: BBHandle):
        raise NotImplementedError("not implemented")

    def extract_insn_features(
        self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        raise NotImplementedError("not implemented")

    def is_library_function(self, addr: Address) -> bool:
        raise NotImplementedError("not implemented")

    def get_function_name(self, addr: Address) -> str:
        raise NotImplementedError("not implemented")
