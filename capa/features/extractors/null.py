from typing import Dict, List, Tuple, Union, TypeAlias
from dataclasses import dataclass

from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address, ThreadAddress, ProcessAddress
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    ThreadHandle,
    ProcessHandle,
    FunctionHandle,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)


@dataclass
class InstructionFeatures:
    features: List[Tuple[Address, Feature]]


@dataclass
class BasicBlockFeatures:
    features: List[Tuple[Address, Feature]]
    instructions: Dict[Address, InstructionFeatures]


@dataclass
class FunctionFeatures:
    features: List[Tuple[Address, Feature]]
    basic_blocks: Dict[Address, BasicBlockFeatures]


@dataclass
class NullStaticFeatureExtractor(StaticFeatureExtractor):
    """
    An extractor that extracts some user-provided features.

    This is useful for testing, as we can provide expected values and see if matching works.
    """

    base_address: Address
    global_features: List[Feature]
    file_features: List[Tuple[Address, Feature]]
    functions: Dict[Address, FunctionFeatures]

    def get_base_address(self):
        return self.base_address

    def extract_global_features(self):
        for feature in self.global_features:
            yield feature, NO_ADDRESS

    def extract_file_features(self):
        for address, feature in self.file_features:
            yield feature, address

    def get_functions(self):
        for address in sorted(self.functions.keys()):
            yield FunctionHandle(address, None)

    def extract_function_features(self, f):
        for address, feature in self.functions[f.address].features:
            yield feature, address

    def get_basic_blocks(self, f):
        for address in sorted(self.functions[f.address].basic_blocks.keys()):
            yield BBHandle(address, None)

    def extract_basic_block_features(self, f, bb):
        for address, feature in self.functions[f.address].basic_blocks[bb.address].features:
            yield feature, address

    def get_instructions(self, f, bb):
        for address in sorted(self.functions[f.address].basic_blocks[bb.address].instructions.keys()):
            yield InsnHandle(address, None)

    def extract_insn_features(self, f, bb, insn):
        for address, feature in self.functions[f.address].basic_blocks[bb.address].instructions[insn.address].features:
            yield feature, address


@dataclass
class ThreadFeatures:
    features: List[Tuple[Address, Feature]]


@dataclass
class ProcessFeatures:
    features: List[Tuple[Address, Feature]]
    threads: Dict[Address, ThreadFeatures]


@dataclass
class NullDynamicFeatureExtractor(DynamicFeatureExtractor):
    base_address: Address
    global_features: List[Feature]
    file_features: List[Tuple[Address, Feature]]
    processes: Dict[Address, ProcessFeatures]

    def extract_global_features(self):
        for feature in self.global_features:
            yield feature, NO_ADDRESS

    def extract_file_features(self):
        for address, feature in self.file_features:
            yield feature, address

    def get_processes(self):
        for address in sorted(self.processes.keys()):
            assert isinstance(address, ProcessAddress)
            yield ProcessHandle(address=address, inner={})

    def extract_process_features(self, p):
        for addr, feature in self.processes[p.address].features:
            yield feature, addr

    def get_threads(self, p):
        for address in sorted(self.processes[p].threads.keys()):
            assert isinstance(address, ThreadAddress)
            yield ThreadHandle(address=address, inner={})

    def extract_thread_features(self, p, t):
        for addr, feature in self.processes[p.address].threads[t.address].features:
            yield feature, addr


NullFeatureExtractor: TypeAlias = Union[NullStaticFeatureExtractor, NullDynamicFeatureExtractor]
