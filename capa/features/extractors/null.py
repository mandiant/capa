# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Dict, List, Tuple, Union
from dataclasses import dataclass

from typing_extensions import TypeAlias

from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address, ThreadAddress, ProcessAddress, DynamicCallAddress
from capa.features.extractors.base_extractor import (
    BBHandle,
    CallHandle,
    InsnHandle,
    SampleHashes,
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
    sample_hashes: SampleHashes
    global_features: List[Feature]
    file_features: List[Tuple[Address, Feature]]
    functions: Dict[Address, FunctionFeatures]

    def get_base_address(self):
        return self.base_address

    def get_sample_hashes(self) -> SampleHashes:
        return self.sample_hashes

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
class CallFeatures:
    name: str
    features: List[Tuple[Address, Feature]]


@dataclass
class ThreadFeatures:
    features: List[Tuple[Address, Feature]]
    calls: Dict[Address, CallFeatures]


@dataclass
class ProcessFeatures:
    features: List[Tuple[Address, Feature]]
    threads: Dict[Address, ThreadFeatures]
    name: str


@dataclass
class NullDynamicFeatureExtractor(DynamicFeatureExtractor):
    base_address: Address
    sample_hashes: SampleHashes
    global_features: List[Feature]
    file_features: List[Tuple[Address, Feature]]
    processes: Dict[Address, ProcessFeatures]

    def extract_global_features(self):
        for feature in self.global_features:
            yield feature, NO_ADDRESS

    def get_sample_hashes(self) -> SampleHashes:
        return self.sample_hashes

    def extract_file_features(self):
        for address, feature in self.file_features:
            yield feature, address

    def get_processes(self):
        for address in sorted(self.processes.keys()):
            assert isinstance(address, ProcessAddress)
            yield ProcessHandle(address=address, inner={})

    def extract_process_features(self, ph):
        for addr, feature in self.processes[ph.address].features:
            yield feature, addr

    def get_process_name(self, ph) -> str:
        return self.processes[ph.address].name

    def get_threads(self, ph):
        for address in sorted(self.processes[ph.address].threads.keys()):
            assert isinstance(address, ThreadAddress)
            yield ThreadHandle(address=address, inner={})

    def extract_thread_features(self, ph, th):
        for addr, feature in self.processes[ph.address].threads[th.address].features:
            yield feature, addr

    def get_calls(self, ph, th):
        for address in sorted(self.processes[ph.address].threads[th.address].calls.keys()):
            assert isinstance(address, DynamicCallAddress)
            yield CallHandle(address=address, inner={})

    def extract_call_features(self, ph, th, ch):
        for address, feature in self.processes[ph.address].threads[th.address].calls[ch.address].features:
            yield feature, address

    def get_call_name(self, ph, th, ch) -> str:
        return self.processes[ph.address].threads[th.address].calls[ch.address].name


NullFeatureExtractor: TypeAlias = Union[NullStaticFeatureExtractor, NullDynamicFeatureExtractor]
