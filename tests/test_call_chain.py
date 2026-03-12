# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import textwrap

import capa.rules
import capa.capabilities.common
from capa.features.address import NO_ADDRESS, AbsoluteVirtualAddress
from capa.features.common import Characteristic
from capa.features.insn import API
from capa.features.extractors.base_extractor import (
    BBHandle,
    InsnHandle,
    SampleHashes,
    FunctionHandle,
    StaticFeatureExtractor,
)


class MockCallChainExtractor(StaticFeatureExtractor):
    def __init__(self):
        super().__init__(SampleHashes.from_bytes(b""))
        self.function_addresses = (
            AbsoluteVirtualAddress(0x1000),
            AbsoluteVirtualAddress(0x2000),
            AbsoluteVirtualAddress(0x3000),
            AbsoluteVirtualAddress(0x4000),
        )
        self.apis = {
            self.function_addresses[0]: ("CryptDecrypt",),
            self.function_addresses[1]: ("connect",),
            self.function_addresses[2]: ("CreateProcessA",),
            self.function_addresses[3]: ("CryptDecrypt",),
        }
        self.callees = {
            self.function_addresses[0]: (self.function_addresses[1],),
            self.function_addresses[1]: (self.function_addresses[2],),
            self.function_addresses[2]: (),
            self.function_addresses[3]: (),
        }

    def get_base_address(self):
        return NO_ADDRESS

    def extract_global_features(self):
        return iter(())

    def extract_file_features(self):
        return iter(())

    def get_functions(self):
        for address in self.function_addresses:
            yield FunctionHandle(address=address, inner=address)

    def extract_function_features(self, f):
        return iter(())

    def get_basic_blocks(self, f):
        yield BBHandle(address=f.address, inner=f.address)

    def extract_basic_block_features(self, f, bb):
        return iter(())

    def get_instructions(self, f, bb):
        yield InsnHandle(address=f.address, inner=f.address)

    def extract_insn_features(self, f, bb, insn):
        for api in self.apis[f.address]:
            yield API(api), insn.address

        for callee in self.callees[f.address]:
            yield Characteristic("calls from"), callee


def test_call_chain_matches_across_functions():
    ruleset = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                    rule:
                      meta:
                        name: call chain behavior
                        scopes:
                          static: function
                          dynamic: process
                      features:
                        - call-chain:
                          - api: CryptDecrypt
                          - api: connect
                          - api: CreateProcessA
                    """
                )
            )
        ]
    )

    capabilities = capa.capabilities.common.find_capabilities(ruleset, MockCallChainExtractor())
    assert "call chain behavior" in capabilities.matches

    match_addresses = {address for address, _ in capabilities.matches["call chain behavior"]}
    assert match_addresses == {AbsoluteVirtualAddress(0x1000)}
