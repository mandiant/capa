# Copyright 2026 Google LLC
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

from capa.features.insn import API
from capa.features.address import AbsoluteVirtualAddress
from capa.capabilities.triage import (
    REASON_CRT_NAME,
    REASON_LARGE_COMPLEXITY,
    REASON_TINY_NO_API,
    TriageDecision,
    classify_function,
)
from capa.features.extractors.base_extractor import BBHandle, InsnHandle, FunctionHandle, SampleHashes, StaticFeatureExtractor


class FakeInsn:
    def __init__(self, mnem: str = "nop"):
        self.mnem = mnem


class FakeFunction:
    section_name = ".text"


class FakeTriageExtractor(StaticFeatureExtractor):
    def __init__(self, names=None, function_data=None):
        super().__init__(SampleHashes(md5="", sha1="", sha256=""))
        self.names = names or {}
        self.function_data = function_data or {}

    def get_base_address(self):
        return AbsoluteVirtualAddress(0x0)

    def extract_global_features(self):
        yield from ()

    def extract_file_features(self):
        yield from ()

    def get_functions(self):
        for fva in sorted(self.function_data):
            yield FunctionHandle(AbsoluteVirtualAddress(fva), FakeFunction())

    def get_function_name(self, addr):
        if int(addr) not in self.names:
            raise KeyError(addr)
        return self.names[int(addr)]

    def extract_function_features(self, f):
        yield from ()

    def get_basic_blocks(self, f):
        for bva in sorted(self.function_data[int(f.address)]["bbs"]):
            yield BBHandle(AbsoluteVirtualAddress(bva), None)

    def extract_basic_block_features(self, f, bb):
        yield from ()

    def get_instructions(self, f, bb):
        for iva, mnem in self.function_data[int(f.address)]["bbs"][int(bb.address)]:
            yield InsnHandle(AbsoluteVirtualAddress(iva), FakeInsn(mnem))

    def extract_insn_features(self, f, bb, insn):
        for feature in self.function_data[int(f.address)].get("insn_features", {}).get(int(insn.address), ()):
            yield feature, insn.address


def test_triage_classify_crt_name_skip():
    extractor = FakeTriageExtractor(
        names={0x401000: "__security_init_cookie"},
        function_data={0x401000: {"bbs": {0x401000: [(0x401000, "ret")]}}},
    )
    fh = FunctionHandle(AbsoluteVirtualAddress(0x401000), FakeFunction())

    result = classify_function(extractor, fh)
    assert result.decision == TriageDecision.SKIP
    assert result.reason == REASON_CRT_NAME


def test_triage_classify_tiny_no_api_skip():
    extractor = FakeTriageExtractor(
        names={0x402000: "sub_402000"},
        function_data={0x402000: {"bbs": {0x402000: [(0x402000, "nop"), (0x402001, "nop")]}}},
    )
    fh = FunctionHandle(AbsoluteVirtualAddress(0x402000), FakeFunction())

    result = classify_function(extractor, fh)
    assert result.decision == TriageDecision.SKIP
    assert result.reason == REASON_TINY_NO_API


def test_triage_classify_large_function_deprioritize():
    insns = [(0x500000 + i, "nop") for i in range(4096)]
    extractor = FakeTriageExtractor(
        names={0x500000: "sub_500000"},
        function_data={0x500000: {"bbs": {0x500000: insns}}},
    )
    fh = FunctionHandle(AbsoluteVirtualAddress(0x500000), FakeFunction())

    result = classify_function(extractor, fh)
    assert result.decision == TriageDecision.DEPRIORITIZE
    assert result.reason == REASON_LARGE_COMPLEXITY


def test_triage_api_presence_prevents_tiny_skip():
    extractor = FakeTriageExtractor(
        names={0x403000: "sub_403000"},
        function_data={
            0x403000: {
                "bbs": {0x403000: [(0x403000, "call"), (0x403001, "ret")]},
                "insn_features": {0x403000: [API("kernel32.CreateFileA")]},
            }
        },
    )
    fh = FunctionHandle(AbsoluteVirtualAddress(0x403000), FakeFunction())

    result = classify_function(extractor, fh)
    assert result.decision == TriageDecision.ANALYZE


def test_triage_api_feature_evidence_prevents_thunk_skip():
    extractor = FakeTriageExtractor(
        names={0x404000: "sub_404000"},
        function_data={
            0x404000: {
                "bbs": {0x404000: [(0x404000, "jmp")]},
                "insn_features": {0x404000: [API("kernel32.CreateFileA")]},
            }
        },
    )
    fh = FunctionHandle(AbsoluteVirtualAddress(0x404000), FakeFunction())

    result = classify_function(extractor, fh)
    assert result.decision == TriageDecision.ANALYZE
