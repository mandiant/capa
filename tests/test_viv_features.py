# Copyright 2020 Google LLC
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
import fixtures


@fixtures.parametrize_backend_feature_fixtures(
    fixtures.BackendFeaturePolicy(
        name="viv",
        include_tags={"static"},
        exclude_tags={"dotnet", "ghidra"},
    )
)
def test_viv_features(feature_fixture):
    extractor = fixtures.get_viv_extractor(feature_fixture.sample_path)
    fixtures.run_feature_fixture(extractor, feature_fixture)


def test_viv_segment_access_features():
    import envi.archs.i386.disasm as d32
    import envi.archs.amd64.disasm as d64

    from capa.features.common import Characteristic
    from capa.features.address import AbsoluteVirtualAddress
    from capa.features.extractors.viv.insn import extract_insn_segment_access_features
    from capa.features.extractors.base_extractor import InsnHandle

    # Single prefix: fs: mov eax, dword [0x30]
    dis32 = d32.i386Disasm()
    op_fs = dis32.disasm(bytes.fromhex("64 8b 05 30 00 00 00"), 0, 0x401000)
    features = list(
        extract_insn_segment_access_features(None, None, InsnHandle(AbsoluteVirtualAddress(0x401000), op_fs))
    )
    assert (Characteristic("fs access"), AbsoluteVirtualAddress(0x401000)) in features

    # Multi-prefix: lock fs: add dword [0x30], eax (0xF0 0x64 0x01 ...)
    op_lock_fs = dis32.disasm(bytes.fromhex("f0 64 01 05 30 00 00 00"), 0, 0x401000)
    features = list(
        extract_insn_segment_access_features(None, None, InsnHandle(AbsoluteVirtualAddress(0x401000), op_lock_fs))
    )
    assert (Characteristic("fs access"), AbsoluteVirtualAddress(0x401000)) in features

    # Single prefix: gs: mov rax, qword [0x60]
    dis64 = d64.Amd64Disasm()
    op_gs = dis64.disasm(bytes.fromhex("65 48 8b 04 25 60 00 00 00"), 0, 0x401000)
    features = list(
        extract_insn_segment_access_features(None, None, InsnHandle(AbsoluteVirtualAddress(0x401000), op_gs))
    )
    assert (Characteristic("gs access"), AbsoluteVirtualAddress(0x401000)) in features

    # Multi-prefix: lock gs: add qword [0x60], rax (0xF0 0x65 ...)
    op_lock_gs = dis64.disasm(bytes.fromhex("f0 65 48 01 04 25 60 00 00 00"), 0, 0x401000)
    features = list(
        extract_insn_segment_access_features(None, None, InsnHandle(AbsoluteVirtualAddress(0x401000), op_lock_gs))
    )
    assert (Characteristic("gs access"), AbsoluteVirtualAddress(0x401000)) in features
