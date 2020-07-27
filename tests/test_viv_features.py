# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import viv_utils
from fixtures import *

import capa.features
import capa.features.file
import capa.features.insn
import capa.features.basicblock
import capa.features.extractors.viv.file
import capa.features.extractors.viv.insn
import capa.features.extractors.viv.function
import capa.features.extractors.viv.basicblock


def extract_file_features(vw, path):
    features = set([])
    for feature, va in capa.features.extractors.viv.file.extract_features(vw, path):
        features.add(feature)
    return features


def extract_function_features(f):
    features = collections.defaultdict(set)
    for bb in f.basic_blocks:
        for insn in bb.instructions:
            for feature, va in capa.features.extractors.viv.insn.extract_features(f, bb, insn):
                features[feature].add(va)
        for feature, va in capa.features.extractors.viv.basicblock.extract_features(f, bb):
            features[feature].add(va)
    for feature, va in capa.features.extractors.viv.function.extract_features(f):
        features[feature].add(va)
    return features


def extract_basic_block_features(f, bb):
    features = set({})
    for insn in bb.instructions:
        for feature, _ in capa.features.extractors.viv.insn.extract_features(f, bb, insn):
            features.add(feature)
    for feature, _ in capa.features.extractors.viv.basicblock.extract_features(f, bb):
        features.add(feature)
    return features


def test_api_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x403BAC))
    assert capa.features.insn.API("advapi32.CryptAcquireContextW") in features
    assert capa.features.insn.API("advapi32.CryptAcquireContext") in features
    assert capa.features.insn.API("advapi32.CryptGenKey") in features
    assert capa.features.insn.API("advapi32.CryptImportKey") in features
    assert capa.features.insn.API("advapi32.CryptDestroyKey") in features
    assert capa.features.insn.API("CryptAcquireContextW") in features
    assert capa.features.insn.API("CryptAcquireContext") in features
    assert capa.features.insn.API("CryptGenKey") in features
    assert capa.features.insn.API("CryptImportKey") in features
    assert capa.features.insn.API("CryptDestroyKey") in features


def test_api_features_64_bit(sample_a198216798ca38f280dc413f8c57f2c2):
    features = extract_function_features(viv_utils.Function(sample_a198216798ca38f280dc413f8c57f2c2.vw, 0x4011B0))
    assert capa.features.insn.API("kernel32.GetStringTypeA") in features
    assert capa.features.insn.API("kernel32.GetStringTypeW") not in features
    assert capa.features.insn.API("kernel32.GetStringType") in features
    assert capa.features.insn.API("GetStringTypeA") in features
    assert capa.features.insn.API("GetStringType") in features
    # call via thunk in IDA Pro
    features = extract_function_features(viv_utils.Function(sample_a198216798ca38f280dc413f8c57f2c2.vw, 0x401CB0))
    assert capa.features.insn.API("msvcrt.vfprintf") in features
    assert capa.features.insn.API("vfprintf") in features


def test_string_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x40105D))
    assert capa.features.String("SCardControl") in features
    assert capa.features.String("SCardTransmit") in features
    assert capa.features.String("ACR  > ") in features
    # other strings not in this function
    assert capa.features.String("bcrypt.dll") not in features


def test_byte_features(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(viv_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.vw, 0x406F60))
    wanted = capa.features.Bytes(b"\xED\x24\x9E\xF4\x52\xA9\x07\x47\x55\x8E\xE1\xAB\x30\x8E\x23\x61")
    # use `==` rather than `is` because the result is not `True` but a truthy value.
    assert wanted.evaluate(features) == True


def test_byte_features64(sample_lab21_01):
    features = extract_function_features(viv_utils.Function(sample_lab21_01.vw, 0x1400010C0))
    wanted = capa.features.Bytes(b"\x32\xA2\xDF\x2D\x99\x2B\x00\x00")
    # use `==` rather than `is` because the result is not `True` but a truthy value.
    assert wanted.evaluate(features) == True


def test_number_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x40105D))
    assert capa.features.insn.Number(0xFF) in features
    assert capa.features.insn.Number(0x3136B0) in features
    # the following are stack adjustments
    assert capa.features.insn.Number(0xC) not in features
    assert capa.features.insn.Number(0x10) not in features


def test_offset_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x40105D))
    assert capa.features.insn.Offset(0x0) in features
    assert capa.features.insn.Offset(0x4) in features
    assert capa.features.insn.Offset(0xC) in features
    # the following are stack references
    assert capa.features.insn.Offset(0x8) not in features
    assert capa.features.insn.Offset(0x10) not in features

    # this function has the following negative offsets
    # movzx   ecx, byte ptr [eax-1]
    # movzx   eax, byte ptr [eax-2]
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x4011FB))
    assert capa.features.insn.Offset(-0x1) in features
    assert capa.features.insn.Offset(-0x2) in features


def test_nzxor_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x410DFC))
    assert capa.features.Characteristic("nzxor") in features  # 0x0410F0B


def get_bb_insn(f, va):
    """fetch the BasicBlock and Instruction instances for the given VA in the given function."""
    for bb in f.basic_blocks:
        for insn in bb.instructions:
            if insn.va == va:
                return (bb, insn)
    raise KeyError(va)


def test_is_security_cookie(mimikatz):
    # not a security cookie check
    f = viv_utils.Function(mimikatz.vw, 0x410DFC)
    for va in [0x0410F0B]:
        bb, insn = get_bb_insn(f, va)
        assert capa.features.extractors.viv.insn.is_security_cookie(f, bb, insn) == False

    # security cookie initial set and final check
    f = viv_utils.Function(mimikatz.vw, 0x46C54A)
    for va in [0x46C557, 0x46C63A]:
        bb, insn = get_bb_insn(f, va)
        assert capa.features.extractors.viv.insn.is_security_cookie(f, bb, insn) == True


def test_mnemonic_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x40105D))
    assert capa.features.insn.Mnemonic("push") in features
    assert capa.features.insn.Mnemonic("movzx") in features
    assert capa.features.insn.Mnemonic("xor") in features

    assert capa.features.insn.Mnemonic("in") not in features
    assert capa.features.insn.Mnemonic("out") not in features


def test_peb_access_features(sample_a933a1a402775cfa94b6bee0963f4b46):
    features = extract_function_features(viv_utils.Function(sample_a933a1a402775cfa94b6bee0963f4b46.vw, 0xABA6FEC))
    assert capa.features.Characteristic("peb access") in features


def test_file_section_name_features(mimikatz):
    features = extract_file_features(mimikatz.vw, mimikatz.path)
    assert capa.features.file.Section(".rsrc") in features
    assert capa.features.file.Section(".text") in features
    assert capa.features.file.Section(".nope") not in features


def test_tight_loop_features(mimikatz):
    f = viv_utils.Function(mimikatz.vw, 0x402EC4)
    for bb in f.basic_blocks:
        if bb.va != 0x402F8E:
            continue
        features = extract_basic_block_features(f, bb)
        assert capa.features.Characteristic("tight loop") in features
        assert capa.features.basicblock.BasicBlock() in features


def test_tight_loop_bb_features(mimikatz):
    f = viv_utils.Function(mimikatz.vw, 0x402EC4)
    for bb in f.basic_blocks:
        if bb.va != 0x402F8E:
            continue
        features = extract_basic_block_features(f, bb)
        assert capa.features.Characteristic("tight loop") in features
        assert capa.features.basicblock.BasicBlock() in features


def test_file_export_name_features(kernel32):
    features = extract_file_features(kernel32.vw, kernel32.path)
    assert capa.features.file.Export("BaseThreadInitThunk") in features
    assert capa.features.file.Export("lstrlenW") in features


def test_file_import_name_features(mimikatz):
    features = extract_file_features(mimikatz.vw, mimikatz.path)
    assert capa.features.file.Import("advapi32.CryptSetHashParam") in features
    assert capa.features.file.Import("CryptSetHashParam") in features
    assert capa.features.file.Import("kernel32.IsWow64Process") in features
    assert capa.features.file.Import("msvcrt.exit") in features
    assert capa.features.file.Import("cabinet.#11") in features
    assert capa.features.file.Import("#11") not in features


def test_cross_section_flow_features(sample_a198216798ca38f280dc413f8c57f2c2):
    features = extract_function_features(viv_utils.Function(sample_a198216798ca38f280dc413f8c57f2c2.vw, 0x4014D0))
    assert capa.features.Characteristic("cross section flow") in features

    # this function has calls to some imports,
    # which should not trigger cross-section flow characteristic
    features = extract_function_features(viv_utils.Function(sample_a198216798ca38f280dc413f8c57f2c2.vw, 0x401563))
    assert capa.features.Characteristic("cross section flow") not in features


def test_segment_access_features(sample_a933a1a402775cfa94b6bee0963f4b46):
    features = extract_function_features(viv_utils.Function(sample_a933a1a402775cfa94b6bee0963f4b46.vw, 0xABA6FEC))
    assert capa.features.Characteristic("fs access") in features


def test_thunk_features(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(viv_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.vw, 0x407970))
    assert capa.features.insn.API("kernel32.CreateToolhelp32Snapshot") in features
    assert capa.features.insn.API("CreateToolhelp32Snapshot") in features


def test_file_embedded_pe(pma_lab_12_04):
    features = extract_file_features(pma_lab_12_04.vw, pma_lab_12_04.path)
    assert capa.features.Characteristic("embedded pe") in features


def test_stackstring_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x4556E5))
    assert capa.features.Characteristic("stack string") in features


def test_switch_features(mimikatz):
    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x409411))
    assert capa.features.Characteristic("switch") in features

    features = extract_function_features(viv_utils.Function(mimikatz.vw, 0x409393))
    assert capa.features.Characteristic("switch") not in features


def test_recursive_call_feature(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41):
    features = extract_function_features(
        viv_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.vw, 0x10003100)
    )
    assert capa.features.Characteristic("recursive call") in features

    features = extract_function_features(
        viv_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.vw, 0x10007B00)
    )
    assert capa.features.Characteristic("recursive call") not in features


def test_loop_feature(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41):
    features = extract_function_features(
        viv_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.vw, 0x10003D30)
    )
    assert capa.features.Characteristic("loop") in features

    features = extract_function_features(
        viv_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.vw, 0x10007250)
    )
    assert capa.features.Characteristic("loop") not in features


def test_file_string_features(sample_bfb9b5391a13d0afd787e87ab90f14f5):
    features = extract_file_features(
        sample_bfb9b5391a13d0afd787e87ab90f14f5.vw, sample_bfb9b5391a13d0afd787e87ab90f14f5.path,
    )
    assert capa.features.String("WarStop") in features  # ASCII, offset 0x40EC
    assert capa.features.String("cimage/png") in features  # UTF-16 LE, offset 0x350E


def test_function_calls_to(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(viv_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.vw, 0x406F60))
    assert capa.features.Characteristic("calls to") in features
    assert len(features[capa.features.Characteristic("calls to")]) == 1


def test_function_calls_to64(sample_lab21_01):
    features = extract_function_features(viv_utils.Function(sample_lab21_01.vw, 0x1400052D0))  # memcpy
    assert capa.features.Characteristic("calls to") in features
    assert len(features[capa.features.Characteristic("calls to")]) == 8


def test_function_calls_from(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(viv_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.vw, 0x406F60))
    assert capa.features.Characteristic("calls from") in features
    assert len(features[capa.features.Characteristic("calls from")]) == 23


def test_basic_block_count(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(viv_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.vw, 0x406F60))
    assert len(features[capa.features.basicblock.BasicBlock()]) == 26


def test_indirect_call_features(sample_a933a1a402775cfa94b6bee0963f4b46):
    features = extract_function_features(viv_utils.Function(sample_a933a1a402775cfa94b6bee0963f4b46.vw, 0xABA68A0))
    assert capa.features.Characteristic("indirect call") in features
    assert len(features[capa.features.Characteristic("indirect call")]) == 3


def test_indirect_calls_resolved(sample_c91887d861d9bd4a5872249b641bc9f9):
    features = extract_function_features(viv_utils.Function(sample_c91887d861d9bd4a5872249b641bc9f9.vw, 0x401A77))
    assert capa.features.insn.API("kernel32.CreatePipe") in features
    assert capa.features.insn.API("kernel32.SetHandleInformation") in features
    assert capa.features.insn.API("kernel32.CloseHandle") in features
    assert capa.features.insn.API("kernel32.WriteFile") in features
