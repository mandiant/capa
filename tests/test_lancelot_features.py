# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os.path
import collections

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

import pytest

import capa.features
import capa.features.file
import capa.features.insn
import capa.features.basicblock
import capa.features.extractors.lancelot.file
import capa.features.extractors.lancelot.insn
import capa.features.extractors.lancelot.function
import capa.features.extractors.lancelot.basicblock
from capa.features import ARCH_X32, ARCH_X64

CD = os.path.dirname(__file__)


@lru_cache
def extract_file_features(extractor):
    features = collections.defaultdict(set)
    for feature, va in extractor.extract_file_features():
        features[feature].add(va)
    return features


@lru_cache
def extract_function_features(extractor, f):
    features = collections.defaultdict(set)
    for bb in extractor.get_basic_blocks(f):
        for insn in extractor.get_instructions(f, bb):
            for feature, va in extractor.extract_insn_features(f, bb, insn):
                features[feature].add(va)
        for feature, va in extractor.extract_basic_block_features(f, bb):
            features[feature].add(va)
    for feature, va in extractor.extract_function_features(f):
        features[feature].add(va)
    return features


@lru_cache
def extract_basic_block_features(extractor, f, bb):
    features = collections.defaultdict(set)
    for insn in extractor.get_instructions(f, bb):
        for feature, va in extractor.extract_insn_features(f, bb, insn):
            features[feature].add(va)
    for feature, va in extractor.extract_basic_block_features(f, bb):
        features[feature].add(va)
    return features


@lru_cache
def get_lancelot_extractor(path):
    with open(path, "rb") as f:
        buf = f.read()

    return capa.features.extractors.lancelot.LancelotFeatureExtractor(buf)


@pytest.fixture
def sample(request):
    if request.param == "mimikatz":
        return os.path.join(CD, "data", "mimikatz.exe_")
    elif request.param == "kernel32":
        return os.path.join(CD, "data", "kernel32.dll_")
    elif request.param == "kernel32-64":
        return os.path.join(CD, "data", "kernel32-64.dll_")
    elif request.param == "pma12-04":
        return os.path.join(CD, "data", "Practical Malware Analysis Lab 12-04.exe_")
    else:
        raise ValueError("unexpected sample fixture")


def get_function(extractor, fva):
    for f in extractor.get_functions():
        if f.__int__() == fva:
            return f
    raise ValueError("function not found")


def get_basic_block(extractor, f, va):
    for bb in extractor.get_basic_blocks(f):
        if bb.__int__() == va:
            return bb
    raise ValueError("basic block not found")


@pytest.fixture
def scope(request):
    if request.param == "file":

        def inner(extractor):
            return extract_file_features(extractor)

        inner.__name__ = request.param
        return inner
    elif "bb=" in request.param:
        # like `function=0x401000,bb=0x40100A`
        fspec, _, bbspec = request.param.partition(",")
        fva = int(fspec.partition("=")[2], 0x10)
        bbva = int(bbspec.partition("=")[2], 0x10)

        def inner(extractor):
            f = get_function(extractor, fva)
            bb = get_basic_block(extractor, f, bbva)
            return extract_basic_block_features(extractor, f, bb)

        inner.__name__ = request.param
        return inner
    elif request.param.startswith("function"):
        # like `function=0x401000`
        va = int(request.param.partition("=")[2], 0x10)

        def inner(extractor):
            f = get_function(extractor, va)
            return extract_function_features(extractor, f)

        inner.__name__ = request.param
        return inner
    else:
        raise ValueError("unexpected scope fixture")


def parametrize(params, values, **kwargs):
    """
    extend `pytest.mark.parametrize` to pretty-print features.
    by default, it renders objects as an opaque value.
    ref: https://docs.pytest.org/en/2.9.0/example/parametrize.html#different-options-for-test-ids

    rendered ID might look something like:

        mimikatz-function=0x403BAC-api(CryptDestroyKey)-True
    """
    ids = ["-".join(map(str, vs)) for vs in values]
    return pytest.mark.parametrize(params, values, ids=ids, **kwargs)


@parametrize(
    "sample,scope,feature,expected",
    [
        # file/characteristic("embedded pe")
        ("pma12-04", "file", capa.features.Characteristic("embedded pe"), True),
        # file/string
        ("mimikatz", "file", capa.features.String("SCardControl"), True),
        ("mimikatz", "file", capa.features.String("SCardTransmit"), True),
        ("mimikatz", "file", capa.features.String("ACR  > "), True),
        ("mimikatz", "file", capa.features.String("nope"), False),
        # file/sections
        ("mimikatz", "file", capa.features.file.Section(".rsrc"), True),
        ("mimikatz", "file", capa.features.file.Section(".text"), True),
        ("mimikatz", "file", capa.features.file.Section(".nope"), False),
        # file/exports
        ("kernel32", "file", capa.features.file.Export("BaseThreadInitThunk"), True),
        ("kernel32", "file", capa.features.file.Export("lstrlenW"), True),
        ("kernel32", "file", capa.features.file.Export("nope"), False),
        # file/imports
        ("mimikatz", "file", capa.features.file.Import("advapi32.CryptSetHashParam"), True),
        ("mimikatz", "file", capa.features.file.Import("CryptSetHashParam"), True),
        ("mimikatz", "file", capa.features.file.Import("kernel32.IsWow64Process"), True),
        ("mimikatz", "file", capa.features.file.Import("msvcrt.exit"), True),
        ("mimikatz", "file", capa.features.file.Import("cabinet.#11"), True),
        ("mimikatz", "file", capa.features.file.Import("#11"), False),
        ("mimikatz", "file", capa.features.file.Import("#nope"), False),
        ("mimikatz", "file", capa.features.file.Import("nope"), False),
        # function/characteristic(loop)
        ("mimikatz", "function=0x401517", capa.features.Characteristic("loop"), True),
        ("mimikatz", "function=0x401000", capa.features.Characteristic("loop"), False),
        # function/characteristic(switch)
        pytest.param(
            "mimikatz",
            "function=0x409411",
            capa.features.Characteristic("switch"),
            True,
            marks=pytest.mark.xfail(reason="characteristic(switch) not implemented yet"),
        ),
        ("mimikatz", "function=0x401000", capa.features.Characteristic("switch"), False),
        # function/characteristic(calls to)
        pytest.param(
            "mimikatz",
            "function=0x401000",
            capa.features.Characteristic("calls to"),
            True,
            marks=pytest.mark.xfail(reason="characteristic(calls to) not implemented yet"),
        ),
        # bb/characteristic(tight loop)
        ("mimikatz", "function=0x402EC4", capa.features.Characteristic("tight loop"), True),
        ("mimikatz", "function=0x401000", capa.features.Characteristic("tight loop"), False),
        # bb/characteristic(stack string)
        ("mimikatz", "function=0x4556E5", capa.features.Characteristic("stack string"), True),
        ("mimikatz", "function=0x401000", capa.features.Characteristic("stack string"), False),
        # bb/characteristic(tight loop)
        ("mimikatz", "function=0x402EC4,bb=0x402F8E", capa.features.Characteristic("tight loop"), True),
        ("mimikatz", "function=0x401000,bb=0x401000", capa.features.Characteristic("tight loop"), False),
        # insn/mnemonic
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("push"), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("movzx"), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("xor"), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("in"), False),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("out"), False),
        # insn/number
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0xFF), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0x3136B0), True),
        # insn/number: stack adjustments
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0xC), False),
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0x10), False),
        # insn/number: arch flavors
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0xFF), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0xFF, arch=ARCH_X32), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0xFF, arch=ARCH_X64), False),
        # insn/offset
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x0), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x4), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0xC), True),
        # insn/offset: stack references
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x8), False),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x10), False),
        # insn/offset: negative
        ("mimikatz", "function=0x4011FB", capa.features.insn.Offset(-0x1), True),
        ("mimikatz", "function=0x4011FB", capa.features.insn.Offset(-0x2), True),
        # insn/offset: arch flavors
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x0), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x0, arch=ARCH_X32), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x0, arch=ARCH_X64), False),
        # insn/api
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptAcquireContextW"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptAcquireContext"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptGenKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptImportKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptDestroyKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptAcquireContextW"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptAcquireContext"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptGenKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptImportKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptDestroyKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("Nope"), False),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.Nope"), False),
        # insn/api: thunk
        ("mimikatz", "function=0x4556E5", capa.features.insn.API("advapi32.LsaQueryInformationPolicy"), True),
        ("mimikatz", "function=0x4556E5", capa.features.insn.API("LsaQueryInformationPolicy"), True),
        # insn/api: x64
        (
            "kernel32-64",
            "function=0x180001010",
            capa.features.insn.API("api-ms-win-core-rtlsupport-l1-1-0.RtlVirtualUnwind"),
            True,
        ),
        ("kernel32-64", "function=0x180001010", capa.features.insn.API("RtlVirtualUnwind"), True),
        # insn/api: x64 thunk
        (
            "kernel32-64",
            "function=0x1800202B0",
            capa.features.insn.API("api-ms-win-core-rtlsupport-l1-1-0.RtlCaptureContext"),
            True,
        ),
        ("kernel32-64", "function=0x1800202B0", capa.features.insn.API("RtlCaptureContext"), True),
        # insn/string
        ("mimikatz", "function=0x40105D", capa.features.String("SCardControl"), True),
        ("mimikatz", "function=0x40105D", capa.features.String("SCardTransmit"), True),
        ("mimikatz", "function=0x40105D", capa.features.String("ACR  > "), True),
        ("mimikatz", "function=0x40105D", capa.features.String("nope"), False),
        # insn/string, pointer to string
        ("mimikatz", "function=0x44EDEF", capa.features.String("INPUTEVENT"), True),
        # insn/bytes
        ("mimikatz", "function=0x40105D", capa.features.Bytes("SCardControl".encode("utf-16le")), True),
        ("mimikatz", "function=0x40105D", capa.features.Bytes("SCardTransmit".encode("utf-16le")), True),
        ("mimikatz", "function=0x40105D", capa.features.Bytes("ACR  > ".encode("utf-16le")), True),
        ("mimikatz", "function=0x40105D", capa.features.Bytes("nope".encode("ascii")), False),
        # insn/bytes, pointer to bytes
        ("mimikatz", "function=0x44EDEF", capa.features.Bytes("INPUTEVENT".encode("utf-16le")), True),
        # insn/characteristic(nzxor)
        ("mimikatz", "function=0x410DFC", capa.features.Characteristic("nzxor"), True),
        ("mimikatz", "function=0x40105D", capa.features.Characteristic("nzxor"), False),
        # insn/characteristic(nzxor): no security cookies
        ("mimikatz", "function=0x46B67A", capa.features.Characteristic("nzxor"), False),
        # insn/characteristic(peb access)
        ("kernel32-64", "function=0x180001068", capa.features.Characteristic("peb access"), True),
        ("mimikatz", "function=0x46B67A", capa.features.Characteristic("peb access"), False),
        # insn/characteristic(gs access)
        ("kernel32-64", "function=0x180001068", capa.features.Characteristic("gs access"), True),
        ("mimikatz", "function=0x46B67A", capa.features.Characteristic("gs access"), False),
    ],
    indirect=["sample", "scope"],
)
def test_lancelot_features(sample, scope, feature, expected):
    extractor = get_lancelot_extractor(sample)
    features = scope(extractor)
    if expected:
        msg = "%s should be found in %s" % (str(feature), scope.__name__)
    else:
        msg = "%s should not be found in %s" % (str(feature), scope.__name__)
    assert feature.evaluate(features) == expected, msg


"""
def test_tight_loop_features(mimikatz):
    f = lancelot_utils.Function(mimikatz.ws, 0x402EC4)
    for bb in f.basic_blocks:
        if bb.va != 0x402F8E:
            continue
        features = extract_basic_block_features(f, bb)
        assert capa.features.Characteristic("tight loop") in features
        assert capa.features.basicblock.BasicBlock() in features


def test_tight_loop_bb_features(mimikatz):
    f = lancelot_utils.Function(mimikatz.ws, 0x402EC4)
    for bb in f.basic_blocks:
        if bb.va != 0x402F8E:
            continue
        features = extract_basic_block_features(f, bb)
        assert capa.features.Characteristic("tight loop") in features
        assert capa.features.basicblock.BasicBlock() in features


def test_cross_section_flow_features(sample_a198216798ca38f280dc413f8c57f2c2):
    features = extract_function_features(lancelot_utils.Function(sample_a198216798ca38f280dc413f8c57f2c2.ws, 0x4014D0))
    assert capa.features.Characteristic("cross section flow") in features

    # this function has calls to some imports,
    # which should not trigger cross-section flow characteristic
    features = extract_function_features(lancelot_utils.Function(sample_a198216798ca38f280dc413f8c57f2c2.ws, 0x401563))
    assert capa.features.Characteristic("cross section flow") not in features


def test_segment_access_features(sample_a933a1a402775cfa94b6bee0963f4b46):
    features = extract_function_features(lancelot_utils.Function(sample_a933a1a402775cfa94b6bee0963f4b46.ws, 0xABA6FEC))
    assert capa.features.Characteristic("fs access") in features


def test_switch_features(mimikatz):
    features = extract_function_features(lancelot_utils.Function(mimikatz.ws, 0x409411))
    assert capa.features.Characteristic("switch") in features

    features = extract_function_features(lancelot_utils.Function(mimikatz.ws, 0x409393))
    assert capa.features.Characteristic("switch") not in features


def test_recursive_call_feature(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41):
    features = extract_function_features(
        lancelot_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.ws, 0x10003100)
    )
    assert capa.features.Characteristic("recursive call") in features

    features = extract_function_features(
        lancelot_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.ws, 0x10007B00)
    )
    assert capa.features.Characteristic("recursive call") not in features


def test_loop_feature(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41):
    features = extract_function_features(
        lancelot_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.ws, 0x10003D30)
    )
    assert capa.features.Characteristic("loop") in features

    features = extract_function_features(
        lancelot_utils.Function(sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.ws, 0x10007250)
    )
    assert capa.features.Characteristic("loop") not in features


def test_function_calls_to(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(lancelot_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.ws, 0x406F60))
    assert capa.features.Characteristic("calls to") in features
    assert len(features[capa.features.Characteristic("calls to")]) == 1


def test_function_calls_to64(sample_lab21_01):
    features = extract_function_features(lancelot_utils.Function(sample_lab21_01.ws, 0x1400052D0))  # memcpy
    assert capa.features.Characteristic("calls to") in features
    assert len(features[capa.features.Characteristic("calls to")]) == 8


def test_function_calls_from(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(lancelot_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.ws, 0x406F60))
    assert capa.features.Characteristic("calls from") in features
    assert len(features[capa.features.Characteristic("calls from")]) == 23


def test_basic_block_count(sample_9324d1a8ae37a36ae560c37448c9705a):
    features = extract_function_features(lancelot_utils.Function(sample_9324d1a8ae37a36ae560c37448c9705a.ws, 0x406F60))
    assert len(features[capa.features.basicblock.BasicBlock()]) == 26


def test_indirect_call_features(sample_a933a1a402775cfa94b6bee0963f4b46):
    features = extract_function_features(lancelot_utils.Function(sample_a933a1a402775cfa94b6bee0963f4b46.ws, 0xABA68A0))
    assert capa.features.Characteristic("indirect call") in features
    assert len(features[capa.features.Characteristic("indirect call")]) == 3


def test_indirect_calls_resolved(sample_c91887d861d9bd4a5872249b641bc9f9):
    features = extract_function_features(lancelot_utils.Function(sample_c91887d861d9bd4a5872249b641bc9f9.ws, 0x401A77))
    assert capa.features.insn.API("kernel32.CreatePipe") in features
    assert capa.features.insn.API("kernel32.SetHandleInformation") in features
    assert capa.features.insn.API("kernel32.CloseHandle") in features
    assert capa.features.insn.API("kernel32.WriteFile") in features
"""
