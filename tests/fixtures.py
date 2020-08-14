# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import os.path
import collections

import pytest

import capa.features.file
import capa.features.insn
import capa.features.basicblock
from capa.features import ARCH_X32, ARCH_X64

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache


CD = os.path.dirname(__file__)


@lru_cache()
def extract_file_features(extractor):
    features = collections.defaultdict(set)
    for feature, va in extractor.extract_file_features():
        features[feature].add(va)
    return features


@lru_cache()
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


@lru_cache()
def extract_basic_block_features(extractor, f, bb):
    features = collections.defaultdict(set)
    for insn in extractor.get_instructions(f, bb):
        for feature, va in extractor.extract_insn_features(f, bb, insn):
            features[feature].add(va)
    for feature, va in extractor.extract_basic_block_features(f, bb):
        features[feature].add(va)
    return features


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
    elif request.param.startswith("a1982"):
        return os.path.join(CD, "data", "a198216798ca38f280dc413f8c57f2c2.exe_")
    elif request.param.startswith("39c05"):
        return os.path.join(CD, "data", "39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.dll_")
    elif request.param.startswith("c9188"):
        return os.path.join(CD, "data", "c91887d861d9bd4a5872249b641bc9f9.exe_")
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


FEATURE_PRESENCE_TESTS = [
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
    ("kernel32-64", "function=0x180001010", capa.features.insn.API("RtlVirtualUnwind"), True,),
    ("kernel32-64", "function=0x180001010", capa.features.insn.API("RtlVirtualUnwind"), True),
    # insn/api: x64 thunk
    ("kernel32-64", "function=0x1800202B0", capa.features.insn.API("RtlCaptureContext"), True,),
    ("kernel32-64", "function=0x1800202B0", capa.features.insn.API("RtlCaptureContext"), True),
    # insn/api: resolve indirect calls
    ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.CreatePipe"), True),
    ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.SetHandleInformation"), True),
    ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.CloseHandle"), True),
    ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.WriteFile"), True),
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
    ("mimikatz", "function=0x46D534", capa.features.Characteristic("nzxor"), False),
    # insn/characteristic(peb access)
    ("kernel32-64", "function=0x1800017D0", capa.features.Characteristic("peb access"), True),
    ("mimikatz", "function=0x4556E5", capa.features.Characteristic("peb access"), False),
    # insn/characteristic(gs access)
    ("kernel32-64", "function=0x180001068", capa.features.Characteristic("gs access"), True),
    ("mimikatz", "function=0x4556E5", capa.features.Characteristic("gs access"), False),
    # insn/characteristic(cross section flow)
    ("a1982...", "function=0x4014D0", capa.features.Characteristic("cross section flow"), True),
    # insn/characteristic(cross section flow): imports don't count
    ("kernel32-64", "function=0x180001068", capa.features.Characteristic("cross section flow"), False),
    ("mimikatz", "function=0x4556E5", capa.features.Characteristic("cross section flow"), False),
    # insn/characteristic(recursive call)
    ("39c05...", "function=0x10003100", capa.features.Characteristic("recursive call"), True),
    ("mimikatz", "function=0x4556E5", capa.features.Characteristic("recursive call"), False),
    # insn/characteristic(indirect call)
    ("mimikatz", "function=0x4175FF", capa.features.Characteristic("indirect call"), True),
    ("mimikatz", "function=0x4556E5", capa.features.Characteristic("indirect call"), False),
    # insn/characteristic(calls from)
    ("mimikatz", "function=0x4556E5", capa.features.Characteristic("calls from"), True),
    ("mimikatz", "function=0x4702FD", capa.features.Characteristic("calls from"), False),
    # function/characteristic(calls to)
    ("mimikatz", "function=0x40105D", capa.features.Characteristic("calls to"), True),
    ("mimikatz", "function=0x46C0D2", capa.features.Characteristic("calls to"), False),
]

FEATURE_COUNT_TESTS = [
    ("mimikatz", "function=0x40E51B", capa.features.basicblock.BasicBlock(), 1),
    ("mimikatz", "function=0x40E5C2", capa.features.basicblock.BasicBlock(), 7),
    ("mimikatz", "function=0x40E5C2", capa.features.Characteristic("calls from"), 3),
]


def do_test_feature_presence(get_extractor, sample, scope, feature, expected):
    extractor = get_extractor(sample)
    features = scope(extractor)
    if expected:
        msg = "%s should be found in %s" % (str(feature), scope.__name__)
    else:
        msg = "%s should not be found in %s" % (str(feature), scope.__name__)
    assert feature.evaluate(features) == expected, msg


def do_test_feature_count(get_extractor, sample, scope, feature, expected):
    extractor = get_extractor(sample)
    features = scope(extractor)
    msg = "%s should be found %d times in %s" % (str(feature), expected, scope.__name__)
    assert len(features[feature]) == expected, msg


Sample = collections.namedtuple("Sample", ["vw", "path"])


@pytest.fixture
def mimikatz():
    import viv_utils
    path = os.path.join(CD, "data", "mimikatz.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_a933a1a402775cfa94b6bee0963f4b46():
    import viv_utils
    path = os.path.join(CD, "data", "a933a1a402775cfa94b6bee0963f4b46.dll_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def kernel32():
    import viv_utils
    path = os.path.join(CD, "data", "kernel32.dll_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_a198216798ca38f280dc413f8c57f2c2():
    import viv_utils
    path = os.path.join(CD, "data", "a198216798ca38f280dc413f8c57f2c2.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_9324d1a8ae37a36ae560c37448c9705a():
    import viv_utils
    path = os.path.join(CD, "data", "9324d1a8ae37a36ae560c37448c9705a.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def pma_lab_12_04():
    import viv_utils
    path = os.path.join(CD, "data", "Practical Malware Analysis Lab 12-04.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_bfb9b5391a13d0afd787e87ab90f14f5():
    import viv_utils
    path = os.path.join(CD, "data", "bfb9b5391a13d0afd787e87ab90f14f5.dll_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_lab21_01():
    import viv_utils
    path = os.path.join(CD, "data", "Practical Malware Analysis Lab 21-01.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_c91887d861d9bd4a5872249b641bc9f9():
    import viv_utils
    path = os.path.join(CD, "data", "c91887d861d9bd4a5872249b641bc9f9.exe_")
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41():
    import viv_utils
    path = os.path.join(CD, "data", "39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.dll_",)
    return Sample(viv_utils.getWorkspace(path), path)


@pytest.fixture
def sample_499c2a85f6e8142c3f48d4251c9c7cd6_raw32():
    import viv_utils
    path = os.path.join(CD, "data", "499c2a85f6e8142c3f48d4251c9c7cd6.raw32")
    return Sample(viv_utils.getShellcodeWorkspace(path), path)


@pytest.fixture
def sample_al_khaser_x86():
    import viv_utils
    path = os.path.join(CD, "data", "al-khaser_x86.exe_")
    return Sample(viv_utils.getWorkspace(path), path)