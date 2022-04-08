# -*- coding: utf-8 -*-
# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import os.path
import binascii
import itertools
import contextlib
import collections
from functools import lru_cache

import pytest

import capa.main
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock
from capa.features.common import (
    OS,
    OS_ANY,
    OS_LINUX,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    FORMAT_ELF,
    OS_WINDOWS,
    FORMAT_DOTNET,
    Arch,
    Format,
)

CD = os.path.dirname(__file__)
DOTNET_DIR = os.path.join(CD, "data", "dotnet")
DNFILE_TESTFILES = os.path.join(DOTNET_DIR, "dnfile-testfiles")


@contextlib.contextmanager
def xfail(condition, reason=None):
    """
    context manager that wraps a block that is expected to fail in some cases.
    when it does fail (and is expected), then mark this as pytest.xfail.
    if its unexpected, raise an exception, so the test fails.

    example::

        # this test:
        #  - passes on Linux if foo() works
        #  - fails  on Linux if foo() fails
        #  - xfails on Windows if foo() fails
        #  - fails  on Windows if foo() works
        with xfail(sys.platform == "win32", reason="doesn't work on Windows"):
            foo()
    """
    try:
        # do the block
        yield
    except:
        if condition:
            # we expected the test to fail, so raise and register this via pytest
            pytest.xfail(reason)
        else:
            # we don't expect an exception, so the test should fail
            raise
    else:
        if not condition:
            # here we expect the block to run successfully,
            # and we've received no exception,
            # so this is good
            pass
        else:
            # we expected an exception, but didn't find one. that's an error.
            raise RuntimeError("expected to fail, but didn't")


# need to limit cache size so GitHub Actions doesn't run out of memory, see #545
@lru_cache(maxsize=1)
def get_viv_extractor(path):
    import capa.main
    import capa.features.extractors.viv.extractor

    sigpaths = [
        os.path.join(CD, "data", "sigs", "test_aulldiv.pat"),
        os.path.join(CD, "data", "sigs", "test_aullrem.pat.gz"),
        os.path.join(CD, "..", "sigs", "1_flare_msvc_rtf_32_64.sig"),
        os.path.join(CD, "..", "sigs", "2_flare_msvc_atlmfc_32_64.sig"),
        os.path.join(CD, "..", "sigs", "3_flare_common_libs.sig"),
    ]

    if "raw32" in path:
        vw = capa.main.get_workspace(path, "sc32", sigpaths=sigpaths)
    elif "raw64" in path:
        vw = capa.main.get_workspace(path, "sc64", sigpaths=sigpaths)
    else:
        vw = capa.main.get_workspace(path, "auto", sigpaths=sigpaths)
    vw.saveWorkspace()
    extractor = capa.features.extractors.viv.extractor.VivisectFeatureExtractor(vw, path)
    fixup_viv(path, extractor)
    return extractor


def fixup_viv(path, extractor):
    """
    vivisect fixups to overcome differences between backends
    """
    if "3b13b" in path:
        # vivisect only recognizes calling thunk function at 0x10001573
        extractor.vw.makeFunction(0x10006860)


@lru_cache()
def get_smda_extractor(path):
    from smda.SmdaConfig import SmdaConfig
    from smda.Disassembler import Disassembler

    import capa.features.extractors.smda.extractor

    config = SmdaConfig()
    config.STORE_BUFFER = True
    disasm = Disassembler(config)
    report = disasm.disassembleFile(path)

    return capa.features.extractors.smda.extractor.SmdaFeatureExtractor(report, path)


@lru_cache(maxsize=1)
def get_pefile_extractor(path):
    import capa.features.extractors.pefile

    return capa.features.extractors.pefile.PefileFeatureExtractor(path)


def get_dotnetfile_extractor(path):
    import capa.features.extractors.dotnetfile

    return capa.features.extractors.dotnetfile.DotnetFileFeatureExtractor(path)


@lru_cache(maxsize=1)
def get_dnfile_extractor(path):
    import capa.features.extractors.dnfile.extractor

    return capa.features.extractors.dnfile.extractor.DnfileFeatureExtractor(path)


def extract_global_features(extractor):
    features = collections.defaultdict(set)
    for feature, va in extractor.extract_global_features():
        features[feature].add(va)
    return features


@lru_cache()
def extract_file_features(extractor):
    features = collections.defaultdict(set)
    for feature, va in extractor.extract_file_features():
        features[feature].add(va)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @lru_cache this
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


# f may not be hashable (e.g. ida func_t) so cannot @lru_cache this
def extract_basic_block_features(extractor, f, bb):
    features = collections.defaultdict(set)
    for insn in extractor.get_instructions(f, bb):
        for feature, va in extractor.extract_insn_features(f, bb, insn):
            features[feature].add(va)
    for feature, va in extractor.extract_basic_block_features(f, bb):
        features[feature].add(va)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @lru_cache this
def extract_instruction_features(extractor, f, bb, insn):
    features = collections.defaultdict(set)
    for feature, va in extractor.extract_insn_features(f, bb, insn):
        features[feature].add(va)
    return features


# note: too reduce the testing time it's recommended to reuse already existing test samples, if possible
def get_data_path_by_name(name):
    if name == "mimikatz":
        return os.path.join(CD, "data", "mimikatz.exe_")
    elif name == "kernel32":
        return os.path.join(CD, "data", "kernel32.dll_")
    elif name == "kernel32-64":
        return os.path.join(CD, "data", "kernel32-64.dll_")
    elif name == "pma01-01":
        return os.path.join(CD, "data", "Practical Malware Analysis Lab 01-01.dll_")
    elif name == "pma12-04":
        return os.path.join(CD, "data", "Practical Malware Analysis Lab 12-04.exe_")
    elif name == "pma16-01":
        return os.path.join(CD, "data", "Practical Malware Analysis Lab 16-01.exe_")
    elif name == "pma21-01":
        return os.path.join(CD, "data", "Practical Malware Analysis Lab 21-01.exe_")
    elif name == "al-khaser x86":
        return os.path.join(CD, "data", "al-khaser_x86.exe_")
    elif name == "al-khaser x64":
        return os.path.join(CD, "data", "al-khaser_x64.exe_")
    elif name.startswith("39c05"):
        return os.path.join(CD, "data", "39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.dll_")
    elif name.startswith("499c2"):
        return os.path.join(CD, "data", "499c2a85f6e8142c3f48d4251c9c7cd6.raw32")
    elif name.startswith("9324d"):
        return os.path.join(CD, "data", "9324d1a8ae37a36ae560c37448c9705a.exe_")
    elif name.startswith("a1982"):
        return os.path.join(CD, "data", "a198216798ca38f280dc413f8c57f2c2.exe_")
    elif name.startswith("a933a"):
        return os.path.join(CD, "data", "a933a1a402775cfa94b6bee0963f4b46.dll_")
    elif name.startswith("bfb9b"):
        return os.path.join(CD, "data", "bfb9b5391a13d0afd787e87ab90f14f5.dll_")
    elif name.startswith("c9188"):
        return os.path.join(CD, "data", "c91887d861d9bd4a5872249b641bc9f9.exe_")
    elif name.startswith("64d9f"):
        return os.path.join(CD, "data", "64d9f7d96b99467f36e22fada623c3bb.dll_")
    elif name.startswith("82bf6"):
        return os.path.join(CD, "data", "82BF6347ACF15E5D883715DC289D8A2B.exe_")
    elif name.startswith("pingtaest"):
        return os.path.join(CD, "data", "ping_täst.exe_")
    elif name.startswith("77329"):
        return os.path.join(CD, "data", "773290480d5445f11d3dc1b800728966.exe_")
    elif name.startswith("3b13b"):
        return os.path.join(CD, "data", "3b13b6f1d7cd14dc4a097a12e2e505c0a4cff495262261e2bfc991df238b9b04.dll_")
    elif name == "7351f.elf":
        return os.path.join(CD, "data", "7351f8a40c5450557b24622417fc478d.elf_")
    elif name.startswith("79abd"):
        return os.path.join(CD, "data", "79abd17391adc6251ecdc58d13d76baf.dll_")
    elif name.startswith("946a9"):
        return os.path.join(CD, "data", "946a99f36a46d335dec080d9a4371940.dll_")
    elif name.startswith("b9f5b"):
        return os.path.join(CD, "data", "b9f5bd514485fb06da39beff051b9fdc.exe_")
    elif name.startswith("mixed-mode-64"):
        return os.path.join(DNFILE_TESTFILES, "mixed-mode", "ModuleCode", "bin", "ModuleCode_amd64.exe")
    elif name.startswith("hello-world"):
        return os.path.join(DNFILE_TESTFILES, "hello-world", "hello-world.exe")
    elif name.startswith("_1c444"):
        return os.path.join(CD, "data", "dotnet", "1c444ebeba24dcba8628b7dfe5fec7c6.exe_")
    else:
        raise ValueError("unexpected sample fixture: %s" % name)


def get_sample_md5_by_name(name):
    """used by IDA tests to ensure the correct IDB is loaded"""
    if name == "mimikatz":
        return "5f66b82558ca92e54e77f216ef4c066c"
    elif name == "kernel32":
        return "e80758cf485db142fca1ee03a34ead05"
    elif name == "kernel32-64":
        return "a8565440629ac87f6fef7d588fe3ff0f"
    elif name == "pma12-04":
        return "56bed8249e7c2982a90e54e1e55391a2"
    elif name == "pma16-01":
        return "7faafc7e4a5c736ebfee6abbbc812d80"
    elif name == "pma01-01":
        return "290934c61de9176ad682ffdd65f0a669"
    elif name == "pma21-01":
        return "c8403fb05244e23a7931c766409b5e22"
    elif name == "al-khaser x86":
        return "db648cd247281954344f1d810c6fd590"
    elif name == "al-khaser x64":
        return "3cb21ae76ff3da4b7e02d77ff76e82be"
    elif name.startswith("39c05"):
        return "b7841b9d5dc1f511a93cc7576672ec0c"
    elif name.startswith("499c2"):
        return "499c2a85f6e8142c3f48d4251c9c7cd6"
    elif name.startswith("9324d"):
        return "9324d1a8ae37a36ae560c37448c9705a"
    elif name.startswith("a1982"):
        return "a198216798ca38f280dc413f8c57f2c2"
    elif name.startswith("a933a"):
        return "a933a1a402775cfa94b6bee0963f4b46"
    elif name.startswith("bfb9b"):
        return "bfb9b5391a13d0afd787e87ab90f14f5"
    elif name.startswith("c9188"):
        return "c91887d861d9bd4a5872249b641bc9f9"
    elif name.startswith("64d9f"):
        return "64d9f7d96b99467f36e22fada623c3bb"
    elif name.startswith("82bf6"):
        return "82bf6347acf15e5d883715dc289d8a2b"
    elif name.startswith("77329"):
        return "773290480d5445f11d3dc1b800728966"
    elif name.startswith("3b13b"):
        # file name is SHA256 hash
        return "56a6ffe6a02941028cc8235204eef31d"
    elif name == "7351f.elf":
        return "7351f8a40c5450557b24622417fc478d"
    elif name.startswith("79abd"):
        return "79abd17391adc6251ecdc58d13d76baf"
    elif name.startswith("946a9"):
        return "946a99f36a46d335dec080d9a4371940"
    elif name.startswith("b9f5b"):
        return "b9f5bd514485fb06da39beff051b9fdc"
    else:
        raise ValueError("unexpected sample fixture: %s" % name)


def resolve_sample(sample):
    return get_data_path_by_name(sample)


@pytest.fixture
def sample(request):
    return resolve_sample(request.param)


def get_function(extractor, fva):
    for f in extractor.get_functions():
        if int(f) == fva:
            return f
    raise ValueError("function not found")


def get_basic_block(extractor, f, va):
    for bb in extractor.get_basic_blocks(f):
        if int(bb) == va:
            return bb
    raise ValueError("basic block not found")


def get_instruction(extractor, f, bb, va):
    for insn in extractor.get_instructions(f, bb):
        if int(insn) == va:
            return insn
    raise ValueError("instruction not found")


def resolve_scope(scope):
    if scope == "file":

        def inner_file(extractor):
            features = extract_file_features(extractor)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_file.__name__ = scope
        return inner_file
    elif "insn=" in scope:
        # like `function=0x401000,bb=0x40100A,insn=0x40100A`
        assert "function=" in scope
        assert "bb=" in scope
        assert "insn=" in scope
        fspec, _, spec = scope.partition(",")
        bbspec, _, ispec = spec.partition(",")
        fva = int(fspec.partition("=")[2], 0x10)
        bbva = int(bbspec.partition("=")[2], 0x10)
        iva = int(ispec.partition("=")[2], 0x10)

        def inner_insn(extractor):
            f = get_function(extractor, fva)
            bb = get_basic_block(extractor, f, bbva)
            insn = get_instruction(extractor, f, bb, iva)
            features = extract_instruction_features(extractor, f, bb, insn)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_insn.__name__ = scope
        return inner_insn
    elif "bb=" in scope:
        # like `function=0x401000,bb=0x40100A`
        assert "function=" in scope
        assert "bb=" in scope
        fspec, _, bbspec = scope.partition(",")
        fva = int(fspec.partition("=")[2], 0x10)
        bbva = int(bbspec.partition("=")[2], 0x10)

        def inner_bb(extractor):
            f = get_function(extractor, fva)
            bb = get_basic_block(extractor, f, bbva)
            features = extract_basic_block_features(extractor, f, bb)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_bb.__name__ = scope
        return inner_bb
    elif scope.startswith("function"):
        # like `function=0x401000`
        va = int(scope.partition("=")[2], 0x10)

        def inner_function(extractor):
            f = get_function(extractor, va)
            features = extract_function_features(extractor, f)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_function.__name__ = scope
        return inner_function
    else:
        raise ValueError("unexpected scope fixture")


@pytest.fixture
def scope(request):
    return resolve_scope(request.param)


def make_test_id(values):
    return "-".join(map(str, values))


def parametrize(params, values, **kwargs):
    """
    extend `pytest.mark.parametrize` to pretty-print features.
    by default, it renders objects as an opaque value.
    ref: https://docs.pytest.org/en/2.9.0/example/parametrize.html#different-options-for-test-ids
    rendered ID might look something like:
        mimikatz-function=0x403BAC-api(CryptDestroyKey)-True
    """
    ids = list(map(make_test_id, values))
    return pytest.mark.parametrize(params, values, ids=ids, **kwargs)


FEATURE_PRESENCE_TESTS = sorted(
    [
        # file/characteristic("embedded pe")
        ("pma12-04", "file", capa.features.common.Characteristic("embedded pe"), True),
        # file/string
        ("mimikatz", "file", capa.features.common.String("SCardControl"), True),
        ("mimikatz", "file", capa.features.common.String("SCardTransmit"), True),
        ("mimikatz", "file", capa.features.common.String("ACR  > "), True),
        ("mimikatz", "file", capa.features.common.String("nope"), False),
        # file/sections
        ("mimikatz", "file", capa.features.file.Section(".text"), True),
        ("mimikatz", "file", capa.features.file.Section(".nope"), False),
        # IDA doesn't extract unmapped sections by default
        # ("mimikatz", "file", capa.features.file.Section(".rsrc"), True),
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
        ("mimikatz", "file", capa.features.file.Import("advapi32.CryptAcquireContextW"), True),
        ("mimikatz", "file", capa.features.file.Import("advapi32.CryptAcquireContext"), True),
        ("mimikatz", "file", capa.features.file.Import("CryptAcquireContextW"), True),
        ("mimikatz", "file", capa.features.file.Import("CryptAcquireContext"), True),
        # function/characteristic(loop)
        ("mimikatz", "function=0x401517", capa.features.common.Characteristic("loop"), True),
        ("mimikatz", "function=0x401000", capa.features.common.Characteristic("loop"), False),
        # bb/characteristic(tight loop)
        ("mimikatz", "function=0x402EC4", capa.features.common.Characteristic("tight loop"), True),
        ("mimikatz", "function=0x401000", capa.features.common.Characteristic("tight loop"), False),
        # bb/characteristic(stack string)
        ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("stack string"), True),
        ("mimikatz", "function=0x401000", capa.features.common.Characteristic("stack string"), False),
        # bb/characteristic(tight loop)
        ("mimikatz", "function=0x402EC4,bb=0x402F8E", capa.features.common.Characteristic("tight loop"), True),
        ("mimikatz", "function=0x401000,bb=0x401000", capa.features.common.Characteristic("tight loop"), False),
        # insn/mnemonic
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("push"), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("movzx"), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("xor"), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("in"), False),
        ("mimikatz", "function=0x40105D", capa.features.insn.Mnemonic("out"), False),
        # insn/operand.number
        ("mimikatz", "function=0x40105D,bb=0x401073", capa.features.insn.OperandNumber(1, 0xFF), True),
        ("mimikatz", "function=0x40105D,bb=0x401073", capa.features.insn.OperandNumber(0, 0xFF), False),
        # insn/operand.offset
        ("mimikatz", "function=0x40105D,bb=0x4010B0", capa.features.insn.OperandOffset(0, 4), True),
        ("mimikatz", "function=0x40105D,bb=0x4010B0", capa.features.insn.OperandOffset(1, 4), False),
        # insn/number
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0xFF), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0x3136B0), True),
        ("mimikatz", "function=0x401000", capa.features.insn.Number(0x0), True),
        # insn/number: stack adjustments
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0xC), False),
        ("mimikatz", "function=0x40105D", capa.features.insn.Number(0x10), False),
        # insn/number: negative
        ("mimikatz", "function=0x401553", capa.features.insn.Number(0xFFFFFFFF), True),
        ("mimikatz", "function=0x43e543", capa.features.insn.Number(0xFFFFFFF0), True),
        # insn/offset
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x0), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x4), True),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0xC), True),
        # insn/offset, issue #276
        ("64d9f", "function=0x10001510,bb=0x100015B0", capa.features.insn.Offset(0x4000), True),
        # insn/offset: stack references
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x8), False),
        ("mimikatz", "function=0x40105D", capa.features.insn.Offset(0x10), False),
        # insn/offset: negative
        ("mimikatz", "function=0x4011FB", capa.features.insn.Offset(-0x1), True),
        ("mimikatz", "function=0x4011FB", capa.features.insn.Offset(-0x2), True),
        #
        # insn/offset from mnemonic: add
        #
        # should not be considered, too big for an offset:
        #    .text:00401D85 81 C1 00 00 00 80       add     ecx, 80000000h
        ("mimikatz", "function=0x401D64,bb=0x401D73,insn=0x401D85", capa.features.insn.Offset(0x80000000), False),
        # should not be considered, relative to stack:
        #    .text:00401CF6 83 C4 10                add     esp, 10h
        ("mimikatz", "function=0x401CC7,bb=0x401CDE,insn=0x401CF6", capa.features.insn.Offset(0x10), False),
        # yes, this is also a offset (imagine eax is a pointer):
        #    .text:0040223C 83 C0 04                add     eax, 4
        ("mimikatz", "function=0x402203,bb=0x402221,insn=0x40223C", capa.features.insn.Offset(0x4), True),
        #
        # insn/number from mnemonic: lea
        #
        # should not be considered, lea operand invalid encoding
        #    .text:00471EE6 8D 1C 81                lea     ebx, [ecx+eax*4]
        ("mimikatz", "function=0x471EAB,bb=0x471ED8,insn=0x471EE6", capa.features.insn.Number(0x4), False),
        # should not be considered, lea operand invalid encoding
        #    .text:004717B1 8D 4C 31 D0             lea     ecx, [ecx+esi-30h]
        ("mimikatz", "function=0x47153B,bb=0x4717AB,insn=0x4717B1", capa.features.insn.Number(-0x30), False),
        # yes, this is also a number (imagine edx is zero):
        #    .text:004018C0 8D 4B 02                lea     ecx, [ebx+2]
        ("mimikatz", "function=0x401873,bb=0x4018B2,insn=0x4018C0", capa.features.insn.Number(0x2), True),
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
            capa.features.insn.API("RtlVirtualUnwind"),
            True,
        ),
        ("kernel32-64", "function=0x180001010", capa.features.insn.API("RtlVirtualUnwind"), True),
        # insn/api: x64 thunk
        (
            "kernel32-64",
            "function=0x1800202B0",
            capa.features.insn.API("RtlCaptureContext"),
            True,
        ),
        ("kernel32-64", "function=0x1800202B0", capa.features.insn.API("RtlCaptureContext"), True),
        # insn/api: x64 nested thunk
        ("al-khaser x64", "function=0x14004B4F0", capa.features.insn.API("__vcrt_GetModuleHandle"), True),
        # insn/api: call via jmp
        ("mimikatz", "function=0x40B3C6", capa.features.insn.API("LocalFree"), True),
        ("c91887...", "function=0x40156F", capa.features.insn.API("CloseClipboard"), True),
        # TODO ignore thunk functions that call via jmp?
        # insn/api: resolve indirect calls
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.CreatePipe"), True),
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.SetHandleInformation"), True),
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.CloseHandle"), True),
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.WriteFile"), True),
        # insn/string
        ("mimikatz", "function=0x40105D", capa.features.common.String("SCardControl"), True),
        ("mimikatz", "function=0x40105D", capa.features.common.String("SCardTransmit"), True),
        ("mimikatz", "function=0x40105D", capa.features.common.String("ACR  > "), True),
        ("mimikatz", "function=0x40105D", capa.features.common.String("nope"), False),
        ("773290...", "function=0x140001140", capa.features.common.String(r"%s:\\OfficePackagesForWDAG"), True),
        # insn/regex
        ("pma16-01", "function=0x4021B0", capa.features.common.Regex("HTTP/1.0"), True),
        ("pma16-01", "function=0x402F40", capa.features.common.Regex("www.practicalmalwareanalysis.com"), True),
        ("pma16-01", "function=0x402F40", capa.features.common.Substring("practicalmalwareanalysis.com"), True),
        # insn/string, pointer to string
        ("mimikatz", "function=0x44EDEF", capa.features.common.String("INPUTEVENT"), True),
        # insn/string, direct memory reference
        ("mimikatz", "function=0x46D6CE", capa.features.common.String("(null)"), True),
        # insn/bytes
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("SCardControl".encode("utf-16le")), True),
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("SCardTransmit".encode("utf-16le")), True),
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("ACR  > ".encode("utf-16le")), True),
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("nope".encode("ascii")), False),
        # IDA features included byte sequences read from invalid memory, fixed in #409
        ("mimikatz", "function=0x44570F", capa.features.common.Bytes(binascii.unhexlify("FF" * 256)), False),
        # insn/bytes, pointer to bytes
        ("mimikatz", "function=0x44EDEF", capa.features.common.Bytes("INPUTEVENT".encode("utf-16le")), True),
        # insn/characteristic(nzxor)
        ("mimikatz", "function=0x410DFC", capa.features.common.Characteristic("nzxor"), True),
        ("mimikatz", "function=0x40105D", capa.features.common.Characteristic("nzxor"), False),
        # insn/characteristic(nzxor): no security cookies
        ("mimikatz", "function=0x46D534", capa.features.common.Characteristic("nzxor"), False),
        # insn/characteristic(nzxor): xorps
        # viv needs fixup to recognize function, see above
        ("3b13b...", "function=0x10006860", capa.features.common.Characteristic("nzxor"), True),
        # insn/characteristic(peb access)
        ("kernel32-64", "function=0x1800017D0", capa.features.common.Characteristic("peb access"), True),
        ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("peb access"), False),
        # insn/characteristic(gs access)
        ("kernel32-64", "function=0x180001068", capa.features.common.Characteristic("gs access"), True),
        ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("gs access"), False),
        # insn/characteristic(cross section flow)
        ("a1982...", "function=0x4014D0", capa.features.common.Characteristic("cross section flow"), True),
        # insn/characteristic(cross section flow): imports don't count
        ("kernel32-64", "function=0x180001068", capa.features.common.Characteristic("cross section flow"), False),
        ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("cross section flow"), False),
        # insn/characteristic(recursive call)
        ("mimikatz", "function=0x40640e", capa.features.common.Characteristic("recursive call"), True),
        # before this we used ambiguous (0x4556E5, False), which has a data reference / indirect recursive call, see #386
        ("mimikatz", "function=0x4175FF", capa.features.common.Characteristic("recursive call"), False),
        # insn/characteristic(indirect call)
        ("mimikatz", "function=0x4175FF", capa.features.common.Characteristic("indirect call"), True),
        ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("indirect call"), False),
        # insn/characteristic(calls from)
        ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("calls from"), True),
        ("mimikatz", "function=0x4702FD", capa.features.common.Characteristic("calls from"), False),
        # function/characteristic(calls to)
        ("mimikatz", "function=0x40105D", capa.features.common.Characteristic("calls to"), True),
        # before this we used ambiguous (0x4556E5, False), which has a data reference / indirect recursive call, see #386
        ("mimikatz", "function=0x456BB9", capa.features.common.Characteristic("calls to"), False),
        # file/function-name
        ("pma16-01", "file", capa.features.file.FunctionName("__aulldiv"), True),
        # os & format & arch
        ("pma16-01", "file", OS(OS_WINDOWS), True),
        ("pma16-01", "file", OS(OS_LINUX), False),
        ("pma16-01", "function=0x404356", OS(OS_WINDOWS), True),
        ("pma16-01", "function=0x404356,bb=0x4043B9", OS(OS_WINDOWS), True),
        ("pma16-01", "file", Arch(ARCH_I386), True),
        ("pma16-01", "file", Arch(ARCH_AMD64), False),
        ("pma16-01", "function=0x404356", Arch(ARCH_I386), True),
        ("pma16-01", "function=0x404356,bb=0x4043B9", Arch(ARCH_I386), True),
        ("pma16-01", "file", Format(FORMAT_PE), True),
        ("pma16-01", "file", Format(FORMAT_ELF), False),
        # elf support
        ("7351f.elf", "file", OS(OS_LINUX), True),
        ("7351f.elf", "file", OS(OS_WINDOWS), False),
        ("7351f.elf", "file", Format(FORMAT_ELF), True),
        ("7351f.elf", "file", Format(FORMAT_PE), False),
        ("7351f.elf", "file", Arch(ARCH_I386), False),
        ("7351f.elf", "file", Arch(ARCH_AMD64), True),
        ("7351f.elf", "function=0x408753", capa.features.common.String("/dev/null"), True),
        ("7351f.elf", "function=0x408753,bb=0x408781", capa.features.insn.API("open"), True),
        ("79abd...", "function=0x10002385,bb=0x10002385", capa.features.common.Characteristic("call $+5"), True),
        ("946a9...", "function=0x10001510,bb=0x100015c0", capa.features.common.Characteristic("call $+5"), True),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)

FEATURE_PRESENCE_TESTS_DOTNET = sorted(
    [
        ("b9f5b", "file", Arch(ARCH_I386), True),
        ("b9f5b", "file", Arch(ARCH_AMD64), False),
        ("mixed-mode-64", "file", Arch(ARCH_AMD64), True),
        ("mixed-mode-64", "file", Arch(ARCH_I386), False),
        ("b9f5b", "file", OS(OS_ANY), True),
        ("b9f5b", "file", Format(FORMAT_DOTNET), True),
        ("hello-world", "function=0x250", capa.features.common.String("Hello World!"), True),
        ("hello-world", "function=0x250, bb=0x250, insn=0x252", capa.features.common.String("Hello World!"), True),
        ("hello-world", "function=0x250", capa.features.insn.API("System.Console::WriteLine"), True),
        ("hello-world", "file", capa.features.file.Import("System.Console::WriteLine"), True),
        ("_1c444", "file", capa.features.file.Import("gdi32.CreateCompatibleBitmap"), True),
        ("_1c444", "file", capa.features.file.Import("CreateCompatibleBitmap"), True),
        ("_1c444", "file", capa.features.file.Import("gdi32::CreateCompatibleBitmap"), False),
        ("_1c444", "function=0x1F68", capa.features.insn.API("GetWindowDC"), True),
        ("_1c444", "function=0x1F68", capa.features.insn.API("user32.GetWindowDC"), True),
        ("_1c444", "function=0x1F68", capa.features.insn.Number(0xCC0020), True),
        ("_1c444", "function=0x1F68", capa.features.insn.Number(0x0), True),
        ("_1c444", "function=0x1F68", capa.features.insn.Number(0x1), False),
        (
            "_1c444",
            "function=0x1F68, bb=0x1F68, insn=0x1FF9",
            capa.features.insn.API("System.Drawing.Image::FromHbitmap"),
            True,
        ),
        ("_1c444", "function=0x1F68, bb=0x1F68, insn=0x1FF9", capa.features.insn.API("FromHbitmap"), False),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)

FEATURE_PRESENCE_TESTS_IDA = [
    # file/imports
    # IDA can recover more names of APIs imported by ordinal
    ("mimikatz", "file", capa.features.file.Import("cabinet.FCIAddFile"), True),
]

FEATURE_COUNT_TESTS = [
    ("mimikatz", "function=0x40E5C2", capa.features.basicblock.BasicBlock(), 7),
    ("mimikatz", "function=0x4702FD", capa.features.common.Characteristic("calls from"), 0),
    ("mimikatz", "function=0x40E5C2", capa.features.common.Characteristic("calls from"), 3),
    ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("calls to"), 0),
    ("mimikatz", "function=0x40B1F1", capa.features.common.Characteristic("calls to"), 3),
]


FEATURE_COUNT_TESTS_DOTNET = []  # type: ignore


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
    msg = "%s should be found %d times in %s, found: %d" % (
        str(feature),
        expected,
        scope.__name__,
        len(features[feature]),
    )
    assert len(features[feature]) == expected, msg


def get_extractor(path):
    extractor = get_viv_extractor(path)
    # overload the extractor so that the fixture exposes `extractor.path`
    setattr(extractor, "path", path)
    return extractor


@pytest.fixture
def mimikatz_extractor():
    return get_extractor(get_data_path_by_name("mimikatz"))


@pytest.fixture
def a933a_extractor():
    return get_extractor(get_data_path_by_name("a933a..."))


@pytest.fixture
def kernel32_extractor():
    return get_extractor(get_data_path_by_name("kernel32"))


@pytest.fixture
def a1982_extractor():
    return get_extractor(get_data_path_by_name("a1982..."))


@pytest.fixture
def z9324d_extractor():
    return get_extractor(get_data_path_by_name("9324d..."))


@pytest.fixture
def pma12_04_extractor():
    return get_extractor(get_data_path_by_name("pma12-04"))


@pytest.fixture
def pma16_01_extractor():
    return get_extractor(get_data_path_by_name("pma16-01"))


@pytest.fixture
def bfb9b_extractor():
    return get_extractor(get_data_path_by_name("bfb9b..."))


@pytest.fixture
def pma21_01_extractor():
    return get_extractor(get_data_path_by_name("pma21-01"))


@pytest.fixture
def c9188_extractor():
    return get_extractor(get_data_path_by_name("c9188..."))


@pytest.fixture
def z39c05_extractor():
    return get_extractor(get_data_path_by_name("39c05..."))


@pytest.fixture
def z499c2_extractor():
    return get_extractor(get_data_path_by_name("499c2..."))


@pytest.fixture
def al_khaser_x86_extractor():
    return get_extractor(get_data_path_by_name("al-khaser x86"))


@pytest.fixture
def pingtaest_extractor():
    return get_extractor(get_data_path_by_name("pingtaest"))


@pytest.fixture
def b9f5b_dotnetfile_extractor():
    return get_dotnetfile_extractor(get_data_path_by_name("b9f5b"))


@pytest.fixture
def mixed_mode_64_dotnetfile_extractor():
    return get_dotnetfile_extractor(get_data_path_by_name("mixed-mode-64"))


@pytest.fixture
def hello_world_dnfile_extractor():
    return get_dnfile_extractor(get_data_path_by_name("hello-world"))


@pytest.fixture
def _1c444_dnfile_extractor():
    return get_dnfile_extractor(get_data_path_by_name("1c444..."))
