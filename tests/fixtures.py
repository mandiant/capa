# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import binascii
import contextlib
import collections
from typing import Set, Dict
from pathlib import Path
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
    OS_AUTO,
    OS_LINUX,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    FORMAT_ELF,
    OS_WINDOWS,
    FORMAT_AUTO,
    FORMAT_DOTNET,
    Arch,
    Format,
    Feature,
    FeatureAccess,
)
from capa.features.address import Address
from capa.features.extractors.base_extractor import (
    BBHandle,
    CallHandle,
    InsnHandle,
    ThreadHandle,
    ProcessHandle,
    FunctionHandle,
)
from capa.features.extractors.dnfile.extractor import DnfileFeatureExtractor

CD = Path(__file__).resolve().parent
DOTNET_DIR = CD / "data" / "dotnet"
DNFILE_TESTFILES = DOTNET_DIR / "dnfile-testfiles"


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
    except Exception:
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
def get_viv_extractor(path: Path):
    import capa.main
    import capa.features.extractors.viv.extractor

    sigpaths = [
        CD / "data" / "sigs" / "test_aulldiv.pat",
        CD / "data" / "sigs" / "test_aullrem.pat.gz",
        CD.parent / "sigs" / "1_flare_msvc_rtf_32_64.sig",
        CD.parent / "sigs" / "2_flare_msvc_atlmfc_32_64.sig",
        CD.parent / "sigs" / "3_flare_common_libs.sig",
    ]

    if "raw32" in path.name:
        vw = capa.loader.get_workspace(path, "sc32", sigpaths=sigpaths)
    elif "raw64" in path.name:
        vw = capa.loader.get_workspace(path, "sc64", sigpaths=sigpaths)
    else:
        vw = capa.loader.get_workspace(path, FORMAT_AUTO, sigpaths=sigpaths)
    vw.saveWorkspace()
    extractor = capa.features.extractors.viv.extractor.VivisectFeatureExtractor(vw, path, OS_AUTO)
    fixup_viv(path, extractor)
    return extractor


def fixup_viv(path: Path, extractor):
    """
    vivisect fixups to overcome differences between backends
    """
    if "3b13b" in path.name:
        # vivisect only recognizes calling thunk function at 0x10001573
        extractor.vw.makeFunction(0x10006860)
    if "294b8d" in path.name:
        # see vivisect/#561
        extractor.vw.makeFunction(0x404970)


@lru_cache(maxsize=1)
def get_pefile_extractor(path: Path):
    import capa.features.extractors.pefile

    extractor = capa.features.extractors.pefile.PefileFeatureExtractor(path)

    # overload the extractor so that the fixture exposes `extractor.path`
    setattr(extractor, "path", path.as_posix())

    return extractor


@lru_cache(maxsize=1)
def get_dnfile_extractor(path: Path):
    import capa.features.extractors.dnfile.extractor

    extractor = capa.features.extractors.dnfile.extractor.DnfileFeatureExtractor(path)

    # overload the extractor so that the fixture exposes `extractor.path`
    setattr(extractor, "path", path.as_posix())

    return extractor


@lru_cache(maxsize=1)
def get_dotnetfile_extractor(path: Path):
    import capa.features.extractors.dotnetfile

    extractor = capa.features.extractors.dotnetfile.DotnetFileFeatureExtractor(path)

    # overload the extractor so that the fixture exposes `extractor.path`
    setattr(extractor, "path", path.as_posix())

    return extractor


@lru_cache(maxsize=1)
def get_binja_extractor(path: Path):
    import binaryninja
    from binaryninja import Settings

    import capa.features.extractors.binja.extractor

    # Workaround for a BN bug: https://github.com/Vector35/binaryninja-api/issues/4051
    settings = Settings()
    if path.name.endswith("kernel32-64.dll_"):
        old_pdb = settings.get_bool("pdb.loadGlobalSymbols")
        settings.set_bool("pdb.loadGlobalSymbols", False)
    bv = binaryninja.load(str(path))
    if path.name.endswith("kernel32-64.dll_"):
        settings.set_bool("pdb.loadGlobalSymbols", old_pdb)

    extractor = capa.features.extractors.binja.extractor.BinjaFeatureExtractor(bv)

    # overload the extractor so that the fixture exposes `extractor.path`
    setattr(extractor, "path", path.as_posix())

    return extractor


@lru_cache(maxsize=1)
def get_cape_extractor(path):
    from capa.helpers import load_json_from_path
    from capa.features.extractors.cape.extractor import CapeExtractor

    report = load_json_from_path(path)

    return CapeExtractor.from_report(report)


@lru_cache(maxsize=1)
def get_drakvuf_extractor(path):
    from capa.helpers import load_jsonl_from_path
    from capa.features.extractors.drakvuf.extractor import DrakvufExtractor

    report = load_jsonl_from_path(path)

    return DrakvufExtractor.from_report(report)


@lru_cache(maxsize=1)
def get_vmray_extractor(path):
    from capa.features.extractors.vmray.extractor import VMRayExtractor

    return VMRayExtractor.from_zipfile(path)


@lru_cache(maxsize=1)
def get_ghidra_extractor(path: Path):
    import capa.features.extractors.ghidra.extractor

    extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()
    setattr(extractor, "path", path.as_posix())

    return extractor


@lru_cache(maxsize=1)
def get_binexport_extractor(path):
    import capa.features.extractors.binexport2
    import capa.features.extractors.binexport2.extractor

    be2 = capa.features.extractors.binexport2.get_binexport2(path)
    search_paths = [CD / "data", CD / "data" / "aarch64"]
    path = capa.features.extractors.binexport2.get_sample_from_binexport2(path, be2, search_paths)
    buf = path.read_bytes()

    return capa.features.extractors.binexport2.extractor.BinExport2FeatureExtractor(be2, buf)


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


def extract_process_features(extractor, ph):
    features = collections.defaultdict(set)
    for th in extractor.get_threads(ph):
        for ch in extractor.get_calls(ph, th):
            for feature, va in extractor.extract_call_features(ph, th, ch):
                features[feature].add(va)
        for feature, va in extractor.extract_thread_features(ph, th):
            features[feature].add(va)
    for feature, va in extractor.extract_process_features(ph):
        features[feature].add(va)
    return features


def extract_thread_features(extractor, ph, th):
    features = collections.defaultdict(set)
    for ch in extractor.get_calls(ph, th):
        for feature, va in extractor.extract_call_features(ph, th, ch):
            features[feature].add(va)
    for feature, va in extractor.extract_thread_features(ph, th):
        features[feature].add(va)
    return features


def extract_call_features(extractor, ph, th, ch):
    features = collections.defaultdict(set)
    for feature, addr in extractor.extract_call_features(ph, th, ch):
        features[feature].add(addr)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @lru_cache this
def extract_function_features(extractor, fh):
    features = collections.defaultdict(set)
    for bb in extractor.get_basic_blocks(fh):
        for insn in extractor.get_instructions(fh, bb):
            for feature, va in extractor.extract_insn_features(fh, bb, insn):
                features[feature].add(va)
        for feature, va in extractor.extract_basic_block_features(fh, bb):
            features[feature].add(va)
    for feature, va in extractor.extract_function_features(fh):
        features[feature].add(va)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @lru_cache this
def extract_basic_block_features(extractor, fh, bbh):
    features = collections.defaultdict(set)
    for insn in extractor.get_instructions(fh, bbh):
        for feature, va in extractor.extract_insn_features(fh, bbh, insn):
            features[feature].add(va)
    for feature, va in extractor.extract_basic_block_features(fh, bbh):
        features[feature].add(va)
    return features


# f may not be hashable (e.g. ida func_t) so cannot @lru_cache this
def extract_instruction_features(extractor, fh, bbh, ih) -> Dict[Feature, Set[Address]]:
    features = collections.defaultdict(set)
    for feature, addr in extractor.extract_insn_features(fh, bbh, ih):
        features[feature].add(addr)
    return features


# note: to reduce the testing time it's recommended to reuse already existing test samples, if possible
def get_data_path_by_name(name) -> Path:
    if name == "mimikatz":
        return CD / "data" / "mimikatz.exe_"
    elif name == "kernel32":
        return CD / "data" / "kernel32.dll_"
    elif name == "kernel32-64":
        return CD / "data" / "kernel32-64.dll_"
    elif name == "pma01-01":
        return CD / "data" / "Practical Malware Analysis Lab 01-01.dll_"
    elif name == "pma01-01-rd":
        return CD / "data" / "rd" / "Practical Malware Analysis Lab 01-01.dll_.json"
    elif name == "pma12-04":
        return CD / "data" / "Practical Malware Analysis Lab 12-04.exe_"
    elif name == "pma16-01":
        return CD / "data" / "Practical Malware Analysis Lab 16-01.exe_"
    elif name == "pma21-01":
        return CD / "data" / "Practical Malware Analysis Lab 21-01.exe_"
    elif name == "al-khaser x86":
        return CD / "data" / "al-khaser_x86.exe_"
    elif name == "al-khaser x64":
        return CD / "data" / "al-khaser_x64.exe_"
    elif name.startswith("39c05"):
        return CD / "data" / "39c05b15e9834ac93f206bc114d0a00c357c888db567ba8f5345da0529cbed41.dll_"
    elif name.startswith("499c2"):
        return CD / "data" / "499c2a85f6e8142c3f48d4251c9c7cd6.raw32"
    elif name.startswith("9324d"):
        return CD / "data" / "9324d1a8ae37a36ae560c37448c9705a.exe_"
    elif name.startswith("395eb"):
        return CD / "data" / "395eb0ddd99d2c9e37b6d0b73485ee9c.exe_"
    elif name.startswith("a1982"):
        return CD / "data" / "a198216798ca38f280dc413f8c57f2c2.exe_"
    elif name.startswith("a933a"):
        return CD / "data" / "a933a1a402775cfa94b6bee0963f4b46.dll_"
    elif name.startswith("bfb9b"):
        return CD / "data" / "bfb9b5391a13d0afd787e87ab90f14f5.dll_"
    elif name.startswith("c9188"):
        return CD / "data" / "c91887d861d9bd4a5872249b641bc9f9.exe_"
    elif name.startswith("64d9f"):
        return CD / "data" / "64d9f7d96b99467f36e22fada623c3bb.dll_"
    elif name.startswith("82bf6"):
        return CD / "data" / "82BF6347ACF15E5D883715DC289D8A2B.exe_"
    elif name.startswith("pingtaest"):
        return CD / "data" / "ping_täst.exe_"
    elif name.startswith("77329"):
        return CD / "data" / "773290480d5445f11d3dc1b800728966.exe_"
    elif name.startswith("3b13b"):
        return CD / "data" / "3b13b6f1d7cd14dc4a097a12e2e505c0a4cff495262261e2bfc991df238b9b04.dll_"
    elif name == "7351f.elf":
        return CD / "data" / "7351f8a40c5450557b24622417fc478d.elf_"
    elif name.startswith("79abd"):
        return CD / "data" / "79abd17391adc6251ecdc58d13d76baf.dll_"
    elif name.startswith("946a9"):
        return CD / "data" / "946a99f36a46d335dec080d9a4371940.dll_"
    elif name.startswith("2f7f5f"):
        return CD / "data" / "2f7f5fb5de175e770d7eae87666f9831.elf_"
    elif name.startswith("b9f5b"):
        return CD / "data" / "b9f5bd514485fb06da39beff051b9fdc.exe_"
    elif name.startswith("mixed-mode-64"):
        return DNFILE_TESTFILES / "mixed-mode" / "ModuleCode" / "bin" / "ModuleCode_amd64.exe"
    elif name.startswith("hello-world"):
        return DNFILE_TESTFILES / "hello-world" / "hello-world.exe"
    elif name.startswith("_1c444"):
        return DOTNET_DIR / "1c444ebeba24dcba8628b7dfe5fec7c6.exe_"
    elif name.startswith("_387f15"):
        return DOTNET_DIR / "387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173.dll_"
    elif name.startswith("_692f"):
        return DOTNET_DIR / "692f7fd6d198e804d6af98eb9e390d61.exe_"
    elif name.startswith("_0953c"):
        return CD / "data" / "0953cc3b77ed2974b09e3a00708f88de931d681e2d0cb64afbaf714610beabe6.exe_"
    elif name.startswith("_039a6"):
        return CD / "data" / "039a6336d0802a2255669e6867a5679c7eb83313dbc61fb1c7232147379bd304.exe_"
    elif name.startswith("b5f052"):
        return CD / "data" / "b5f0524e69b3a3cf636c7ac366ca57bf5e3a8fdc8a9f01caf196c611a7918a87.elf_"
    elif name.startswith("bf7a9c"):
        return CD / "data" / "bf7a9c8bdfa6d47e01ad2b056264acc3fd90cf43fe0ed8deec93ab46b47d76cb.elf_"
    elif name.startswith("294b8d"):
        return CD / "data" / "294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc.elf_"
    elif name.startswith("2bf18d"):
        return CD / "data" / "2bf18d0403677378adad9001b1243211.elf_"
    elif name.startswith("0000a657"):
        return (
            CD
            / "data"
            / "dynamic"
            / "cape"
            / "v2.2"
            / "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz"
        )
    elif name.startswith("d46900"):
        return (
            CD
            / "data"
            / "dynamic"
            / "cape"
            / "v2.2"
            / "d46900384c78863420fb3e297d0a2f743cd2b6b3f7f82bf64059a168e07aceb7.json.gz"
        )
    elif name.startswith("93b2d1-drakvuf"):
        return (
            CD
            / "data"
            / "dynamic"
            / "drakvuf"
            / "93b2d1840566f45fab674ebc79a9d19c88993bcb645e0357f3cb584d16e7c795.log.gz"
        )
    elif name.startswith("93b2d1-vmray"):
        return (
            CD
            / "data"
            / "dynamic"
            / "vmray"
            / "93b2d1840566f45fab674ebc79a9d19c88993bcb645e0357f3cb584d16e7c795_min_archive.zip"
        )
    elif name.startswith("ea2876"):
        return CD / "data" / "ea2876e9175410b6f6719f80ee44b9553960758c7d0f7bed73c0fe9a78d8e669.dll_"
    elif name.startswith("1038a2"):
        return CD / "data" / "1038a23daad86042c66bfe6c9d052d27048de9653bde5750dc0f240c792d9ac8.elf_"
    elif name.startswith("3da7c"):
        return CD / "data" / "3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_"
    elif name.startswith("nested_typedef"):
        return CD / "data" / "dotnet" / "dd9098ff91717f4906afe9dafdfa2f52.exe_"
    elif name.startswith("nested_typeref"):
        return CD / "data" / "dotnet" / "2c7d60f77812607dec5085973ff76cea.dll_"
    elif name.startswith("687e79.ghidra.be2"):
        return (
            CD
            / "data"
            / "binexport2"
            / "687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_.ghidra.BinExport"
        )
    elif name.startswith("d1e650.ghidra.be2"):
        return (
            CD
            / "data"
            / "binexport2"
            / "d1e6506964edbfffb08c0dd32e1486b11fbced7a4bd870ffe79f110298f0efb8.elf_.ghidra.BinExport"
        )
    else:
        raise ValueError(f"unexpected sample fixture: {name}")


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
    elif name.startswith("7351f"):
        return "7351f8a40c5450557b24622417fc478d"
    elif name.startswith("79abd"):
        return "79abd17391adc6251ecdc58d13d76baf"
    elif name.startswith("946a9"):
        return "946a99f36a46d335dec080d9a4371940"
    elif name.startswith("b9f5b"):
        return "b9f5bd514485fb06da39beff051b9fdc"
    elif name.startswith("294b8d"):
        # file name is SHA256 hash
        return "3db3e55b16a7b1b1afb970d5e77c5d98"
    elif name.startswith("2bf18d"):
        return "2bf18d0403677378adad9001b1243211"
    elif name.startswith("ea2876"):
        return "76fa734236daa023444dec26863401dc"
    else:
        raise ValueError(f"unexpected sample fixture: {name}")


def resolve_sample(sample):
    return get_data_path_by_name(sample)


@pytest.fixture
def sample(request):
    return resolve_sample(request.param)


def get_process(extractor, ppid: int, pid: int) -> ProcessHandle:
    for ph in extractor.get_processes():
        if ph.address.ppid == ppid and ph.address.pid == pid:
            return ph
    raise ValueError("process not found")


def get_thread(extractor, ph: ProcessHandle, tid: int) -> ThreadHandle:
    for th in extractor.get_threads(ph):
        if th.address.tid == tid:
            return th
    raise ValueError("thread not found")


def get_call(extractor, ph: ProcessHandle, th: ThreadHandle, cid: int) -> CallHandle:
    for ch in extractor.get_calls(ph, th):
        if ch.address.id == cid:
            return ch
    raise ValueError("call not found")


def get_function(extractor, fva: int) -> FunctionHandle:
    for fh in extractor.get_functions():
        if isinstance(extractor, DnfileFeatureExtractor):
            addr = fh.inner.offset
        else:
            addr = fh.address
        if addr == fva:
            return fh
    raise ValueError("function not found")


def get_function_by_token(extractor, token: int) -> FunctionHandle:
    for fh in extractor.get_functions():
        if fh.address == token:
            return fh
    raise ValueError("function not found by token")


def get_basic_block(extractor, fh: FunctionHandle, va: int) -> BBHandle:
    for bbh in extractor.get_basic_blocks(fh):
        if isinstance(extractor, DnfileFeatureExtractor):
            addr = bbh.inner.offset
        else:
            addr = bbh.address
        if addr == va:
            return bbh
    raise ValueError("basic block not found")


def get_instruction(extractor, fh: FunctionHandle, bbh: BBHandle, va: int) -> InsnHandle:
    for ih in extractor.get_instructions(fh, bbh):
        if isinstance(extractor, DnfileFeatureExtractor):
            addr = ih.inner.offset
        else:
            addr = ih.address
        if addr == va:
            return ih
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
            fh = get_function(extractor, fva)
            bbh = get_basic_block(extractor, fh, bbva)
            ih = get_instruction(extractor, fh, bbh, iva)
            features = extract_instruction_features(extractor, fh, bbh, ih)
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
            fh = get_function(extractor, fva)
            bbh = get_basic_block(extractor, fh, bbva)
            features = extract_basic_block_features(extractor, fh, bbh)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_bb.__name__ = scope
        return inner_bb
    elif scope.startswith(("function", "token")):
        # like `function=0x401000` or `token=0x6000001`
        va = int(scope.partition("=")[2], 0x10)

        def inner_function(extractor):
            if scope.startswith("token"):
                fh = get_function_by_token(extractor, va)
            else:
                fh = get_function(extractor, va)
            features = extract_function_features(extractor, fh)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_function.__name__ = scope
        return inner_function
    elif "call=" in scope:
        # like `process=(pid:ppid),thread=tid,call=id`
        assert "process=" in scope
        assert "thread=" in scope
        pspec, _, spec = scope.partition(",")
        tspec, _, cspec = spec.partition(",")
        pspec = pspec.partition("=")[2][1:-1].split(":")
        assert len(pspec) == 2
        pid, ppid = map(int, pspec)
        tid = int(tspec.partition("=")[2])
        cid = int(cspec.partition("=")[2])

        def inner_call(extractor):
            ph = get_process(extractor, ppid, pid)
            th = get_thread(extractor, ph, tid)
            ch = get_call(extractor, ph, th, cid)
            features = extract_call_features(extractor, ph, th, ch)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_call.__name__ = scope
        return inner_call
    elif "thread=" in scope:
        # like `process=(pid:ppid),thread=tid`
        assert "process=" in scope
        pspec, _, tspec = scope.partition(",")
        pspec = pspec.partition("=")[2][1:-1].split(":")
        assert len(pspec) == 2
        pid, ppid = map(int, pspec)
        tid = int(tspec.partition("=")[2])

        def inner_thread(extractor):
            ph = get_process(extractor, ppid, pid)
            th = get_thread(extractor, ph, tid)
            features = extract_thread_features(extractor, ph, th)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_thread.__name__ = scope
        return inner_thread
    elif "process=" in scope:
        # like `process=(pid:ppid)`
        pspec = scope.partition("=")[2][1:-1].split(":")
        assert len(pspec) == 2
        pid, ppid = map(int, pspec)

        def inner_process(extractor):
            ph = get_process(extractor, ppid, pid)
            features = extract_process_features(extractor, ph)
            for k, vs in extract_global_features(extractor).items():
                features[k].update(vs)
            return features

        inner_process.__name__ = scope
        return inner_process
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
        # forwarded export
        ("ea2876", "file", capa.features.file.Export("vresion.GetFileVersionInfoA"), True),
        # file/imports
        ("mimikatz", "file", capa.features.file.Import("advapi32.CryptSetHashParam"), True),
        ("mimikatz", "file", capa.features.file.Import("CryptSetHashParam"), True),
        ("mimikatz", "file", capa.features.file.Import("kernel32.IsWow64Process"), True),
        ("mimikatz", "file", capa.features.file.Import("IsWow64Process"), True),
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
        # 0x4012b4  MOVZX       ECX, [EAX+0xFFFFFFFFFFFFFFFF]
        ("mimikatz", "function=0x4011FB", capa.features.insn.Offset(-0x1), True),
        # 0x4012b8  MOVZX       EAX, [EAX+0xFFFFFFFFFFFFFFFE]
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
        # yes, this is also a number (imagine ebx is zero):
        #    .text:004018C0 8D 4B 02                lea     ecx, [ebx+2]
        ("mimikatz", "function=0x401873,bb=0x4018B2,insn=0x4018C0", capa.features.insn.Number(0x2), True),
        # insn/api
        # not extracting dll anymore
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptAcquireContextW"), False),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptAcquireContext"), False),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptGenKey"), False),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptImportKey"), False),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.CryptDestroyKey"), False),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptAcquireContextW"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptAcquireContext"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptGenKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptImportKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("CryptDestroyKey"), True),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("Nope"), False),
        ("mimikatz", "function=0x403BAC", capa.features.insn.API("advapi32.Nope"), False),
        # insn/api: thunk
        # not extracting dll anymore
        ("mimikatz", "function=0x4556E5", capa.features.insn.API("advapi32.LsaQueryInformationPolicy"), False),
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
        # insn/api: resolve indirect calls
        # not extracting dll anymore
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.CreatePipe"), False),
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.SetHandleInformation"), False),
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.CloseHandle"), False),
        ("c91887...", "function=0x401A77", capa.features.insn.API("kernel32.WriteFile"), False),
        ("c91887...", "function=0x401A77", capa.features.insn.API("CreatePipe"), True),
        ("c91887...", "function=0x401A77", capa.features.insn.API("SetHandleInformation"), True),
        ("c91887...", "function=0x401A77", capa.features.insn.API("CloseHandle"), True),
        ("c91887...", "function=0x401A77", capa.features.insn.API("WriteFile"), True),
        # insn/string
        ("mimikatz", "function=0x40105D", capa.features.common.String("SCardControl"), True),
        ("mimikatz", "function=0x40105D", capa.features.common.String("SCardTransmit"), True),
        ("mimikatz", "function=0x40105D", capa.features.common.String("ACR  > "), True),
        ("mimikatz", "function=0x40105D", capa.features.common.String("nope"), False),
        ("773290...", "function=0x140001140", capa.features.common.String(r"%s:\\OfficePackagesForWDAG"), True),
        # overlapping string, see #1271
        ("294b8d...", "function=0x404970,bb=0x404970,insn=0x40499F", capa.features.common.String("\r\n\x00:ht"), False),
        # insn/regex
        ("pma16-01", "function=0x4021B0", capa.features.common.Regex("HTTP/1.0"), True),
        ("pma16-01", "function=0x402F40", capa.features.common.Regex("www.practicalmalwareanalysis.com"), True),
        ("pma16-01", "function=0x402F40", capa.features.common.Substring("practicalmalwareanalysis.com"), True),
        # insn/string, pointer to string
        ("mimikatz", "function=0x44EDEF", capa.features.common.String("INPUTEVENT"), True),
        # insn/string, direct memory reference
        ("mimikatz", "function=0x46D6CE", capa.features.common.String("(null)"), True),
        # insn/bytes
        ("mimikatz", "function=0x401517", capa.features.common.Bytes(binascii.unhexlify("CA3B0E000000F8AF47")), True),
        ("mimikatz", "function=0x404414", capa.features.common.Bytes(binascii.unhexlify("0180000040EA4700")), True),
        # don't extract byte features for obvious strings
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("SCardControl".encode("utf-16le")), False),
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("SCardTransmit".encode("utf-16le")), False),
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("ACR  > ".encode("utf-16le")), False),
        ("mimikatz", "function=0x40105D", capa.features.common.Bytes("nope".encode("ascii")), False),
        # push    offset aAcsAcr1220 ; "ACS..." -> where ACS == 41 00 43 00 == valid pointer to middle of instruction
        ("mimikatz", "function=0x401000", capa.features.common.Bytes(binascii.unhexlify("FDFF59F647")), False),
        # IDA features included byte sequences read from invalid memory, fixed in #409
        ("mimikatz", "function=0x44570F", capa.features.common.Bytes(binascii.unhexlify("FF" * 256)), False),
        # insn/bytes, pointer to string bytes
        ("mimikatz", "function=0x44EDEF", capa.features.common.Bytes("INPUTEVENT".encode("utf-16le")), False),
        # insn/characteristic(nzxor)
        ("mimikatz", "function=0x410DFC", capa.features.common.Characteristic("nzxor"), True),
        ("mimikatz", "function=0x40105D", capa.features.common.Characteristic("nzxor"), False),
        # insn/characteristic(nzxor): no security cookies
        ("mimikatz", "function=0x46D534", capa.features.common.Characteristic("nzxor"), False),
        # insn/characteristic(nzxor): xorps
        # viv needs fixup to recognize function, see above
        ("mimikatz", "function=0x410dfc", capa.features.common.Characteristic("nzxor"), True),
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
        # function/characteristic(forwarded export)
        ("ea2876", "file", capa.features.common.Characteristic("forwarded export"), True),
        # before this we used ambiguous (0x4556E5, False), which has a data reference / indirect recursive call, see #386
        ("mimikatz", "function=0x456BB9", capa.features.common.Characteristic("calls to"), False),
        # file/function-name
        ("pma16-01", "file", capa.features.file.FunctionName("__aulldiv"), True),
        # os & format & arch
        ("pma16-01", "file", OS(OS_WINDOWS), True),
        ("pma16-01", "file", OS(OS_LINUX), False),
        ("mimikatz", "file", OS(OS_WINDOWS), True),
        ("pma16-01", "function=0x404356", OS(OS_WINDOWS), True),
        ("pma16-01", "function=0x404356,bb=0x4043B9", OS(OS_WINDOWS), True),
        ("mimikatz", "function=0x40105D", OS(OS_WINDOWS), True),
        ("pma16-01", "file", Arch(ARCH_I386), True),
        ("pma16-01", "file", Arch(ARCH_AMD64), False),
        ("mimikatz", "file", Arch(ARCH_I386), True),
        ("pma16-01", "function=0x404356", Arch(ARCH_I386), True),
        ("pma16-01", "function=0x404356,bb=0x4043B9", Arch(ARCH_I386), True),
        ("mimikatz", "function=0x40105D", Arch(ARCH_I386), True),
        ("pma16-01", "file", Format(FORMAT_PE), True),
        ("pma16-01", "file", Format(FORMAT_ELF), False),
        ("mimikatz", "file", Format(FORMAT_PE), True),
        # format is also a global feature
        ("pma16-01", "function=0x404356", Format(FORMAT_PE), True),
        ("mimikatz", "function=0x456BB9", Format(FORMAT_PE), True),
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

# this list should be merged into the one above (FEATURE_PRESENSE_TESTS)
# once the debug symbol functionality has been added to all backends
FEATURE_SYMTAB_FUNC_TESTS = [
    (
        "2bf18d",
        "function=0x4027b3,bb=0x402861,insn=0x40286d",
        capa.features.insn.API("__GI_connect"),
        True,
    ),
    (
        "2bf18d",
        "function=0x4027b3,bb=0x402861,insn=0x40286d",
        capa.features.insn.API("connect"),
        True,
    ),
    (
        "2bf18d",
        "function=0x4027b3,bb=0x402861,insn=0x40286d",
        capa.features.insn.API("__libc_connect"),
        True,
    ),
    (
        "2bf18d",
        "function=0x4088a4",
        capa.features.file.FunctionName("__GI_connect"),
        True,
    ),
    (
        "2bf18d",
        "function=0x4088a4",
        capa.features.file.FunctionName("connect"),
        True,
    ),
    (
        "2bf18d",
        "function=0x4088a4",
        capa.features.file.FunctionName("__libc_connect"),
        True,
    ),
]

FEATURE_PRESENCE_TESTS_DOTNET = sorted(
    [
        ("b9f5b", "file", Arch(ARCH_I386), True),
        ("b9f5b", "file", Arch(ARCH_AMD64), False),
        ("mixed-mode-64", "file", Arch(ARCH_AMD64), True),
        ("mixed-mode-64", "file", Arch(ARCH_I386), False),
        ("mixed-mode-64", "file", capa.features.common.Characteristic("mixed mode"), True),
        ("hello-world", "file", capa.features.common.Characteristic("mixed mode"), False),
        ("b9f5b", "file", OS(OS_ANY), True),
        ("b9f5b", "file", Format(FORMAT_PE), True),
        ("b9f5b", "file", Format(FORMAT_DOTNET), True),
        ("hello-world", "file", capa.features.file.FunctionName("HelloWorld::Main"), True),
        ("hello-world", "file", capa.features.file.FunctionName("HelloWorld::ctor"), True),
        ("hello-world", "file", capa.features.file.FunctionName("HelloWorld::cctor"), False),
        ("hello-world", "file", capa.features.common.String("Hello World!"), True),
        ("hello-world", "file", capa.features.common.Class("HelloWorld"), True),
        ("hello-world", "file", capa.features.common.Class("System.Console"), True),
        ("hello-world", "file", capa.features.common.Namespace("System.Diagnostics"), True),
        ("hello-world", "function=0x250", capa.features.common.String("Hello World!"), True),
        ("hello-world", "function=0x250, bb=0x250, insn=0x252", capa.features.common.String("Hello World!"), True),
        ("hello-world", "function=0x250, bb=0x250, insn=0x257", capa.features.common.Class("System.Console"), True),
        ("hello-world", "function=0x250, bb=0x250, insn=0x257", capa.features.common.Namespace("System"), True),
        ("hello-world", "function=0x250", capa.features.insn.API("System.Console::WriteLine"), True),
        ("hello-world", "file", capa.features.file.Import("System.Console::WriteLine"), True),
        ("_1c444", "file", capa.features.common.String(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"), True),
        ("_1c444", "file", capa.features.common.String("get_IsAlive"), True),
        ("_1c444", "file", capa.features.file.Import("gdi32.CreateCompatibleBitmap"), True),
        ("_1c444", "file", capa.features.file.Import("CreateCompatibleBitmap"), True),
        ("_1c444", "file", capa.features.file.Import("gdi32::CreateCompatibleBitmap"), False),
        ("_1c444", "function=0x1F68", capa.features.insn.API("GetWindowDC"), True),
        # not extracting dll anymore
        ("_1c444", "function=0x1F68", capa.features.insn.API("user32.GetWindowDC"), False),
        ("_1c444", "function=0x1F68", capa.features.insn.Number(0xCC0020), True),
        ("_1c444", "token=0x600001D", capa.features.common.Characteristic("calls to"), True),
        ("_1c444", "token=0x6000018", capa.features.common.Characteristic("calls to"), False),
        ("_1c444", "token=0x600001D", capa.features.common.Characteristic("calls from"), True),
        ("_1c444", "token=0x600000F", capa.features.common.Characteristic("calls from"), False),
        ("_1c444", "function=0x1F68", capa.features.insn.Number(0x0), True),
        ("_1c444", "function=0x1F68", capa.features.insn.Number(0x1), False),
        ("_692f", "token=0x6000004", capa.features.insn.API("System.Linq.Enumerable::First"), True),  # generic method
        (
            "_692f",
            "token=0x6000004",
            capa.features.insn.Property("System.Linq.Enumerable::First"),
            False,
        ),  # generic method
        ("_692f", "token=0x6000004", capa.features.common.Namespace("System.Linq"), True),  # generic method
        ("_692f", "token=0x6000004", capa.features.common.Class("System.Linq.Enumerable"), True),  # generic method
        ("_1c444", "token=0x6000020", capa.features.common.Namespace("Reqss"), True),  # ldftn
        ("_1c444", "token=0x6000020", capa.features.common.Class("Reqss.Reqss"), True),  # ldftn
        (
            "_1c444",
            "function=0x1F59, bb=0x1F59, insn=0x1F5B",
            capa.features.common.Characteristic("unmanaged call"),
            True,
        ),
        ("_1c444", "function=0x2544", capa.features.common.Characteristic("unmanaged call"), False),
        # same as above but using token instead of function
        ("_1c444", "token=0x6000088", capa.features.common.Characteristic("unmanaged call"), False),
        (
            "_1c444",
            "function=0x1F68, bb=0x1F68, insn=0x1FF9",
            capa.features.insn.API("System.Drawing.Image::FromHbitmap"),
            True,
        ),
        ("_1c444", "function=0x1F68, bb=0x1F68, insn=0x1FF9", capa.features.insn.API("FromHbitmap"), False),
        (
            "_1c444",
            "token=0x600002B",
            capa.features.insn.Property("System.IO.FileInfo::Length", access=FeatureAccess.READ),
            True,
        ),  # MemberRef property access
        (
            "_1c444",
            "token=0x600002B",
            capa.features.insn.Property("System.IO.FileInfo::Length"),
            True,
        ),  # MemberRef property access
        (
            "_1c444",
            "token=0x6000081",
            capa.features.insn.API("System.Diagnostics.Process::Start"),
            True,
        ),  # MemberRef property access
        (
            "_1c444",
            "token=0x6000081",
            capa.features.insn.Property(
                "System.Diagnostics.ProcessStartInfo::UseShellExecute", access=FeatureAccess.WRITE
            ),  # MemberRef property access
            True,
        ),
        (
            "_1c444",
            "token=0x6000081",
            capa.features.insn.Property(
                "System.Diagnostics.ProcessStartInfo::WorkingDirectory", access=FeatureAccess.WRITE
            ),  # MemberRef property access
            True,
        ),
        (
            "_1c444",
            "token=0x6000081",
            capa.features.insn.Property(
                "System.Diagnostics.ProcessStartInfo::FileName", access=FeatureAccess.WRITE
            ),  # MemberRef property access
            True,
        ),
        (
            "_1c444",
            "token=0x6000087",
            capa.features.insn.Property(
                "Sockets.MySocket::reConnectionDelay", access=FeatureAccess.WRITE
            ),  # Field property access
            True,
        ),
        (
            "_1c444",
            "token=0x600008A",
            capa.features.insn.Property(
                "Sockets.MySocket::isConnected", access=FeatureAccess.WRITE
            ),  # Field property access
            True,
        ),
        (
            "_1c444",
            "token=0x600008A",
            capa.features.common.Class("Sockets.MySocket"),  # Field property access
            True,
        ),
        (
            "_1c444",
            "token=0x600008A",
            capa.features.common.Namespace("Sockets"),  # Field property access
            True,
        ),
        (
            "_1c444",
            "token=0x600008A",
            capa.features.insn.Property(
                "Sockets.MySocket::onConnected", access=FeatureAccess.READ
            ),  # Field property access
            True,
        ),
        (
            "_0953c",
            "token=0x6000004",
            capa.features.insn.Property(
                "System.Diagnostics.Debugger::IsAttached", access=FeatureAccess.READ
            ),  # MemberRef property access
            True,
        ),
        (
            "_0953c",
            "token=0x6000004",
            capa.features.common.Class("System.Diagnostics.Debugger"),  # MemberRef property access
            True,
        ),
        (
            "_0953c",
            "token=0x6000004",
            capa.features.common.Namespace("System.Diagnostics"),  # MemberRef property access
            True,
        ),
        (
            "_692f",
            "token=0x6000006",
            capa.features.insn.Property(
                "System.Management.Automation.PowerShell::Streams", access=FeatureAccess.READ
            ),  # MemberRef property access
            False,
        ),
        (
            "_387f15",
            "token=0x600009E",
            capa.features.insn.Property(
                "Modulo.IqQzcRDvSTulAhyLtZHqyeYGgaXGbuLwhxUKXYmhtnOmgpnPJDTSIPhYPpnE::geoplugin_countryCode",
                access=FeatureAccess.READ,
            ),  # MethodDef property access
            True,
        ),
        (
            "_387f15",
            "token=0x600009E",
            capa.features.common.Class(
                "Modulo.IqQzcRDvSTulAhyLtZHqyeYGgaXGbuLwhxUKXYmhtnOmgpnPJDTSIPhYPpnE"
            ),  # MethodDef property access
            True,
        ),
        (
            "_387f15",
            "token=0x600009E",
            capa.features.common.Namespace("Modulo"),  # MethodDef property access
            True,
        ),
        (
            "_039a6",
            "token=0x6000007",
            capa.features.insn.API("System.Reflection.Assembly::Load"),
            True,
        ),
        (
            "_039a6",
            "token=0x600001D",
            capa.features.insn.Property("StagelessHollow.Arac::Marka", access=FeatureAccess.READ),  # MethodDef method
            True,
        ),
        (
            "_039a6",
            "token=0x600001C",
            capa.features.insn.Property("StagelessHollow.Arac::Marka", access=FeatureAccess.READ),  # MethodDef method
            False,
        ),
        (
            "_039a6",
            "token=0x6000023",
            capa.features.insn.Property(
                "System.Runtime.CompilerServices.AsyncTaskMethodBuilder::Task", access=FeatureAccess.READ
            ),  # MemberRef method
            False,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("mynamespace.myclass_outer0"),
            True,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("mynamespace.myclass_outer1"),
            True,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("mynamespace.myclass_outer0/myclass_inner0_0"),
            True,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("mynamespace.myclass_outer0/myclass_inner0_1"),
            True,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("mynamespace.myclass_outer1/myclass_inner1_0"),
            True,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("mynamespace.myclass_outer1/myclass_inner1_1"),
            True,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("mynamespace.myclass_outer1/myclass_inner1_0/myclass_inner_inner"),
            True,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("myclass_inner_inner"),
            False,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("myclass_inner1_0"),
            False,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("myclass_inner1_1"),
            False,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("myclass_inner0_0"),
            False,
        ),
        (
            "nested_typedef",
            "file",
            capa.features.common.Class("myclass_inner0_1"),
            False,
        ),
        (
            "nested_typeref",
            "file",
            capa.features.file.Import("Android.OS.Build/VERSION::SdkInt"),
            True,
        ),
        (
            "nested_typeref",
            "file",
            capa.features.file.Import("Android.Media.Image/Plane::Buffer"),
            True,
        ),
        (
            "nested_typeref",
            "file",
            capa.features.file.Import("Android.Provider.Telephony/Sent/Sent::ContentUri"),
            True,
        ),
        (
            "nested_typeref",
            "file",
            capa.features.file.Import("Android.OS.Build::SdkInt"),
            False,
        ),
        (
            "nested_typeref",
            "file",
            capa.features.file.Import("Plane::Buffer"),
            False,
        ),
        (
            "nested_typeref",
            "file",
            capa.features.file.Import("Sent::ContentUri"),
            False,
        ),
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


FEATURE_COUNT_TESTS_DOTNET = [
    ("_1c444", "token=0x600001D", capa.features.common.Characteristic("calls to"), 1),
    ("_1c444", "token=0x600001D", capa.features.common.Characteristic("calls from"), 9),
]


FEATURE_COUNT_TESTS_GHIDRA = [
    # Ghidra may render functions as labels, as well as provide differing amounts of call references
    ("mimikatz", "function=0x4702FD", capa.features.common.Characteristic("calls from"), 0),
    ("mimikatz", "function=0x401bf1", capa.features.common.Characteristic("calls to"), 2),
    ("mimikatz", "function=0x401000", capa.features.basicblock.BasicBlock(), 3),
]


def do_test_feature_presence(get_extractor, sample, scope, feature, expected):
    extractor = get_extractor(sample)
    features = scope(extractor)
    if expected:
        msg = f"{str(feature)} should be found in {scope.__name__}"
    else:
        msg = f"{str(feature)} should not be found in {scope.__name__}"
    assert feature.evaluate(features) == expected, msg


def do_test_feature_count(get_extractor, sample, scope, feature, expected):
    extractor = get_extractor(sample)
    features = scope(extractor)
    msg = f"{str(feature)} should be found {expected} times in {scope.__name__}, found: {len(features[feature])}"
    assert len(features[feature]) == expected, msg


def get_extractor(path: Path):
    extractor = get_viv_extractor(path)
    # overload the extractor so that the fixture exposes `extractor.path`
    setattr(extractor, "path", path.as_posix())
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
def z395eb_extractor():
    return get_extractor(get_data_path_by_name("395eb..."))


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
def hello_world_dotnetfile_extractor():
    return get_dnfile_extractor(get_data_path_by_name("hello-world"))


@pytest.fixture
def _1c444_dotnetfile_extractor():
    return get_dnfile_extractor(get_data_path_by_name("_1c444"))


@pytest.fixture
def _692f_dotnetfile_extractor():
    return get_dnfile_extractor(get_data_path_by_name("_692f"))


@pytest.fixture
def _0953c_dotnetfile_extractor():
    return get_dnfile_extractor(get_data_path_by_name("_0953c"))


@pytest.fixture
def _039a6_dotnetfile_extractor():
    return get_dnfile_extractor(get_data_path_by_name("_039a6"))


def get_result_doc(path: Path):
    return capa.render.result_document.ResultDocument.from_file(path)


@pytest.fixture
def pma0101_rd():
    # python -m capa.main tests/data/Practical\ Malware\ Analysis\ Lab\ 01-01.dll_ --json > tests/data/rd/Practical\ Malware\ Analysis\ Lab\ 01-01.dll_.json
    return get_result_doc(CD / "data" / "rd" / "Practical Malware Analysis Lab 01-01.dll_.json")


@pytest.fixture
def dotnet_1c444e_rd():
    # .NET sample
    # python -m capa.main tests/data/dotnet/1c444ebeba24dcba8628b7dfe5fec7c6.exe_ --json > tests/data/rd/1c444ebeba24dcba8628b7dfe5fec7c6.exe_.json
    return get_result_doc(CD / "data" / "rd" / "1c444ebeba24dcba8628b7dfe5fec7c6.exe_.json")


@pytest.fixture
def a3f3bbc_rd():
    # python -m capa.main tests/data/3f3bbcf8fd90bdcdcdc5494314ed4225.exe_ --json > tests/data/rd/3f3bbcf8fd90bdcdcdc5494314ed4225.exe_.json
    return get_result_doc(CD / "data" / "rd" / "3f3bbcf8fd90bdcdcdc5494314ed4225.exe_.json")


@pytest.fixture
def al_khaserx86_rd():
    # python -m capa.main tests/data/al-khaser_x86.exe_ --json > tests/data/rd/al-khaser_x86.exe_.json
    return get_result_doc(CD / "data" / "rd" / "al-khaser_x86.exe_.json")


@pytest.fixture
def al_khaserx64_rd():
    # python -m capa.main tests/data/al-khaser_x64.exe_ --json > tests/data/rd/al-khaser_x64.exe_.json
    return get_result_doc(CD / "data" / "rd" / "al-khaser_x64.exe_.json")


@pytest.fixture
def a076114_rd():
    # python -m capa.main tests/data/0761142efbda6c4b1e801223de723578.dll_ --json > tests/data/rd/0761142efbda6c4b1e801223de723578.dll_.json
    return get_result_doc(CD / "data" / "rd" / "0761142efbda6c4b1e801223de723578.dll_.json")


@pytest.fixture
def dynamic_a0000a6_rd():
    # python -m capa.main tests/data/dynamic/cape/v2.2/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json --json > tests/data/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json
    # gzip tests/data/rd/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json
    return get_result_doc(
        CD / "data" / "rd" / "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz"
    )
