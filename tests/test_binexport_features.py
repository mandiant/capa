# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import binascii
from typing import cast

import pytest
import fixtures

import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock
from capa.features.common import (
    OS,
    OS_LINUX,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    FORMAT_ELF,
    OS_ANDROID,
    OS_WINDOWS,
    ARCH_AARCH64,
    Arch,
    Format,
)

FEATURE_PRESENCE_TESTS_BE2_ELF_AARCH64 = sorted(
    [
        # file/string
        (
            "687e79.ghidra.be2",
            "file",
            capa.features.common.String("AppDataService start"),
            True,
        ),
        ("687e79.ghidra.be2", "file", capa.features.common.String("nope"), False),
        # file/sections
        ("687e79.ghidra.be2", "file", capa.features.file.Section(".text"), True),
        ("687e79.ghidra.be2", "file", capa.features.file.Section(".nope"), False),
        # file/exports
        (
            "687e79.ghidra.be2",
            "file",
            capa.features.file.Export("android::clearDir"),
            "xfail: name demangling is not implemented",
        ),
        ("687e79.ghidra.be2", "file", capa.features.file.Export("nope"), False),
        # file/imports
        ("687e79.ghidra.be2", "file", capa.features.file.Import("fopen"), True),
        ("687e79.ghidra.be2", "file", capa.features.file.Import("exit"), True),
        (
            "687e79.ghidra.be2",
            "file",
            capa.features.file.Import("_ZN7android10IInterfaceD0Ev"),
            True,
        ),
        ("687e79.ghidra.be2", "file", capa.features.file.Import("nope"), False),
        # function/characteristic(loop)
        (
            "687e79.ghidra.be2",
            "function=0x1056c0",
            capa.features.common.Characteristic("loop"),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x1075c0",
            capa.features.common.Characteristic("loop"),
            False,
        ),
        # bb/characteristic(tight loop)
        (
            "d1e650.ghidra.be2",
            "function=0x114af4",
            capa.features.common.Characteristic("tight loop"),
            True,
        ),
        (
            "d1e650.ghidra.be2",
            "function=0x118F1C",
            capa.features.common.Characteristic("tight loop"),
            True,
        ),
        (
            "d1e650.ghidra.be2",
            "function=0x11464c",
            capa.features.common.Characteristic("tight loop"),
            False,
        ),
        # bb/characteristic(stack string)
        (
            "687e79.ghidra.be2",
            "function=0x0",
            capa.features.common.Characteristic("stack string"),
            "xfail: not implemented yet",
        ),
        (
            "687e79.ghidra.be2",
            "function=0x0",
            capa.features.common.Characteristic("stack string"),
            "xfail: not implemented yet",
        ),
        # insn/mnemonic
        ("687e79.ghidra.be2", "function=0x107588", capa.features.insn.Mnemonic("stp"), True),
        ("687e79.ghidra.be2", "function=0x107588", capa.features.insn.Mnemonic("adrp"), True),
        ("687e79.ghidra.be2", "function=0x107588", capa.features.insn.Mnemonic("bl"), True),
        ("687e79.ghidra.be2", "function=0x107588", capa.features.insn.Mnemonic("in"), False),
        ("687e79.ghidra.be2", "function=0x107588", capa.features.insn.Mnemonic("adrl"), False),
        # insn/number
        # 00114524 add x29,sp,#0x10
        (
            "d1e650.ghidra.be2",
            "function=0x11451c",
            capa.features.insn.Number(0x10),
            False,
        ),
        # 00105128 sub sp,sp,#0xE0
        (
            "687e79.ghidra.be2",
            "function=0x105128",
            capa.features.insn.Number(0xE0),
            False,
        ),
        # insn/operand.number
        (
            "687e79.ghidra.be2",
            "function=0x105128,bb=0x1051e4",
            capa.features.insn.OperandNumber(1, 0xFFFFFFFF),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x107588,bb=0x107588",
            capa.features.insn.OperandNumber(1, 0x8),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x107588,bb=0x107588,insn=0x1075a4",
            capa.features.insn.OperandNumber(1, 0x8),
            True,
        ),
        # insn/operand.offset
        (
            "687e79.ghidra.be2",
            "function=0x105128,bb=0x105450",
            capa.features.insn.OperandOffset(2, 0x10),
            True,
        ),
        (
            "d1e650.ghidra.be2",
            "function=0x124854,bb=0x1248AC,insn=0x1248B4",
            capa.features.insn.OperandOffset(2, -0x48),
            True,
        ),
        (
            "d1e650.ghidra.be2",
            "function=0x13347c,bb=0x133548,insn=0x133554",
            capa.features.insn.OperandOffset(2, 0x20),
            False,
        ),
        ("687e79.ghidra.be2", "function=0x105C88", capa.features.insn.Number(0xF000), True),
        # insn/number: negative
        (
            "687e79.ghidra.be2",
            "function=0x1057f8,bb=0x1057f8",
            capa.features.insn.Number(0xFFFFFFFFFFFFFFFF),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x1057f8,bb=0x1057f8",
            capa.features.insn.Number(0xFFFFFFFFFFFFFFFF),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x1066e0,bb=0x1068c4",
            capa.features.insn.Number(0xFFFFFFFF),
            True,
        ),
        # insn/offset
        (
            "687e79.ghidra.be2",
            "function=0x105128,bb=0x105450",
            capa.features.insn.Offset(0x10),
            True,
        ),
        # ldp x29,x30,[sp, #0x20]
        (
            "d1e650.ghidra.be2",
            "function=0x13347c,bb=0x133548,insn=0x133554",
            capa.features.insn.Offset(0x20),
            False,
        ),
        # stp x20,x0,[x19, #0x8]
        (
            "d1e650.ghidra.be2",
            "function=0x1183e0,bb=0x11849c,insn=0x1184b0",
            capa.features.insn.Offset(0x8),
            True,
        ),
        # str xzr,[x8, #0x8]!
        (
            "d1e650.ghidra.be2",
            "function=0x138688,bb=0x138994,insn=0x1389a8",
            capa.features.insn.Offset(0x8),
            True,
        ),
        # ldr x9,[x8, #0x8]!
        (
            "d1e650.ghidra.be2",
            "function=0x138688,bb=0x138978,insn=0x138984",
            capa.features.insn.Offset(0x8),
            True,
        ),
        # ldr x19,[sp], #0x20
        (
            "d1e650.ghidra.be2",
            "function=0x11451c",
            capa.features.insn.Offset(0x20),
            False,
        ),
        # ldrb w9,[x8, #0x1]
        (
            "d1e650.ghidra.be2",
            "function=0x138a9c,bb=0x138b00,insn=0x138b00",
            capa.features.insn.Offset(0x1),
            True,
        ),
        # insn/offset: negative
        (
            "d1e650.ghidra.be2",
            "function=0x124854,bb=0x1248AC,insn=0x1248B4",
            capa.features.insn.Offset(-0x48),
            True,
        ),
        # insn/offset from mnemonic: add
        # 0010514c add x23,param_1,#0x8
        (
            "687e79.ghidra.be2",
            "function=0x105128,bb=0x105128,insn=0x10514c",
            capa.features.insn.Offset(0x8),
            True,
        ),
        # insn/api
        # not extracting dll name
        ("687e79.ghidra.be2", "function=0x105c88", capa.features.insn.API("memset"), True),
        ("687e79.ghidra.be2", "function=0x105c88", capa.features.insn.API("Nope"), False),
        # insn/string
        (
            "687e79.ghidra.be2",
            "function=0x107588",
            capa.features.common.String("AppDataService start"),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x1075c0",
            capa.features.common.String("AppDataService"),
            True,
        ),
        ("687e79.ghidra.be2", "function=0x107588", capa.features.common.String("nope"), False),
        (
            "687e79.ghidra.be2",
            "function=0x106d58",
            capa.features.common.String("/data/misc/wifi/wpa_supplicant.conf"),
            True,
        ),
        # insn/regex
        (
            "687e79.ghidra.be2",
            "function=0x105c88",
            capa.features.common.Regex("innerRename"),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x106d58",
            capa.features.common.Regex("/data/misc"),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x106d58",
            capa.features.common.Substring("/data/misc"),
            True,
        ),
        # insn/bytes
        (
            "d1e650.ghidra.be2",
            "function=0x1165a4",
            capa.features.common.Bytes(binascii.unhexlify("E405B89370BA6B419CD7925275BF6FCC1E8360CC")),
            True,
        ),
        # # don't extract byte features for obvious strings
        (
            "687e79.ghidra.be2",
            "function=0x1057f8",
            capa.features.common.Bytes("/system/xbin/busybox".encode("utf-16le")),
            False,
        ),
        # insn/characteristic(nzxor)
        (
            "d1e650.ghidra.be2",
            "function=0x114af4",
            capa.features.common.Characteristic("nzxor"),
            True,
        ),
        (
            "d1e650.ghidra.be2",
            "function=0x117988",
            capa.features.common.Characteristic("nzxor"),
            True,
        ),
        # # insn/characteristic(cross section flow)
        # ("a1982...", "function=0x4014D0", capa.features.common.Characteristic("cross section flow"), True),
        # # insn/characteristic(cross section flow): imports don't count
        # ("mimikatz", "function=0x4556E5", capa.features.common.Characteristic("cross section flow"), False),
        # insn/characteristic(recursive call)
        (
            "687e79.ghidra.be2",
            "function=0x105b38",
            capa.features.common.Characteristic("recursive call"),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x106530",
            capa.features.common.Characteristic("recursive call"),
            True,
        ),
        # insn/characteristic(indirect call)
        ("d1e650.ghidra.be2", "function=0x118620", capa.features.common.Characteristic("indirect call"), True),
        (
            "d1e650.ghidra.be2",
            "function=0x118500",
            capa.features.common.Characteristic("indirect call"),
            False,
        ),
        ("d1e650.ghidra.be2", "function=0x118620", capa.features.common.Characteristic("indirect call"), True),
        (
            "d1e650.ghidra.be2",
            "function=0x11451c",
            capa.features.common.Characteristic("indirect call"),
            True,
        ),
        # insn/characteristic(calls from)
        (
            "687e79.ghidra.be2",
            "function=0x105080",
            capa.features.common.Characteristic("calls from"),
            True,
        ),
        (
            "687e79.ghidra.be2",
            "function=0x1070e8",
            capa.features.common.Characteristic("calls from"),
            False,
        ),
        # function/characteristic(calls to)
        (
            "687e79.ghidra.be2",
            "function=0x1075c0",
            capa.features.common.Characteristic("calls to"),
            True,
        ),
        # file/function-name
        (
            "687e79.ghidra.be2",
            "file",
            capa.features.file.FunctionName("__libc_init"),
            "xfail: TODO should this be a function-name?",
        ),
        # os & format & arch
        ("687e79.ghidra.be2", "file", OS(OS_ANDROID), True),
        ("687e79.ghidra.be2", "file", OS(OS_LINUX), False),
        ("687e79.ghidra.be2", "file", OS(OS_WINDOWS), False),
        # os & format & arch are also global features
        ("687e79.ghidra.be2", "function=0x107588", OS(OS_ANDROID), True),
        ("687e79.ghidra.be2", "function=0x1075c0,bb=0x1076c0", OS(OS_ANDROID), True),
        ("687e79.ghidra.be2", "file", Arch(ARCH_I386), False),
        ("687e79.ghidra.be2", "file", Arch(ARCH_AMD64), False),
        ("687e79.ghidra.be2", "file", Arch(ARCH_AARCH64), True),
        ("687e79.ghidra.be2", "function=0x107588", Arch(ARCH_AARCH64), True),
        ("687e79.ghidra.be2", "function=0x1075c0,bb=0x1076c0", Arch(ARCH_AARCH64), True),
        ("687e79.ghidra.be2", "file", Format(FORMAT_ELF), True),
        ("687e79.ghidra.be2", "file", Format(FORMAT_PE), False),
        ("687e79.ghidra.be2", "function=0x107588", Format(FORMAT_ELF), True),
        ("687e79.ghidra.be2", "function=0x107588", Format(FORMAT_PE), False),
    ],
    # order tests by (file, item)
    # so that our LRU cache is most effective.
    key=lambda t: (t[0], t[1]),
)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    FEATURE_PRESENCE_TESTS_BE2_ELF_AARCH64,
    indirect=["sample", "scope"],
)
def test_binexport_features_elf_aarch64(sample, scope, feature, expected):
    if not isinstance(expected, bool):
        # (for now) xfails indicates using string like: "xfail: not implemented yet"
        pytest.xfail(expected)
    fixtures.do_test_feature_presence(fixtures.get_binexport_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_PRESENCE_TESTS,
    indirect=["sample", "scope"],
)
def test_binexport_features_pe_x86(sample, scope, feature, expected):
    if "mimikatz.exe_" not in sample.name:
        pytest.skip("for now only testing mimikatz.exe_ Ghidra BinExport file")

    if isinstance(feature, capa.features.common.Characteristic) and "stack string" in cast(str, feature.value):
        pytest.skip("for now only testing basic features")

    sample = sample.parent / "binexport2" / (sample.name + ".ghidra.BinExport")
    assert sample.exists()
    fixtures.do_test_feature_presence(fixtures.get_binexport_extractor, sample, scope, feature, expected)


@fixtures.parametrize(
    "sample,scope,feature,expected",
    fixtures.FEATURE_COUNT_TESTS_GHIDRA,
    indirect=["sample", "scope"],
)
def test_binexport_feature_counts_ghidra(sample, scope, feature, expected):
    if "mimikatz.exe_" not in sample.name:
        pytest.skip("for now only testing mimikatz.exe_ Ghidra BinExport file")
    sample = sample.parent / "binexport2" / (sample.name + ".ghidra.BinExport")
    assert sample.exists()
    fixtures.do_test_feature_count(fixtures.get_binexport_extractor, sample, scope, feature, expected)
