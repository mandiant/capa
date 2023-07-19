#!/usr/bin/env python
"""
Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

"""
import sys
import logging
import pathlib
import argparse
import textwrap
from enum import Enum
from typing import Literal, Optional, assert_never

import vstruct
import vstruct.defs.minidump as minidump
from vstruct.primitives import v_bytes, v_uint16, v_uint32, v_uint64

logger = logging.getLogger("show-mdmp")


class hexdump:
    # via: https://gist.github.com/NeatMonster/c06c61ba4114a2b31418a364341c26c0
    def __init__(self, buf, off=0):
        self.buf = buf
        self.off = off

    def __iter__(self):
        last_bs, last_line = None, None
        for i in range(0, len(self.buf), 16):
            bs = bytearray(self.buf[i : i + 16])
            line = "{:08x}  {:23}  {:23}  |{:16}|".format(
                self.off + i,
                " ".join(("{:02x}".format(x) for x in bs[:8])),
                " ".join(("{:02x}".format(x) for x in bs[8:])),
                "".join((chr(x) if 32 <= x < 127 else "." for x in bs)),
            )
            if bs == last_bs:
                line = "*"
            if bs != last_bs or line != last_line:
                yield line
            last_bs, last_line = bs, line
        yield "{:08x}".format(self.off + len(self.buf))

    def __str__(self):
        return "\n".join(self)

    def __repr__(self):
        return "\n".join(self)


# https://github.com/rust-minidump/rust-minidump/blob/87a29fba5e19cfae5ebf73a57ba31504a3872545/minidump-common/src/format.rs#L1365C1-L1392C2
class FLOATING_SAVE_AREA_X86(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.control_word = v_uint32()
        self.status_word = v_uint32()
        self.tag_word = v_uint32()
        self.error_offset = v_uint32()
        self.error_selector = v_uint32()
        self.data_offset = v_uint32()
        self.data_selector = v_uint32()
        self.register_area = v_bytes(size=80)
        self.cr0_npx_state = v_uint32()


class CONTEXT_X86(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.context_flags = v_uint32()
        self.dr0 = v_uint32()
        self.dr1 = v_uint32()
        self.dr2 = v_uint32()
        self.dr3 = v_uint32()
        self.dr6 = v_uint32()
        self.dr7 = v_uint32()
        self.float_save = FLOATING_SAVE_AREA_X86()
        self.gs = v_uint32()
        self.fs = v_uint32()
        self.es = v_uint32()
        self.ds = v_uint32()
        self.edi = v_uint32()
        self.esi = v_uint32()
        self.ebx = v_uint32()
        self.edx = v_uint32()
        self.ecx = v_uint32()
        self.eax = v_uint32()
        self.ebp = v_uint32()
        self.eip = v_uint32()
        self.cs = v_uint32()
        self.eflags = v_uint32()
        self.esp = v_uint32()
        self.ss = v_uint32()
        self.extended_registers = v_bytes(size=512)


class v_vint128(vstruct.VStruct):
    # vector register
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.lo = v_uint64()
        self.hi = v_uint64()


# https://github.com/rust-minidump/rust-minidump/blob/87a29fba5e19cfae5ebf73a57ba31504a3872545/minidump-common/src/format.rs#L957C1-L1013C2
class CONTEXT_AMD64(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.p1_home = v_uint64()
        self.p2_home = v_uint64()
        self.p3_home = v_uint64()
        self.p4_home = v_uint64()
        self.p5_home = v_uint64()
        self.p6_home = v_uint64()
        self.context_flags = v_uint32()
        self.mx_csr = v_uint32()
        self.cs = v_uint16()
        self.ds = v_uint16()
        self.es = v_uint16()
        self.fs = v_uint16()
        self.gs = v_uint16()
        self.ss = v_uint16()
        self.eflags = v_uint32()
        self.dr0 = v_uint64()
        self.dr1 = v_uint64()
        self.dr2 = v_uint64()
        self.dr3 = v_uint64()
        self.dr6 = v_uint64()
        self.dr7 = v_uint64()
        self.rax = v_uint64()
        self.rcx = v_uint64()
        self.rdx = v_uint64()
        self.rbx = v_uint64()
        self.rsp = v_uint64()
        self.rbp = v_uint64()
        self.rsi = v_uint64()
        self.rdi = v_uint64()
        self.r8 = v_uint64()
        self.r9 = v_uint64()
        self.r10 = v_uint64()
        self.r11 = v_uint64()
        self.r12 = v_uint64()
        self.r13 = v_uint64()
        self.r14 = v_uint64()
        self.r15 = v_uint64()
        self.rip = v_uint64()
        self.float_save = v_bytes(size=512)
        self.vector_register = vstruct.VArray([v_vint128() for i in range(26)])
        self.vector_control = v_uint64()
        self.debug_control = v_uint64()
        self.last_branch_to_rip = v_uint64()
        self.last_branch_from_rip = v_uint64()
        self.last_exception_to_rip = v_uint64()
        self.last_exception_from_rip = v_uint64()


def find_name(buf: bytes, mdmp: minidump.MiniDump, va: int) -> Optional[str]:
    for _, mod in mdmp.MiniDumpModuleListStream.Modules:
        if mod.BaseOfImage <= va < mod.BaseOfImage + mod.SizeOfImage:
            mname = minidump.MiniDumpString()
            mname.vsParse(buf, offset=mod.ModuleNameRva)

            return mname.Buffer

    for _, thread in mdmp.MiniDumpThreadListStream.Threads:
        if thread.Stack.StartOfMemoryRange <= va < thread.Stack.StartOfMemoryRange + thread.Stack.Memory.DataSize:
            return f"stack for thread {thread.ThreadId}"

    for _, thread in mdmp.MiniDumpThreadListStream.Threads:
        if thread.Teb == va:
            return f"TEB for thread {thread.ThreadId}"

    return None


def get_arch(mdmp: minidump.MiniDump) -> Literal["amd64", "intel"]:
    # https://github.com/rust-minidump/rust-minidump/blob/87a29fba5e19cfae5ebf73a57ba31504a3872545/minidump-common/src/format.rs#L1476C1-L1498C45
    PROCESSOR_ARCHITECTURE_INTEL = 0
    PROCESSOR_ARCHITECTURE_AMD64 = 9

    if mdmp.MiniDumpSystemInfoStream.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64:
        return "amd64"
    elif mdmp.MiniDumpSystemInfoStream.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL:
        return "intel"
    else:
        raise NotImplementedError(f"unknown processor architecture: {mdmp.SystemInfo.ProcessorArchitecture}")


def memory_ranges(mdmp: minidump.MiniDump) -> minidump.MiniDumpMemoryDescriptor | minidump.MiniDumpMemoryDescriptor64:
    arch = get_arch(mdmp)

    if arch == "amd64":
        for _, mem in mdmp.MiniDumpMemory64ListStream.MemoryRanges:
            yield mem
    elif arch == "intel":
        for _, mem in mdmp.MiniDumpMemoryListStream.MemoryRanges:
            yield mem
    else:
        assert_never(arch)


def memory_range_start(mem: minidump.MiniDumpMemoryDescriptor | minidump.MiniDumpMemoryDescriptor64) -> int:
    if isinstance(mem, minidump.MiniDumpMemoryDescriptor):
        # needs fix here: https://github.com/vivisect/vivisect/pull/626
        # for correct name of this field.
        return mem.StartOfMemoryRange
    elif isinstance(mem, minidump.MiniDumpMemoryDescriptor64):
        return mem.StartOfMemoryRange
    else:
        assert_never(mem)


def memory_range_size(mem: minidump.MiniDumpMemoryDescriptor | minidump.MiniDumpMemoryDescriptor64) -> int:
    if isinstance(mem, minidump.MiniDumpMemoryDescriptor):
        return mem.Memory.DataSize
    elif isinstance(mem, minidump.MiniDumpMemoryDescriptor64):
        return mem.DataSize
    else:
        assert_never(mem)


def memory_range_end(mem: minidump.MiniDumpMemoryDescriptor | minidump.MiniDumpMemoryDescriptor64) -> int:
    return memory_range_start(mem) + memory_range_size(mem)


def resolve_register(buf: bytes, mdmp: minidump.MiniDump, v: int) -> Optional[str]:
    name = find_name(buf, mdmp, v)
    if name:
        return f"-> {name}"

    for mem in memory_ranges(mdmp):
        if memory_range_start(mem) <= v < memory_range_end(mem):
            return f"-> range [{memory_range_start(mem):#016x}-{memory_range_end(mem):#016x}]"

    return None


class MemoryState(Enum):
    MEM_COMMIT = 0x01000
    MEM_RESERVE = 0x02000
    MEM_FREE = 0x10000


class MemoryProtection(Enum):
    PAGE_NONE = 0x00
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    ACCESS_MASK = 0xFF
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Describe the contents of a Minidump file")
    parser.add_argument("mdmp", type=str, help="path to minidump file")

    logging_group = parser.add_argument_group("logging arguments")

    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )

    args = parser.parse_args(args=argv)

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    path = pathlib.Path(args.mdmp)
    buf = path.read_bytes()

    # not yet implemented by vstruct (nor rust-minidump):
    #   SystemMemoryInfoStream = 21,
    #   ProcessVmCountersStream = 22,
    #   IptTraceStream = 23,
    #   ThreadNamesStream = 24,
    mdmp = minidump.parseFromBytes(buf)
    print(mdmp.tree())

    arch = get_arch(mdmp)
    print(f"arch: {arch}")
    print()

    print("modules:")
    for _, mod in mdmp.MiniDumpModuleListStream.Modules:
        start, end = mod.BaseOfImage, mod.BaseOfImage + mod.SizeOfImage

        mname = minidump.MiniDumpString()
        mname.vsParse(buf, offset=mod.ModuleNameRva)
        print(f"  [{start:#016x}-{end:#016x}] {mname.Buffer}")

        # danger: O(n**2)
        for mem in memory_ranges(mdmp):
            if start <= memory_range_start(mem) < end:
                print(f"    [{memory_range_start(mem):#016x}-{memory_range_end(mem):#016x}]")

    print()

    # needs fix here: https://github.com/vivisect/vivisect/pull/625
    # in order to recover all the threads.

    for _, thread in mdmp.MiniDumpThreadListStream.Threads:
        if arch == "amd64":
            ctx = CONTEXT_AMD64()
        elif arch == "intel":
            ctx = CONTEXT_X86()
        else:
            raise NotImplementedError(f"unknown processor architecture: {arch}")

        ctx.vsParse(buf, offset=thread.ThreadContext.RVA)

        if arch == "amd64":
            print(
                textwrap.dedent(
                    f"""
                thread: {thread.ThreadId}
                    rax: {ctx.rax:#016x} {resolve_register(buf, mdmp, ctx.rax) or ""}
                    rbx: {ctx.rbx:#016x} {resolve_register(buf, mdmp, ctx.rbx) or ""}
                    rcx: {ctx.rcx:#016x} {resolve_register(buf, mdmp, ctx.rcx) or ""}
                    rdx: {ctx.rdx:#016x} {resolve_register(buf, mdmp, ctx.rdx) or ""}
                    rsi: {ctx.rsi:#016x} {resolve_register(buf, mdmp, ctx.rsi) or ""}
                    rdi: {ctx.rdi:#016x} {resolve_register(buf, mdmp, ctx.rdi) or ""}
                    rbp: {ctx.rbp:#016x} {resolve_register(buf, mdmp, ctx.rbp) or ""}
                    rsp: {ctx.rsp:#016x} {resolve_register(buf, mdmp, ctx.rsp) or ""}
                    r8:  {ctx.r8:#016x} {resolve_register(buf, mdmp, ctx.r8) or ""}
                    r9:  {ctx.r9:#016x} {resolve_register(buf, mdmp, ctx.r9) or ""}
                    r10: {ctx.r10:#016x} {resolve_register(buf, mdmp, ctx.r10) or ""}
                    r11: {ctx.r11:#016x} {resolve_register(buf, mdmp, ctx.r11) or ""}
                    r12: {ctx.r12:#016x} {resolve_register(buf, mdmp, ctx.r12) or ""}
                    r13: {ctx.r13:#016x} {resolve_register(buf, mdmp, ctx.r13) or ""}
                    r14: {ctx.r14:#016x} {resolve_register(buf, mdmp, ctx.r14) or ""}
                    r15: {ctx.r15:#016x} {resolve_register(buf, mdmp, ctx.r15) or ""}
                    rip: {ctx.rip:#016x} {resolve_register(buf, mdmp, ctx.rip) or ""}
            """
                )
            )
        elif arch == "intel":
            print(
                textwrap.dedent(
                    f"""
                thread: {thread.ThreadId}
                    eax: {ctx.eax:#016x} {resolve_register(buf, mdmp, ctx.eax) or ""}
                    ebx: {ctx.ebx:#016x} {resolve_register(buf, mdmp, ctx.ebx) or ""}
                    ecx: {ctx.ecx:#016x} {resolve_register(buf, mdmp, ctx.ecx) or ""}
                    edx: {ctx.edx:#016x} {resolve_register(buf, mdmp, ctx.edx) or ""}
                    esi: {ctx.esi:#016x} {resolve_register(buf, mdmp, ctx.esi) or ""}
                    edi: {ctx.edi:#016x} {resolve_register(buf, mdmp, ctx.edi) or ""}
                    ebp: {ctx.ebp:#016x} {resolve_register(buf, mdmp, ctx.ebp) or ""}
                    esp: {ctx.esp:#016x} {resolve_register(buf, mdmp, ctx.esp) or ""}
                    eip: {ctx.eip:#016x} {resolve_register(buf, mdmp, ctx.eip) or ""}
            """
                )
            )
        else:
            raise NotImplementedError(f"unknown processor architecture: {arch}")

        print(f"  teb:  [{thread.Teb:#08x}-???]")

        # danger: O(n**2)
        for mem in memory_ranges(mdmp):
            if thread.Teb == memory_range_start(mem):
                print(f"    [{memory_range_start(mem):#016x}-{memory_range_end(mem):#016x}]")
        print()

        start, end = thread.Stack.StartOfMemoryRange, thread.Stack.StartOfMemoryRange + thread.Stack.Memory.DataSize
        print(f"  stack: [{start:#016x}-{end:#016x}]")

        # danger: O(n**2)
        for mem in memory_ranges(mdmp):
            if start <= memory_range_start(mem) < end:
                print(f"    [{memory_range_start(mem):#016x}-{memory_range_end(mem):#016x}]")
    print()

    # these are all the memory ranges in the process virtual memory.
    # not all of these ranges will be available in the memory dump.
    # this metadata is also not available in all memory dumps.
    if hasattr(mdmp, "MiniDumpMemoryInfoListStream"):
        print("memory regions:")
        for _, entry in mdmp.MiniDumpMemoryInfoListStream.Entries:
            name = find_name(buf, mdmp, entry.BaseAddress) or ""

            state = MemoryState(entry.State).name
            access = MemoryProtection(entry.Protect & MemoryProtection.ACCESS_MASK.value).name

            start, end = entry.BaseAddress, entry.BaseAddress + entry.RegionSize
            print(f"  [{start:#016x}-{end:#016x}] {state:<12s} {access:<20s} {name}")
        print()

    # these are the ranges that are stored within the memory dump
    print("memory dump ranges:")
    for mem in sorted(memory_ranges(mdmp), key=lambda mem: mem.StartOfMemoryRange):
        name = find_name(buf, mdmp, memory_range_start(mem)) or ""

        print(f"  [{memory_range_start(mem):#016x}-{memory_range_end(mem):#016x}] {name}")

        # mbuf = buf[mem.Memory.RVA:mem.Memory.RVA + mem.Memory.DataSize]
        # print(hexdump(mbuf, off=mem.StartOfMemoryRange))
    print()


if __name__ == "__main__":
    sys.exit(main())
