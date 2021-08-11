#!/usr/bin/env python2
"""
Copyright (C) 2021 FireEye, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

detect-elf-os

Attempt to detect the underlying OS that the given ELF file targets.
"""
import sys
import struct
import logging
import argparse
import contextlib
from enum import Enum
from typing import BinaryIO

logger = logging.getLogger("capa.detect-elf-os")


def align(v, alignment):
    remainder = v % alignment
    if remainder == 0:
        return v
    else:
        return v + remainder


class IDAIO:
    """
    An object that acts as a file-like object,
    using bytes from the current IDB workspace.
    """

    def __init__(self):
        assert IDAIO.is_runtime_ida() == True

        super(IDAIO, self).__init__()
        import idc
        import ida_bytes
        import ida_loader

        self.offset = 0

    def seek(self, offset, whence=0):
        assert whence == 0
        self.offset = offset

    def read(self, size):
        ea = ida_loader.get_fileregion_ea(self.offset)
        if ea == idc.BADADDR:
            # best guess, such as if file is mapped at address 0x0.
            ea = self.offset

        logger.debug("reading 0x%x bytes at 0x%x (ea: 0x%x)", size, self.offset, ea)
        return ida_bytes.get_bytes(ea, size)

    def close(self):
        return

    @staticmethod
    def is_runtime_ida():
        try:
            import idc
        except ImportError:
            return False
        else:
            return True


class CorruptElfFile(ValueError):
    pass


class OS(str, Enum):
    HPUX = "HPUX"
    NETBSD = "NETBSD"
    LINUX = "LINUX"
    HURD = "HURD"
    _86OPEN = "86OPEN"
    SOLARIS = "SOLARIS"
    AIX = "AIX"
    IRIX = "IRIX"
    FREEBSD = "FREEBSD"
    TRU64 = "TRU64"
    MODESTO = "MODESTO"
    OPENBSD = "OPENBSD"
    OPENVMS = "OPENVMS"
    NSK = "NSK"
    AROS = "AROS"
    FENIXOS = "FENIXOS"
    CLOUD = "CLOUD"
    SORTFIX = "SORTFIX"
    ARM_AEABI = "ARM_AEABI"
    SYLLABLE = "SYLLABLE"
    NACL = "NACL"


def detect_elf_os(f: BinaryIO) -> str:
    f.seek(0x0)
    file_header = f.read(0x40)

    # we'll set this to the detected OS
    # prefer the first heuristics,
    # but rather than short circuiting,
    # we'll still parse out the remainder, for debugging.
    ret = None

    if not file_header.startswith(b"\x7fELF"):
        raise CorruptElfFile("missing magic header")

    ei_class, ei_data = struct.unpack_from("BB", file_header, 4)
    logger.debug("ei_class: 0x%02x ei_data: 0x%02x", ei_class, ei_data)
    if ei_class == 1:
        bitness = 32
    elif ei_class == 2:
        bitness = 64
    else:
        raise CorruptElfFile("invalid ei_class: 0x%02x" % ei_class)

    if ei_data == 1:
        endian = "<"
    elif ei_data == 2:
        endian = ">"
    else:
        raise CorruptElfFile("not an ELF file: invalid ei_data: 0x%02x" % ei_data)

    if bitness == 32:
        (e_phoff,) = struct.unpack_from(endian + "I", file_header, 0x1C)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", file_header, 0x2A)
    elif bitness == 64:
        (e_phoff,) = struct.unpack_from(endian + "Q", file_header, 0x20)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", file_header, 0x36)
    else:
        raise NotImplemented

    logger.debug("e_phoff: 0x%02x e_phentsize: 0x%02x e_phnum: %d", e_phoff, e_phentsize, e_phnum)

    (ei_osabi,) = struct.unpack_from(endian + "B", file_header, 7)
    OSABI = {
        # via pyelftools: https://github.com/eliben/pyelftools/blob/0664de05ed2db3d39041e2d51d19622a8ef4fb0f/elftools/elf/enums.py#L35-L58
        # 0: "SYSV",
        1: OS.HPUX,
        2: OS.NETBSD,
        3: OS.LINUX,
        4: OS.HURD,
        5: OS._86OPEN,
        6: OS.SOLARIS,
        7: OS.AIX,
        8: OS.IRIX,
        9: OS.FREEBSD,
        10: OS.TRU64,
        11: OS.MODESTO,
        12: OS.OPENBSD,
        13: OS.OPENVMS,
        14: OS.NSK,
        15: OS.AROS,
        16: OS.FENIXOS,
        17: OS.CLOUD,
        # 53: "SORTFIX",
        # 64: "ARM_AEABI",
        # 97: "ARM",
        # 255: "STANDALONE",
    }
    logger.debug("ei_osabi: 0x%02x (%s)", ei_osabi, OSABI.get(ei_osabi, "unknown"))

    if ei_osabi in OSABI and ei_osabi != 0x0:
        # update only if not set
        # so we can get the debugging output of subsequent strategies
        ret = OSABI[ei_osabi] if not ret else ret

    f.seek(e_phoff)
    program_header_size = e_phnum * e_phentsize
    program_headers = f.read(program_header_size)
    if len(program_headers) != program_header_size:
        logger.warning("failed to read program headers")
        e_phnum = 0

    for i in range(e_phnum):
        offset = i * e_phentsize
        phent = program_headers[offset : offset + e_phentsize]

        PT_NOTE = 0x4

        (p_type,) = struct.unpack_from(endian + "I", phent, 0x0)
        logger.debug("p_type: 0x%04x", p_type)
        if p_type != PT_NOTE:
            continue

        if bitness == 32:
            p_offset, _, _, p_filesz = struct.unpack_from(endian + "IIII", phent, 0x4)
        elif bitness == 64:
            p_offset, _, _, p_filesz = struct.unpack_from(endian + "QQQQ", phent, 0x8)
        else:
            raise NotImplemented

        logger.debug("p_offset: 0x%02x p_filesz: 0x%04x", p_offset, p_filesz)

        f.seek(p_offset)
        note = f.read(p_filesz)
        if len(note) != p_filesz:
            logger.warning("failed to read note content")
            continue

        namesz, descsz, type_ = struct.unpack_from(endian + "III", note, 0x0)
        name_offset = 0xC
        desc_offset = name_offset + align(namesz, 0x4)

        logger.debug("namesz: 0x%02x descsz: 0x%02x type: 0x%04x", namesz, descsz, type_)

        name = note[name_offset : name_offset + namesz].partition(b"\x00")[0].decode("ascii")
        logger.debug("name: %s", name)

        if type_ != 1:
            continue

        if name == "GNU":
            if descsz < 16:
                continue

            desc = note[desc_offset : desc_offset + descsz]
            abi_tag, kmajor, kminor, kpatch = struct.unpack_from(endian + "IIII", desc, 0x0)
            # via readelf: https://github.com/bminor/binutils-gdb/blob/c0e94211e1ac05049a4ce7c192c9d14d1764eb3e/binutils/readelf.c#L19635-L19658
            # and here: https://github.com/bminor/binutils-gdb/blob/34c54daa337da9fadf87d2706d6a590ae1f88f4d/include/elf/common.h#L933-L939
            GNU_ABI_TAG = {
                0: OS.LINUX,
                1: OS.HURD,
                2: OS.SOLARIS,
                3: OS.FREEBSD,
                4: OS.NETBSD,
                5: OS.SYLLABLE,
                6: OS.NACL,
            }
            logger.debug("GNU_ABI_TAG: 0x%02x", abi_tag)

            if abi_tag in GNU_ABI_TAG:
                # update only if not set
                # so we can get the debugging output of subsequent strategies
                ret = GNU_ABI_TAG[abi_tag] if not ret else ret
                logger.debug("abi tag: %s earliest compatible kernel: %d.%d.%d", ret, kmajor, kminor, kpatch)
        elif name == "OpenBSD":
            logger.debug("note owner: %s", "OPENBSD")
            ret = OS.OPENBSD if not ret else ret
        elif name == "NetBSD":
            logger.debug("note owner: %s", "NETBSD")
            ret = OS.NETBSD if not ret else ret

    for i in range(e_phnum):
        offset = i * e_phentsize
        phent = program_headers[offset : offset + e_phentsize]

        PT_INTERP = 0x3

        (p_type,) = struct.unpack_from(endian + "I", phent, 0x0)
        if p_type != PT_INTERP:
            continue

        if bitness == 32:
            p_offset, _, _, p_filesz = struct.unpack_from(endian + "IIII", phent, 0x4)
        elif bitness == 64:
            p_offset, _, _, p_filesz = struct.unpack_from(endian + "QQQQ", phent, 0x8)
        else:
            raise NotImplemented

        f.seek(p_offset)
        interp = f.read(p_filesz)
        if len(interp) != p_filesz:
            logger.warning("failed to read interp content")
            continue

        linker = interp.partition(b"\x00")[0].decode("ascii")
        logger.debug("linker: %s", linker)
        if "ld-linux" in linker:
            # update only if not set
            # so we can get the debugging output of subsequent strategies
            ret = OS.LINUX if ret is None else ret

    return ret.value if ret is not None else "unknown"


def main(argv=None):
    if IDAIO.is_runtime_ida():
        f: BinaryIO = IDAIO()

    else:
        print("not ida")
        if argv is None:
            argv = sys.argv[1:]

        parser = argparse.ArgumentParser(description="Detect the underlying OS for the given ELF file")
        parser.add_argument("sample", type=str, help="path to ELF file")

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

        f = open(args.sample, "rb")

    with contextlib.closing(f):
        try:
            print(detect_elf_os(f))
            return 0
        except CorruptElfFile as e:
            logger.error("corrupt ELF file: %s", str(e.args[0]))
            return -1


if __name__ == "__main__":
    if IDAIO.is_runtime_ida():
        main()
    else:
        sys.exit(main())
