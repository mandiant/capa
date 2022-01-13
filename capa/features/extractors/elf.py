# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import struct
import logging
from enum import Enum
from typing import BinaryIO

logger = logging.getLogger(__name__)


def align(v, alignment):
    remainder = v % alignment
    if remainder == 0:
        return v
    else:
        return v + (alignment - remainder)


class CorruptElfFile(ValueError):
    pass


class OS(str, Enum):
    HPUX = "hpux"
    NETBSD = "netbsd"
    LINUX = "linux"
    HURD = "hurd"
    _86OPEN = "86open"
    SOLARIS = "solaris"
    AIX = "aix"
    IRIX = "irix"
    FREEBSD = "freebsd"
    TRU64 = "tru64"
    MODESTO = "modesto"
    OPENBSD = "openbsd"
    OPENVMS = "openvms"
    NSK = "nsk"
    AROS = "aros"
    FENIXOS = "fenixos"
    CLOUD = "cloud"
    SYLLABLE = "syllable"
    NACL = "nacl"


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
        (e_phoff, e_shoff) = struct.unpack_from(endian + "II", file_header, 0x1C)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", file_header, 0x2A)
        e_shentsize, e_shnum = struct.unpack_from(endian + "HH", file_header, 0x2E)
    elif bitness == 64:
        (e_phoff, e_shoff) = struct.unpack_from(endian + "QQ", file_header, 0x20)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", file_header, 0x36)
        e_shentsize, e_shnum = struct.unpack_from(endian + "HH", file_header, 0x3A)
    else:
        raise NotImplementedError()

    logger.debug("e_phoff: 0x%02x e_phentsize: 0x%02x e_phnum: %d", e_phoff, e_phentsize, e_phnum)

    (ei_osabi,) = struct.unpack_from(endian + "B", file_header, 7)
    OSABI = {
        # via pyelftools: https://github.com/eliben/pyelftools/blob/0664de05ed2db3d39041e2d51d19622a8ef4fb0f/elftools/elf/enums.py#L35-L58
        # some candidates are commented out because the are not useful values,
        # at least when guessing OSes
        # 0: "SYSV",  # too often used when OS is not SYSV
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
        # 53: "SORTFIX",      # i can't find any reference to this OS, i dont think it exists
        # 64: "ARM_AEABI",    # not an OS
        # 97: "ARM",          # not an OS
        # 255: "STANDALONE",  # not an OS
    }
    logger.debug("ei_osabi: 0x%02x (%s)", ei_osabi, OSABI.get(ei_osabi, "unknown"))

    # os_osabi == 0 is commonly set even when the OS is not SYSV.
    # other values are unused or unknown.
    if ei_osabi in OSABI and ei_osabi != 0x0:
        # subsequent strategies may overwrite this value
        ret = OSABI[ei_osabi]

    f.seek(e_phoff)
    program_header_size = e_phnum * e_phentsize
    program_headers = f.read(program_header_size)
    if len(program_headers) != program_header_size:
        logger.warning("failed to read program headers")
        e_phnum = 0

    # search for PT_NOTE sections that specify an OS
    # for example, on Linux there is a GNU section with minimum kernel version
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
            raise NotImplementedError()

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
        elif name == "FreeBSD":
            logger.debug("note owner: %s", "FREEBSD")
            ret = OS.FREEBSD if not ret else ret

    # search for recognizable dynamic linkers (interpreters)
    # for example, on linux, we see file paths like: /lib64/ld-linux-x86-64.so.2
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
            raise NotImplementedError()

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

    f.seek(e_shoff)
    section_header_size = e_shnum * e_shentsize
    section_headers = f.read(section_header_size)
    if len(section_headers) != section_header_size:
        logger.warning("failed to read section headers")
        e_shnum = 0

    # search for notes stored in sections that aren't visible in program headers.
    # e.g. .note.Linux in Linux kernel modules.
    for i in range(e_shnum):
        offset = i * e_shentsize
        shent = section_headers[offset : offset + e_shentsize]

        if bitness == 32:
            sh_name, sh_type, _, sh_addr, sh_offset, sh_size = struct.unpack_from(endian + "IIIIII", shent, 0x0)
        elif bitness == 64:
            sh_name, sh_type, _, sh_addr, sh_offset, sh_size = struct.unpack_from(endian + "IIQQQQ", shent, 0x0)
        else:
            raise NotImplementedError()

        SHT_NOTE = 0x7
        if sh_type != SHT_NOTE:
            continue

        logger.debug("sh_offset: 0x%02x sh_size: 0x%04x", sh_offset, sh_size)

        f.seek(sh_offset)
        note = f.read(sh_size)
        if len(note) != sh_size:
            logger.warning("failed to read note content")
            continue

        namesz, descsz, type_ = struct.unpack_from(endian + "III", note, 0x0)
        name_offset = 0xC
        desc_offset = name_offset + align(namesz, 0x4)

        logger.debug("namesz: 0x%02x descsz: 0x%02x type: 0x%04x", namesz, descsz, type_)

        name = note[name_offset : name_offset + namesz].partition(b"\x00")[0].decode("ascii")
        logger.debug("name: %s", name)

        if name == "Linux":
            logger.debug("note owner: %s", "LINUX")
            ret = OS.LINUX if not ret else ret

    return ret.value if ret is not None else "unknown"


class Arch(str, Enum):
    I386 = "i386"
    AMD64 = "amd64"


def detect_elf_arch(f: BinaryIO) -> str:
    f.seek(0x0)
    file_header = f.read(0x40)

    if not file_header.startswith(b"\x7fELF"):
        raise CorruptElfFile("missing magic header")

    (ei_data,) = struct.unpack_from("B", file_header, 5)
    logger.debug("ei_data: 0x%02x", ei_data)

    if ei_data == 1:
        endian = "<"
    elif ei_data == 2:
        endian = ">"
    else:
        raise CorruptElfFile("not an ELF file: invalid ei_data: 0x%02x" % ei_data)

    (ei_machine,) = struct.unpack_from(endian + "H", file_header, 0x12)
    logger.debug("ei_machine: 0x%02x", ei_machine)

    EM_386 = 0x3
    EM_X86_64 = 0x3E
    if ei_machine == EM_386:
        return Arch.I386
    elif ei_machine == EM_X86_64:
        return Arch.AMD64
    else:
        # not really unknown, but unsupport at the moment:
        # https://github.com/eliben/pyelftools/blob/ab444d982d1849191e910299a985989857466620/elftools/elf/enums.py#L73
        return "unknown"
