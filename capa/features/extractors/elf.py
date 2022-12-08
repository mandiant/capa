# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import struct
import logging
import collections
from enum import Enum
from typing import BinaryIO

logger = logging.getLogger(__name__)


def align(v, alignment):
    remainder = v % alignment
    if remainder == 0:
        return v
    else:
        return v + (alignment - remainder)


def read_cstr(buf, offset):
    s = buf[offset:]
    s, _, _ = s.partition(b"\x00")
    return s.decode("utf-8")


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


def detect_elf_os(f) -> str:
    """
    f: type Union[BinaryIO, IDAIO]
    """
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

    (e_machine,) = struct.unpack_from(endian + "H", file_header, 0x12)
    MACHINE = {
        0: "None",
        1: "M32",
        2: "SPARC",
        3: "386",
        4: "68K",
        5: "88K",
        6: "486",
        7: "860",
        8: "MIPS",
        9: "S370",
        10: "MIPS_RS3_LE",
        11: "RS6000",
        12: "UNKNOWN12",
        13: "UNKNOWN13",
        14: "UNKNOWN14",
        15: "PA_RISC",
        16: "nCUBE",
        17: "VPP500",
        18: "SPARC32PLUS",
        19: "960",
        20: "PPC",
        21: "PPC64",
        22: "S390",
        23: "SPU",
        24: "UNKNOWN24",
        25: "UNKNOWN25",
        26: "UNKNOWN26",
        27: "UNKNOWN27",
        28: "UNKNOWN28",
        29: "UNKNOWN29",
        30: "UNKNOWN30",
        31: "UNKNOWN31",
        32: "UNKNOWN32",
        33: "UNKNOWN33",
        34: "UNKNOWN34",
        35: "UNKNOWN35",
        36: "V800",
        37: "FR20",
        38: "RH32",
        39: "RCE",
        40: "ARM",
        41: "ALPHA",
        42: "SH",
        43: "SPARCV9",
        44: "TRICORE",
        45: "ARC",
        46: "H8_300",
        47: "H8_300H",
        48: "H8S",
        49: "H8_500",
        50: "IA_64",
        51: "MIPS_X",
        52: "COLDFIRE",
        53: "68HC12",
        54: "MMA",
        55: "PCP",
        56: "NCPU",
        57: "NDR1",
        58: "STARCORE",
        59: "ME16",
        60: "ST100",
        61: "TINYJ",
        62: "X86_64",
        63: "PDSP",
        64: "PDP10",
        65: "PDP11",
        66: "FX66",
        67: "ST9PLUS",
        68: "ST7",
        69: "68HC16",
        70: "68HC11",
        71: "68HC08",
        72: "68HC05",
        73: "SVX",
        74: "ST19",
        75: "VAX",
        76: "CRIS",
        77: "JAVELIN",
        78: "FIREPATH",
        79: "ZSP",
        80: "MMIX",
        81: "HUANY",
        82: "PRISM",
        83: "AVR",
        84: "FR30",
        85: "D10V",
        86: "D30V",
        87: "V850",
        88: "M32R",
        89: "MN10300",
        90: "MN10200",
        91: "PJ",
        92: "OPENRISC",
        93: "ARC_A5",
        94: "XTENSA",
        95: "VIDEOCORE",
        96: "TMM_GPP",
        97: "NS32K",
        98: "TPC",
        99: "SNP1K",
        100: "ST200",
    }
    logger.debug("emachine: 0x%02x (%s)", e_machine, MACHINE.get(e_machine, "unknown"))
 
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
        logger.debug("ph:p_type: 0x%04x", p_type)
        if p_type != PT_NOTE:
            continue

        if bitness == 32:
            p_offset, _, _, p_filesz = struct.unpack_from(endian + "IIII", phent, 0x4)
        elif bitness == 64:
            p_offset, _, _, p_filesz = struct.unpack_from(endian + "QQQQ", phent, 0x8)
        else:
            raise NotImplementedError()

        logger.debug("ph:p_offset: 0x%02x p_filesz: 0x%04x", p_offset, p_filesz)

        f.seek(p_offset)
        version_r = f.read(p_filesz)
        if len(version_r) != p_filesz:
            logger.warning("failed to read note content")
            continue

        namesz, descsz, type_ = struct.unpack_from(endian + "III", version_r, 0x0)
        name_offset = 0xC
        desc_offset = name_offset + align(namesz, 0x4)

        logger.debug("ph:namesz: 0x%02x descsz: 0x%02x type: 0x%04x", namesz, descsz, type_)

        name = version_r[name_offset : name_offset + namesz].partition(b"\x00")[0].decode("ascii")
        logger.debug("name: %s", name)

        if type_ != 1:
            continue

        if name == "GNU":
            if descsz < 16:
                continue

            desc = version_r[desc_offset : desc_offset + descsz]
            abi_tag, kmajor, kminor, kpatch = struct.unpack_from(endian + "IIII", desc, 0x0)
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
    linker = None
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
            sh_name, sh_type, _, sh_addr, linked_sh_offset, linked_sh_size = struct.unpack_from(endian + "IIIIII", shent, 0x0)
        elif bitness == 64:
            sh_name, sh_type, _, sh_addr, linked_sh_offset, linked_sh_size = struct.unpack_from(endian + "IIQQQQ", shent, 0x0)
        else:
            raise NotImplementedError()

        SHT_NOTE = 0x7
        if sh_type != SHT_NOTE:
            continue

        logger.debug("sh:sh_offset: 0x%02x sh_size: 0x%04x", linked_sh_offset, linked_sh_size)

        f.seek(linked_sh_offset)
        version_r = f.read(linked_sh_size)
        if len(version_r) != linked_sh_size:
            logger.warning("failed to read note content")
            continue

        namesz, descsz, type_ = struct.unpack_from(endian + "III", version_r, 0x0)
        name_offset = 0xC
        desc_offset = name_offset + align(namesz, 0x4)

        logger.debug("sh:namesz: 0x%02x descsz: 0x%02x type: 0x%04x", namesz, descsz, type_)

        name = version_r[name_offset : name_offset + namesz].partition(b"\x00")[0].decode("ascii")
        logger.debug("name: %s", name)

        if name == "Linux":
            logger.debug("note owner: %s", "LINUX")
            ret = OS.LINUX if not ret else ret
        elif name == "OpenBSD":
            logger.debug("note owner: %s", "OPENBSD")
            ret = OS.OPENBSD if not ret else ret
        elif name == "NetBSD":
            logger.debug("note owner: %s", "NETBSD")
            ret = OS.NETBSD if not ret else ret
        elif name == "FreeBSD":
            logger.debug("note owner: %s", "FREEBSD")
            ret = OS.FREEBSD if not ret else ret
        elif name == "GNU":
            if descsz < 16:
                continue

            desc = version_r[desc_offset : desc_offset + descsz]
            abi_tag, kmajor, kminor, kpatch = struct.unpack_from(endian + "IIII", desc, 0x0)
            logger.debug("GNU_ABI_TAG: 0x%02x", abi_tag)

            if abi_tag in GNU_ABI_TAG:
                # update only if not set
                # so we can get the debugging output of subsequent strategies
                ret = GNU_ABI_TAG[abi_tag] if not ret else ret
                logger.debug("abi tag: %s earliest compatible kernel: %d.%d.%d", ret, kmajor, kminor, kpatch)

    if not ret:
        # if we don't have any guesses yet,
        # then lets look for GLIBC symbol versioning requirements.
        # this will let us guess about linux/hurd in some cases.
        #
        # symbol version requirements are stored in the .gnu.version_r section,
        # which has type SHT_GNU_verneed (0x6ffffffe).
        #
        # this contains a linked list of ElfXX_Verneed structs,
        # each referencing a linked list of ElfXX_Vernaux structs.
        # strings are stored in the section referenced by the sh_link field of the section header.
        # each Verneed struct contains a reference to the name of the library,
        # each Vernaux struct contains a reference to the name of a symbol.
        for i in range(e_shnum):
            offset = i * e_shentsize
            shent = section_headers[offset : offset + e_shentsize]

            if bitness == 32:
                sh_name, sh_type, _, sh_addr, sh_offset, sh_size, sh_link = struct.unpack_from(endian + "IIIIIII", shent, 0x0)
            elif bitness == 64:
                sh_name, sh_type, _, sh_addr, sh_offset, sh_size, sh_link = struct.unpack_from(endian + "IIQQQQI", shent, 0x0)
            else:
                raise NotImplementedError()

            SHT_GNU_VERNEED = 0x6ffffffe
            if sh_type != SHT_GNU_VERNEED:
                continue

            logger.debug("sh:sh_offset: 0x%02x sh_size: 0x%04x", sh_offset, sh_size)

            # read the section containing the verneed structures
            f.seek(sh_offset)
            version_r = f.read(sh_size)
            if len(version_r) != sh_size:
                logger.warning("failed to read .gnu.version_r content")
                continue

            # read the linked section content
            # which contains strings referenced by the verneed structures
            linked_shent_offset = sh_link * e_shentsize
            linked_shent = section_headers[linked_shent_offset : linked_shent_offset + e_shentsize]

            if bitness == 32:
                _, _, _, _, linked_sh_offset, linked_sh_size = struct.unpack_from(endian + "IIIIII", linked_shent, 0x0)
            elif bitness == 64:
                _, _, _, _, linked_sh_offset, linked_sh_size = struct.unpack_from(endian + "IIQQQQ", linked_shent, 0x0)
            else:
                raise NotImplementedError()

            f.seek(linked_sh_offset)
            linked_sh = f.read(linked_sh_size)
            if len(linked_sh) != linked_sh_size:
                logger.warning("failed to read linked content")
                continue

            so_abis = collections.defaultdict(set)

            # read verneed structures from the start of the section
            # until the vn_next link is 0x0.
            # each entry describes a shared object that is required by this binary.
            vn_offset = 0x0
            while True:
                # ElfXX_Verneed layout is the same on 32 and 64 bit
                vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(endian + "HHIII", version_r, vn_offset)
                if vn_version != 1:
                    # unexpected format, don't try to keep parsing
                    break

                # shared object names, like: "libdl.so.2"
                so_name = read_cstr(linked_sh, vn_file)

                # read vernaux structures linked from the verneed structure.
                # there should be vn_cnt of these.
                # each entry describes an ABI name required by the shared object.
                vna_offset = vn_offset + vn_aux
                for i in range(vn_cnt):
                    # ElfXX_Vernaux layout is the same on 32 and 64 bit
                    _, _, _, vna_name, vna_next = struct.unpack_from(endian + "IHHII", version_r, vna_offset)

                    # ABI names, like: "GLIBC_2.2.5"
                    abi = read_cstr(linked_sh, vna_name)
                    so_abis[so_name].add(abi)

                    vna_offset += vna_next

                vn_offset += vn_next
                if vn_next == 0:
                    break

            has_glibc_verneed = False
            for so_name, abis in so_abis.items():
                for abi in abis:
                    if abi.startswith("GLIBC"):
                        has_glibc_verneed = True

            if has_glibc_verneed:
                if MACHINE.get(e_machine) != "386":
                    ret = OS.LINUX

                # TODO: check dynamic sections for libmachuser and libhurduser

                if linker and "ld-linux" in linker:
                    ret = OS.LINUX

                if linker and "/ld.so" in linker:
                    ret = OS.HURD

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
