# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import struct
import logging
import itertools
import collections
from enum import Enum
from typing import Set, Dict, List, Tuple, BinaryIO, Iterator, Optional
from dataclasses import dataclass

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


@dataclass
class Phdr:
    type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    buf: bytes


@dataclass
class Shdr:
    name: int
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int
    buf: bytes


class ELF:
    def __init__(self, f: BinaryIO):
        self.f = f

        # these will all be initialized in `_parse()`
        self.bitness: int
        self.endian: str
        self.e_phentsize: int
        self.e_phnum: int
        self.e_shentsize: int
        self.e_shnum: int
        self.phbuf: bytes
        self.shbuf: bytes

        self._parse()

    def _parse(self):
        self.f.seek(0x0)
        self.file_header = self.f.read(0x40)

        if not self.file_header.startswith(b"\x7fELF"):
            raise CorruptElfFile("missing magic header")

        ei_class, ei_data = struct.unpack_from("BB", self.file_header, 4)
        logger.debug("ei_class: 0x%02x ei_data: 0x%02x", ei_class, ei_data)
        if ei_class == 1:
            self.bitness = 32
        elif ei_class == 2:
            self.bitness = 64
        else:
            raise CorruptElfFile(f"invalid ei_class: 0x{ei_class:02x}")

        if ei_data == 1:
            self.endian = "<"
        elif ei_data == 2:
            self.endian = ">"
        else:
            raise CorruptElfFile(f"not an ELF file: invalid ei_data: 0x{ei_data:02x}")

        if self.bitness == 32:
            e_phoff, e_shoff = struct.unpack_from(self.endian + "II", self.file_header, 0x1C)
            self.e_phentsize, self.e_phnum = struct.unpack_from(self.endian + "HH", self.file_header, 0x2A)
            self.e_shentsize, self.e_shnum = struct.unpack_from(self.endian + "HH", self.file_header, 0x2E)
        elif self.bitness == 64:
            e_phoff, e_shoff = struct.unpack_from(self.endian + "QQ", self.file_header, 0x20)
            self.e_phentsize, self.e_phnum = struct.unpack_from(self.endian + "HH", self.file_header, 0x36)
            self.e_shentsize, self.e_shnum = struct.unpack_from(self.endian + "HH", self.file_header, 0x3A)
        else:
            raise NotImplementedError()

        logger.debug("e_phoff: 0x%02x e_phentsize: 0x%02x e_phnum: %d", e_phoff, self.e_phentsize, self.e_phnum)

        self.f.seek(e_phoff)
        program_header_size = self.e_phnum * self.e_phentsize
        self.phbuf = self.f.read(program_header_size)
        if len(self.phbuf) != program_header_size:
            logger.warning("failed to read program headers")
            self.e_phnum = 0

        self.f.seek(e_shoff)
        section_header_size = self.e_shnum * self.e_shentsize
        self.shbuf = self.f.read(section_header_size)
        if len(self.shbuf) != section_header_size:
            logger.warning("failed to read section headers")
            self.e_shnum = 0

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

    @property
    def ei_osabi(self) -> Optional[OS]:
        (ei_osabi,) = struct.unpack_from(self.endian + "B", self.file_header, 7)
        return ELF.OSABI.get(ei_osabi)

    MACHINE = {
        # via https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
        1: "M32",
        2: "SPARC",
        3: "i386",
        4: "68K",
        5: "88K",
        6: "486",
        7: "860",
        8: "MIPS",
        9: "S370",
        10: "MIPS_RS3_LE",
        11: "RS6000",
        15: "PA_RISC",
        16: "nCUBE",
        17: "VPP500",
        18: "SPARC32PLUS",
        19: "960",
        20: "PPC",
        21: "PPC64",
        22: "S390",
        23: "SPU",
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
        62: "amd64",
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

    @property
    def e_machine(self) -> Optional[str]:
        (e_machine,) = struct.unpack_from(self.endian + "H", self.file_header, 0x12)
        return ELF.MACHINE.get(e_machine)

    def parse_program_header(self, i) -> Phdr:
        phent_offset = i * self.e_phentsize
        phent = self.phbuf[phent_offset : phent_offset + self.e_phentsize]

        (p_type,) = struct.unpack_from(self.endian + "I", phent, 0x0)
        logger.debug("ph:p_type: 0x%04x", p_type)

        if self.bitness == 32:
            p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from(self.endian + "IIII", phent, 0x4)
        elif self.bitness == 64:
            p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from(self.endian + "QQQQ", phent, 0x8)
        else:
            raise NotImplementedError()

        logger.debug("ph:p_offset: 0x%02x p_filesz: 0x%04x", p_offset, p_filesz)

        self.f.seek(p_offset)
        buf = self.f.read(p_filesz)
        if len(buf) != p_filesz:
            raise ValueError("failed to read program header content")

        return Phdr(p_type, p_offset, p_vaddr, p_paddr, p_filesz, buf)

    @property
    def program_headers(self):
        for i in range(self.e_phnum):
            try:
                yield self.parse_program_header(i)
            except ValueError:
                continue

    def parse_section_header(self, i) -> Shdr:
        shent_offset = i * self.e_shentsize
        shent = self.shbuf[shent_offset : shent_offset + self.e_shentsize]

        if self.bitness == 32:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from(
                self.endian + "IIIIIIIIII", shent, 0x0
            )
        elif self.bitness == 64:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from(
                self.endian + "IIQQQQIIQQ", shent, 0x0
            )
        else:
            raise NotImplementedError()

        logger.debug("sh:sh_offset: 0x%02x sh_size: 0x%04x", sh_offset, sh_size)

        self.f.seek(sh_offset)
        buf = self.f.read(sh_size)
        if len(buf) != sh_size:
            raise ValueError("failed to read section header content")

        return Shdr(sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_entsize, buf)

    @property
    def section_headers(self):
        for i in range(self.e_shnum):
            try:
                yield self.parse_section_header(i)
            except ValueError:
                continue

    @property
    def linker(self):
        PT_INTERP = 0x3
        for phdr in self.program_headers:
            if phdr.type != PT_INTERP:
                continue

            return read_cstr(phdr.buf, 0)

    @property
    def versions_needed(self) -> Dict[str, Set[str]]:
        # symbol version requirements are stored in the .gnu.version_r section,
        # which has type SHT_GNU_verneed (0x6ffffffe).
        #
        # this contains a linked list of ElfXX_Verneed structs,
        # each referencing a linked list of ElfXX_Vernaux structs.
        # strings are stored in the section referenced by the sh_link field of the section header.
        # each Verneed struct contains a reference to the name of the library,
        # each Vernaux struct contains a reference to the name of a symbol.
        SHT_GNU_VERNEED = 0x6FFFFFFE
        for shdr in self.section_headers:
            if shdr.type != SHT_GNU_VERNEED:
                continue

            # the linked section contains strings referenced by the verneed structures.
            linked_shdr = self.parse_section_header(shdr.link)

            versions_needed = collections.defaultdict(set)

            # read verneed structures from the start of the section
            # until the vn_next link is 0x0.
            # each entry describes a shared object that is required by this binary.
            vn_offset = 0x0
            while True:
                # ElfXX_Verneed layout is the same on 32 and 64 bit
                vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(
                    self.endian + "HHIII", shdr.buf, vn_offset
                )
                if vn_version != 1:
                    # unexpected format, don't try to keep parsing
                    break

                # shared object names, like: "libdl.so.2"
                so_name = read_cstr(linked_shdr.buf, vn_file)

                # read vernaux structures linked from the verneed structure.
                # there should be vn_cnt of these.
                # each entry describes an ABI name required by the shared object.
                vna_offset = vn_offset + vn_aux
                for i in range(vn_cnt):
                    # ElfXX_Vernaux layout is the same on 32 and 64 bit
                    _, _, _, vna_name, vna_next = struct.unpack_from(self.endian + "IHHII", shdr.buf, vna_offset)

                    # ABI names, like: "GLIBC_2.2.5"
                    abi = read_cstr(linked_shdr.buf, vna_name)
                    versions_needed[so_name].add(abi)

                    vna_offset += vna_next

                vn_offset += vn_next
                if vn_next == 0:
                    break

            return dict(versions_needed)

        return {}

    @property
    def dynamic_entries(self) -> Iterator[Tuple[int, int]]:
        """
        read the entries from the dynamic section,
        yielding the tag and value for each entry.
        """
        DT_NULL = 0x0
        PT_DYNAMIC = 0x2
        for phdr in self.program_headers:
            if phdr.type != PT_DYNAMIC:
                continue

            offset = 0x0
            while True:
                if self.bitness == 32:
                    d_tag, d_val = struct.unpack_from(self.endian + "II", phdr.buf, offset)
                    offset += 8
                elif self.bitness == 64:
                    d_tag, d_val = struct.unpack_from(self.endian + "QQ", phdr.buf, offset)
                    offset += 16
                else:
                    raise NotImplementedError()

                if d_tag == DT_NULL:
                    break

                yield d_tag, d_val

    @property
    def strtab(self) -> Optional[bytes]:
        """
        fetch the bytes of the string table
        referenced by the dynamic section.
        """
        DT_STRTAB = 0x5
        DT_STRSZ = 0xA

        strtab_addr = None
        strtab_size = None

        for d_tag, d_val in self.dynamic_entries:
            if d_tag == DT_STRTAB:
                strtab_addr = d_val

        for d_tag, d_val in self.dynamic_entries:
            if d_tag == DT_STRSZ:
                strtab_size = d_val

        if strtab_addr is None:
            return None

        if strtab_size is None:
            return None

        strtab_offset = None
        for shdr in self.section_headers:
            if shdr.addr <= strtab_addr < shdr.addr + shdr.size:
                strtab_offset = shdr.offset + (strtab_addr - shdr.addr)

        if strtab_offset is None:
            return None

        self.f.seek(strtab_offset)
        strtab_buf = self.f.read(strtab_size)

        if len(strtab_buf) != strtab_size:
            return None

        return strtab_buf

    @property
    def needed(self) -> Iterator[str]:
        """
        read the names of DT_NEEDED entries from the dynamic section,
        which correspond to dependencies on other shared objects,
        like: `libpthread.so.0`
        """
        DT_NEEDED = 0x1
        strtab = self.strtab
        if not strtab:
            return

        for d_tag, d_val in self.dynamic_entries:
            if d_tag != DT_NEEDED:
                continue

            yield read_cstr(strtab, d_val)

    @property
    def symtab(self) -> Optional[Tuple[Shdr, Shdr]]:
        """
        fetch the Shdr for the symtab and the associated strtab.
        """
        SHT_SYMTAB = 0x2
        for shdr in self.section_headers:
            if shdr.type != SHT_SYMTAB:
                continue

            # the linked section contains strings referenced by the symtab structures.
            strtab_shdr = self.parse_section_header(shdr.link)

            return shdr, strtab_shdr

        return None


@dataclass
class ABITag:
    os: OS
    kmajor: int
    kminor: int
    kpatch: int


class PHNote:
    def __init__(self, endian: str, buf: bytes):
        self.endian = endian
        self.buf = buf

        # these will be initialized in `_parse()`
        self.type_: int
        self.descsz: int
        self.name: str

        self._parse()

    def _parse(self):
        namesz, self.descsz, self.type_ = struct.unpack_from(self.endian + "III", self.buf, 0x0)
        name_offset = 0xC
        self.desc_offset = name_offset + align(namesz, 0x4)

        logger.debug("ph:namesz: 0x%02x descsz: 0x%02x type: 0x%04x", namesz, self.descsz, self.type_)

        self.name = self.buf[name_offset : name_offset + namesz].partition(b"\x00")[0].decode("ascii")
        logger.debug("name: %s", self.name)

    @property
    def abi_tag(self) -> Optional[ABITag]:
        if self.type_ != 1:
            # > The type field shall be 1.
            # Linux Standard Base Specification 1.2
            # ref: https://refspecs.linuxfoundation.org/LSB_1.2.0/gLSB/noteabitag.html
            return None

        if self.name != "GNU":
            return None

        if self.descsz < 16:
            return None

        desc = self.buf[self.desc_offset : self.desc_offset + self.descsz]
        abi_tag, kmajor, kminor, kpatch = struct.unpack_from(self.endian + "IIII", desc, 0x0)
        logger.debug("GNU_ABI_TAG: 0x%02x", abi_tag)

        os = GNU_ABI_TAG.get(abi_tag)
        if not os:
            return None

        logger.debug("abi tag: %s earliest compatible kernel: %d.%d.%d", os, kmajor, kminor, kpatch)

        return ABITag(os, kmajor, kminor, kpatch)


class SHNote:
    def __init__(self, endian: str, buf: bytes):
        self.endian = endian
        self.buf = buf

        # these will be initialized in `_parse()`
        self.type_: int
        self.descsz: int
        self.name: str

        self._parse()

    def _parse(self):
        namesz, self.descsz, self.type_ = struct.unpack_from(self.endian + "III", self.buf, 0x0)
        name_offset = 0xC
        self.desc_offset = name_offset + align(namesz, 0x4)

        logger.debug("sh:namesz: 0x%02x descsz: 0x%02x type: 0x%04x", namesz, self.descsz, self.type_)

        name_buf = self.buf[name_offset : name_offset + namesz]
        self.name = read_cstr(name_buf, 0x0)
        logger.debug("sh:name: %s", self.name)

    @property
    def abi_tag(self) -> Optional[ABITag]:
        if self.name != "GNU":
            return None

        if self.descsz < 16:
            return None

        desc = self.buf[self.desc_offset : self.desc_offset + self.descsz]
        abi_tag, kmajor, kminor, kpatch = struct.unpack_from(self.endian + "IIII", desc, 0x0)
        logger.debug("GNU_ABI_TAG: 0x%02x", abi_tag)

        os = GNU_ABI_TAG.get(abi_tag)
        if not os:
            return None

        logger.debug("abi tag: %s earliest compatible kernel: %d.%d.%d", os, kmajor, kminor, kpatch)
        return ABITag(os, kmajor, kminor, kpatch)


@dataclass
class Symbol:
    name_offset: int
    value: int
    size: int
    info: int
    other: int
    shndx: int


class SymTab:
    def __init__(
        self,
        endian: str,
        bitness: int,
        symtab: Shdr,
        strtab: Shdr,
    ) -> None:
        self.symbols: List[Symbol] = []

        self.symtab = symtab
        self.strtab = strtab

        self._parse(endian, bitness, symtab.buf)

    def _parse(self, endian: str, bitness: int, symtab_buf: bytes) -> None:
        """
        return the symbol's information in
        the order specified by sys/elf32.h
        """
        for i in range(int(len(self.symtab.buf) / self.symtab.entsize)):
            if bitness == 32:
                name_offset, value, size, info, other, shndx = struct.unpack_from(
                    endian + "IIIBBH", symtab_buf, i * self.symtab.entsize
                )
            elif bitness == 64:
                name_offset, info, other, shndx, value, size = struct.unpack_from(
                    endian + "IBBBQQ", symtab_buf, i * self.symtab.entsize
                )

            self.symbols.append(Symbol(name_offset, value, size, info, other, shndx))

    def get_name(self, symbol: Symbol) -> str:
        """
        fetch a symbol's name from symtab's
        associated strings' section (SHT_STRTAB)
        """
        if not self.strtab:
            raise ValueError("no strings found")

        for i in range(symbol.name_offset, self.strtab.size):
            if self.strtab.buf[i] == 0:
                return self.strtab.buf[symbol.name_offset : i].decode("utf-8")

        raise ValueError("symbol name not found")

    def get_symbols(self) -> Iterator[Symbol]:
        """
        return a tuple: (name, value, size, info, other, shndx)
        for each symbol contained in the symbol table
        """
        for symbol in self.symbols:
            yield symbol


def guess_os_from_osabi(elf: ELF) -> Optional[OS]:
    return elf.ei_osabi


def guess_os_from_ph_notes(elf: ELF) -> Optional[OS]:
    # search for PT_NOTE sections that specify an OS
    # for example, on Linux there is a GNU section with minimum kernel version
    PT_NOTE = 0x4
    for phdr in elf.program_headers:
        if phdr.type != PT_NOTE:
            continue

        note = PHNote(elf.endian, phdr.buf)

        if note.type_ != 1:
            # > The type field shall be 1.
            # Linux Standard Base Specification 1.2
            # ref: https://refspecs.linuxfoundation.org/LSB_1.2.0/gLSB/noteabitag.html
            continue

        if note.name == "Linux":
            logger.debug("note owner: %s", "LINUX")
            return OS.LINUX
        elif note.name == "OpenBSD":
            logger.debug("note owner: %s", "OPENBSD")
            return OS.OPENBSD
        elif note.name == "NetBSD":
            logger.debug("note owner: %s", "NETBSD")
            return OS.NETBSD
        elif note.name == "FreeBSD":
            logger.debug("note owner: %s", "FREEBSD")
            return OS.FREEBSD
        elif note.name == "GNU":
            abi_tag = note.abi_tag
            if abi_tag:
                return abi_tag.os
            else:
                # cannot make a guess about the OS, but probably linux or hurd
                pass

    return None


def guess_os_from_sh_notes(elf: ELF) -> Optional[OS]:
    # search for notes stored in sections that aren't visible in program headers.
    # e.g. .note.Linux in Linux kernel modules.
    SHT_NOTE = 0x7
    for shdr in elf.section_headers:
        if shdr.type != SHT_NOTE:
            continue

        note = SHNote(elf.endian, shdr.buf)

        if note.name == "Linux":
            logger.debug("note owner: %s", "LINUX")
            return OS.LINUX
        elif note.name == "OpenBSD":
            logger.debug("note owner: %s", "OPENBSD")
            return OS.OPENBSD
        elif note.name == "NetBSD":
            logger.debug("note owner: %s", "NETBSD")
            return OS.NETBSD
        elif note.name == "FreeBSD":
            logger.debug("note owner: %s", "FREEBSD")
            return OS.FREEBSD
        elif note.name == "GNU":
            abi_tag = note.abi_tag
            if abi_tag:
                return abi_tag.os
            else:
                # cannot make a guess about the OS, but probably linux or hurd
                pass

    return None


def guess_os_from_linker(elf: ELF) -> Optional[OS]:
    # search for recognizable dynamic linkers (interpreters)
    # for example, on linux, we see file paths like: /lib64/ld-linux-x86-64.so.2
    linker = elf.linker
    if linker and "ld-linux" in elf.linker:
        return OS.LINUX

    return None


def guess_os_from_abi_versions_needed(elf: ELF) -> Optional[OS]:
    # then lets look for GLIBC symbol versioning requirements.
    # this will let us guess about linux/hurd in some cases.

    versions_needed = elf.versions_needed
    if any(map(lambda abi: abi.startswith("GLIBC"), itertools.chain(*versions_needed.values()))):
        # there are any GLIBC versions needed

        if elf.e_machine != "i386":
            # GLIBC runs on Linux and Hurd.
            # for Hurd, its *only* on i386.
            # so if we're not on i386, then we're on Linux.
            return OS.LINUX

        else:
            # we're on i386, so we could be on either Linux or Hurd.
            linker = elf.linker

            if linker and "ld-linux" in linker:
                return OS.LINUX

            elif linker and "/ld.so" in linker:
                return OS.HURD

            else:
                # we don't have any good guesses based on versions needed
                pass

    return None


def guess_os_from_needed_dependencies(elf: ELF) -> Optional[OS]:
    for needed in elf.needed:
        if needed.startswith("libmachuser.so"):
            return OS.HURD
        if needed.startswith("libhurduser.so"):
            return OS.HURD

    return None


def guess_os_from_symtab(elf: ELF) -> Optional[OS]:
    shdrs = elf.symtab
    if not shdrs:
        # executable does not contain a symbol table
        # or the symbol's names are stripped
        return None

    symtab_shdr, strtab_shdr = shdrs
    symtab = SymTab(elf.endian, elf.bitness, symtab_shdr, strtab_shdr)

    keywords = {
        OS.LINUX: [
            "linux",
            "/linux/",
        ],
    }

    for symbol in symtab.get_symbols():
        sym_name = symtab.get_name(symbol)

        for os, hints in keywords.items():
            if any(map(lambda x: x in sym_name, hints)):
                return os

    return None


def detect_elf_os(f) -> str:
    """
    f: type Union[BinaryIO, IDAIO]
    """
    elf = ELF(f)

    osabi_guess = guess_os_from_osabi(elf)
    logger.debug("guess: osabi: %s", osabi_guess)

    ph_notes_guess = guess_os_from_ph_notes(elf)
    logger.debug("guess: ph notes: %s", ph_notes_guess)

    sh_notes_guess = guess_os_from_sh_notes(elf)
    logger.debug("guess: sh notes: %s", sh_notes_guess)

    linker_guess = guess_os_from_linker(elf)
    logger.debug("guess: linker: %s", linker_guess)

    abi_versions_needed_guess = guess_os_from_abi_versions_needed(elf)
    logger.debug("guess: ABI versions needed: %s", abi_versions_needed_guess)

    needed_dependencies_guess = guess_os_from_needed_dependencies(elf)
    logger.debug("guess: needed dependencies: %s", needed_dependencies_guess)

    symtab_guess = guess_os_from_symtab(elf)
    logger.debug("guess: pertinent symbol name: %s", symtab_guess)

    ret = None

    if osabi_guess:
        ret = osabi_guess

    elif ph_notes_guess:
        ret = ph_notes_guess

    elif sh_notes_guess:
        ret = sh_notes_guess

    elif linker_guess:
        ret = linker_guess

    elif abi_versions_needed_guess:
        ret = abi_versions_needed_guess

    elif needed_dependencies_guess:
        ret = needed_dependencies_guess

    elif symtab_guess:
        ret = symtab_guess

    return ret.value if ret is not None else "unknown"


def detect_elf_arch(f: BinaryIO) -> str:
    return ELF(f).e_machine or "unknown"
