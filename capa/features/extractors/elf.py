# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
import logging
import itertools
import collections
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO, Iterator, Optional
from dataclasses import dataclass

if TYPE_CHECKING:
    import Elf  # from vivisect

logger = logging.getLogger(__name__)


def align(v, alignment):
    remainder = v % alignment
    if remainder == 0:
        return v
    else:
        return v + (alignment - remainder)


def read_cstr(buf, offset) -> str:
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
    ANDROID = "android"
    DRAGONFLYBSD = "dragonfly BSD"
    ILLUMOS = "illumos"
    ZOS = "z/os"
    UNIX = "unix"


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
    flags: int
    memsz: int


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

    @classmethod
    def from_viv(cls, section, buf: bytes) -> "Shdr":
        return cls(
            section.sh_name,
            section.sh_type,
            section.sh_flags,
            section.sh_addr,
            section.sh_offset,
            section.sh_size,
            section.sh_link,
            section.sh_entsize,
            buf,
        )

    def get_name(self, elf: "ELF") -> str:
        return elf.shstrtab.buf[self.name :].partition(b"\x00")[0].decode("ascii")


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
        self.e_shstrndx: int
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
            self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from(
                self.endian + "HHH", self.file_header, 0x2E
            )
        elif self.bitness == 64:
            e_phoff, e_shoff = struct.unpack_from(self.endian + "QQ", self.file_header, 0x20)
            self.e_phentsize, self.e_phnum = struct.unpack_from(self.endian + "HH", self.file_header, 0x36)
            self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from(
                self.endian + "HHH", self.file_header, 0x3A
            )
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
        # 53: "SORTFIX",      # i can't find any reference to this OS, i don't think it exists
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
        # https://www.sco.com/developers/gabi/latest/ch4.eheader.html
        183: "aarch64",
        243: "riscv",
    }

    @property
    def e_machine(self) -> Optional[str]:
        (e_machine,) = struct.unpack_from(self.endian + "H", self.file_header, 0x12)
        return ELF.MACHINE.get(e_machine)

    def parse_program_header(self, i) -> Phdr:
        phent_offset = i * self.e_phentsize
        phent = self.phbuf[phent_offset : phent_offset + self.e_phentsize]

        if self.bitness == 32:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags = struct.unpack_from(
                self.endian + "IIIIIII", phent, 0x0
            )
        elif self.bitness == 64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from(
                self.endian + "IIQQQQQ", phent, 0x0
            )
        else:
            raise NotImplementedError()

        self.f.seek(p_offset)
        buf = self.f.read(p_filesz)
        if len(buf) != p_filesz:
            raise ValueError("failed to read program header content")

        return Phdr(p_type, p_offset, p_vaddr, p_paddr, p_filesz, buf, p_flags, p_memsz)

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
    def shstrtab(self) -> Shdr:
        return self.parse_section_header(self.e_shstrndx)

    @property
    def linker(self):
        PT_INTERP = 0x3
        for phdr in self.program_headers:
            if phdr.type != PT_INTERP:
                continue

            return read_cstr(phdr.buf, 0)

    @property
    def versions_needed(self) -> dict[str, set[str]]:
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
                for _ in range(vn_cnt):
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
    def dynamic_entries(self) -> Iterator[tuple[int, int]]:
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
                break

        for d_tag, d_val in self.dynamic_entries:
            if d_tag == DT_STRSZ:
                strtab_size = d_val
                break

        if strtab_addr is None:
            return None

        if strtab_size is None:
            return None

        strtab_offset = None
        for shdr in self.section_headers:
            # the section header address should be defined
            if shdr.addr and shdr.addr <= strtab_addr < shdr.addr + shdr.size:
                strtab_offset = shdr.offset + (strtab_addr - shdr.addr)
                break

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

            try:
                yield read_cstr(strtab, d_val)
            except UnicodeDecodeError as e:
                logger.warning("failed to read DT_NEEDED entry: %s", str(e))

    @property
    def symtab(self) -> Optional[tuple[Shdr, Shdr]]:
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
        self.symbols: list[Symbol] = []

        self.symtab = symtab
        self.strtab = strtab

        self._parse(endian, bitness, symtab.buf)

    def _parse(self, endian: str, bitness: int, symtab_buf: bytes) -> None:
        """
        return the symbol's information in
        the order specified by sys/elf32.h
        """
        if self.symtab.entsize == 0:
            return

        for i in range(int(len(self.symtab.buf) / self.symtab.entsize)):
            if bitness == 32:
                name_offset, value, size, info, other, shndx = struct.unpack_from(
                    endian + "IIIBBH", symtab_buf, i * self.symtab.entsize
                )
            elif bitness == 64:
                name_offset, info, other, shndx, value, size = struct.unpack_from(
                    endian + "IBBHQQ", symtab_buf, i * self.symtab.entsize
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
        yield from self.symbols

    @classmethod
    def from_viv(cls, elf: "Elf.Elf") -> Optional["SymTab"]:
        endian = "<" if elf.getEndian() == 0 else ">"
        bitness = elf.bits

        SHT_SYMTAB = 0x2
        for section in elf.sections:
            if section.sh_type == SHT_SYMTAB:
                strtab_section = elf.sections[section.sh_link]
                sh_symtab = Shdr.from_viv(section, elf.readAtOffset(section.sh_offset, section.sh_size))
                sh_strtab = Shdr.from_viv(
                    strtab_section, elf.readAtOffset(strtab_section.sh_offset, strtab_section.sh_size)
                )

        try:
            return cls(endian, bitness, sh_symtab, sh_strtab)
        except NameError:
            return None
        except Exception:
            # all exceptions that could be encountered by
            # cls._parse() imply a faulty symbol's table.
            raise CorruptElfFile("malformed symbol's table")


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
        elif note.name == "Android":
            logger.debug("note owner: %s", "Android")
            # see the following for parsing the structure:
            # https://android.googlesource.com/platform/ndk/+/master/parse_elfnote.py
            return OS.ANDROID
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


def guess_os_from_ident_directive(elf: ELF) -> Optional[OS]:
    # GCC inserts the GNU version via an .ident directive
    # that gets stored in a section named ".comment".
    # look at the version and recognize common OSes.
    #
    # assume the GCC version matches the target OS version,
    # which I guess could be wrong during cross-compilation?
    # therefore, don't rely on this if possible.
    #
    # https://stackoverflow.com/q/6263425
    # https://gcc.gnu.org/onlinedocs/cpp/Other-Directives.html

    SHT_PROGBITS = 0x1
    for shdr in elf.section_headers:
        if shdr.type != SHT_PROGBITS:
            continue

        if shdr.get_name(elf) != ".comment":
            continue

        try:
            comment = shdr.buf.decode("utf-8")
        except ValueError:
            continue

        if "GCC:" not in comment:
            continue

        logger.debug(".ident: %s", comment)

        # these values come from our testfiles, like:
        # rg -a "GCC: " tests/data/
        if "Debian" in comment:
            return OS.LINUX
        elif "Ubuntu" in comment:
            return OS.LINUX
        elif "Red Hat" in comment:
            return OS.LINUX
        elif "Alpine" in comment:
            return OS.LINUX
        elif "Android" in comment:
            return OS.ANDROID

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
    if any(abi.startswith("GLIBC") for abi in itertools.chain(*versions_needed.values())):
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
                # in practice, Hurd isn't a common/viable OS,
                # so this is almost certain to be Linux,
                # so lets just make that guess.
                return OS.LINUX

    return None


def guess_os_from_needed_dependencies(elf: ELF) -> Optional[OS]:
    for needed in elf.needed:
        if needed.startswith("libmachuser.so"):
            return OS.HURD
        if needed.startswith("libhurduser.so"):
            return OS.HURD
        if needed.startswith("libandroid.so"):
            return OS.ANDROID
        if needed.startswith("liblog.so"):
            return OS.ANDROID

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
            if any(hint in sym_name for hint in hints):
                logger.debug("symtab: %s looks like %s", sym_name, os)
                return os

    return None


def is_go_binary(elf: ELF) -> bool:
    for shdr in elf.section_headers:
        if shdr.get_name(elf) == ".note.go.buildid":
            logger.debug("go buildinfo: found section .note.go.buildid")
            return True

    # The `go version` command enumerates sections for the name `.go.buildinfo`
    # (in addition to looking for the BUILDINFO_MAGIC) to check if an executable is go or not.
    # See references to the `errNotGoExe` error here:
    # https://github.com/golang/go/blob/master/src/debug/buildinfo/buildinfo.go#L41
    for shdr in elf.section_headers:
        if shdr.get_name(elf) == ".go.buildinfo":
            logger.debug("go buildinfo: found section .go.buildinfo")
            return True

    # other strategy used by FLOSS: search for known runtime strings.
    # https://github.com/mandiant/flare-floss/blob/b2ca8adfc5edf278861dd6bff67d73da39683b46/floss/language/identify.py#L88
    return False


def get_go_buildinfo_data(elf: ELF) -> Optional[bytes]:
    for shdr in elf.section_headers:
        if shdr.get_name(elf) == ".go.buildinfo":
            logger.debug("go buildinfo: found section .go.buildinfo")
            return shdr.buf

    PT_LOAD = 0x1
    PF_X = 1
    PF_W = 2
    for phdr in elf.program_headers:
        if phdr.type != PT_LOAD:
            continue

        if (phdr.flags & (PF_X | PF_W)) == PF_W:
            logger.debug("go buildinfo: found data segment")
            return phdr.buf

    return None


def read_data(elf: ELF, rva: int, size: int) -> Optional[bytes]:
    # ELF segments are for runtime data,
    # ELF sections are for link-time data.
    # So we want to read Program Headers/Segments.
    for phdr in elf.program_headers:
        if phdr.vaddr <= rva < phdr.vaddr + phdr.memsz:
            segment_data = phdr.buf

            # pad the section with NULLs
            # assume page alignment is already handled.
            # might need more hardening here.
            if len(segment_data) < phdr.memsz:
                segment_data += b"\x00" * (phdr.memsz - len(segment_data))

            segment_offset = rva - phdr.vaddr
            return segment_data[segment_offset : segment_offset + size]

    return None


def read_go_slice(elf: ELF, rva: int) -> Optional[bytes]:
    if elf.bitness == 32:
        struct_size = 8
        struct_format = elf.endian + "II"
    elif elf.bitness == 64:
        struct_size = 16
        struct_format = elf.endian + "QQ"
    else:
        raise ValueError("invalid psize")

    struct_buf = read_data(elf, rva, struct_size)
    if not struct_buf:
        return None

    addr, length = struct.unpack_from(struct_format, struct_buf, 0)

    return read_data(elf, addr, length)


def guess_os_from_go_buildinfo(elf: ELF) -> Optional[OS]:
    """
    In a binary compiled by Go, the buildinfo structure may contain
    metadata about the build environment, including the configured
    GOOS, which specifies the target operating system.

    Search for and parse the buildinfo structure,
    which may be found in the .go.buildinfo section,
    and often contains this metadata inline. Otherwise,
    follow a few byte slices to the relevant information.

    This strategy is derived from GoReSym.
    """
    buf = get_go_buildinfo_data(elf)
    if not buf:
        logger.debug("go buildinfo: no buildinfo section")
        return None

    assert isinstance(buf, bytes)

    # The build info blob left by the linker is identified by
    # a 16-byte header, consisting of:
    #  - buildInfoMagic (14 bytes),
    #  - the binary's pointer size (1 byte), and
    #  - whether the binary is big endian (1 byte).
    #
    # Then:
    #  - virtual address to Go string: runtime.buildVersion
    #  - virtual address to Go string: runtime.modinfo
    #
    #  On 32-bit platforms, the last 8 bytes are unused.
    #
    #  If the endianness has the 2 bit set, then the pointers are zero,
    #  and the 32-byte header is followed by varint-prefixed string data
    #  for the two string values we care about.
    # https://github.com/mandiant/GoReSym/blob/0860a1b1b4f3495e9fb7e71eb4386bf3e0a7c500/buildinfo/buildinfo.go#L185-L193
    BUILDINFO_MAGIC = b"\xFF Go buildinf:"

    try:
        index = buf.index(BUILDINFO_MAGIC)
    except ValueError:
        logger.debug("go buildinfo: no buildinfo magic")
        return None

    psize, flags = struct.unpack_from("<bb", buf, index + len(BUILDINFO_MAGIC))
    assert psize in (4, 8)
    is_big_endian = flags & 0b01
    has_inline_strings = flags & 0b10
    logger.debug("go buildinfo: psize: %d big endian: %s inline: %s", psize, is_big_endian, has_inline_strings)

    GOOS_TO_OS = {
        b"aix": OS.AIX,
        b"android": OS.ANDROID,
        b"dragonfly": OS.DRAGONFLYBSD,
        b"freebsd": OS.FREEBSD,
        b"hurd": OS.HURD,
        b"illumos": OS.ILLUMOS,
        b"linux": OS.LINUX,
        b"netbsd": OS.NETBSD,
        b"openbsd": OS.OPENBSD,
        b"solaris": OS.SOLARIS,
        b"zos": OS.ZOS,
        b"windows": None,  # PE format
        b"plan9": None,  # a.out format
        b"ios": None,  # Mach-O format
        b"darwin": None,  # Mach-O format
        b"nacl": None,  # dropped in GO 1.14
        b"js": None,
    }

    if has_inline_strings:
        # This is the common case/path. Most samples will have an inline GOOS string.
        #
        # To find samples on VT, use these VTGrep searches:
        #
        #   content: {ff 20 47 6f 20 62 75 69 6c 64 69 6e 66 3a 04 02}
        #   content: {ff 20 47 6f 20 62 75 69 6c 64 69 6e 66 3a 08 02}

        # If present, the GOOS key will be found within
        # the current buildinfo data region.
        #
        # Brute force the k-v pair, like `GOOS=linux`,
        # rather than try to parse the data, which would be fragile.
        for key, os in GOOS_TO_OS.items():
            if (b"GOOS=" + key) in buf:
                logger.debug("go buildinfo: found os: %s", os)
                return os
    else:
        # This is the uncommon path. Most samples will have an inline GOOS string.
        #
        # To find samples on VT, use the referenced VTGrep content searches.
        info_format = {
            # content: {ff 20 47 6f 20 62 75 69 6c 64 69 6e 66 3a 04 00}
            # like: 71e617e5cc7fda89bf67422ff60f437e9d54622382c5ed6ff31f75e601f9b22e
            # in which the modinfo doesn't have GOOS.
            (4, False): "<II",
            # content: {ff 20 47 6f 20 62 75 69 6c 64 69 6e 66 3a 08 00}
            # like: 93d3b3e2a904c6c909e20f2f76c3c2e8d0c81d535eb46e5493b5701f461816c3
            # in which the modinfo doesn't have GOOS.
            (8, False): "<QQ",
            # content: {ff 20 47 6f 20 62 75 69 6c 64 69 6e 66 3a 04 01}
            # (no matches on VT today)
            (4, True): ">II",
            # content: {ff 20 47 6f 20 62 75 69 6c 64 69 6e 66 3a 08 01}
            # like: d44ba497964050c0e3dd2a192c511e4c3c4f17717f0322a554d64b797ee4690a
            # in which the modinfo doesn't have GOOS.
            (8, True): ">QQ",
        }

        build_version_address, modinfo_address = struct.unpack_from(
            info_format[(psize, is_big_endian)], buf, index + 0x10
        )
        logger.debug("go buildinfo: build version address: 0x%x", build_version_address)
        logger.debug("go buildinfo: modinfo address: 0x%x", modinfo_address)

        build_version = read_go_slice(elf, build_version_address)
        if build_version:
            logger.debug("go buildinfo: build version: %s", build_version.decode("utf-8"))

        modinfo = read_go_slice(elf, modinfo_address)
        if modinfo:
            if modinfo[-0x11] == ord("\n"):
                # Strip module framing: sentinel strings delimiting the module info.
                # These are cmd/go/internal/modload/build.infoStart and infoEnd.
                # Which should probably be:
                # 	infoStart, _ = hex.DecodeString("3077af0c9274080241e1c107e6d618e6")
                #   infoEnd, _   = hex.DecodeString("f932433186182072008242104116d8f2")
                modinfo = modinfo[0x10:-0x10]
            logger.debug("go buildinfo: modinfo: %s", modinfo.decode("utf-8"))

        if not modinfo:
            return None

        for key, os in GOOS_TO_OS.items():
            # Brute force the k-v pair, like `GOOS=linux`,
            # rather than try to parse the data, which would be fragile.
            if (b"GOOS=" + key) in modinfo:
                logger.debug("go buildinfo: found os: %s", os)
                return os

    return None


def guess_os_from_go_source(elf: ELF) -> Optional[OS]:
    """
    In a binary compiled by Go, runtime metadata may contain
    references to the source filenames, including the
    src/runtime/os_* files, whose name indicates the
    target operating system.

    Confirm the given ELF seems to be built by Go,
    and then look for strings that look like
    Go source filenames.

    This strategy is derived from GoReSym.
    """
    if not is_go_binary(elf):
        return None

    for phdr in elf.program_headers:
        buf = phdr.buf
        NEEDLE_OS = b"/src/runtime/os_"
        try:
            index = buf.index(NEEDLE_OS)
        except ValueError:
            continue

        rest = buf[index + len(NEEDLE_OS) : index + len(NEEDLE_OS) + 32]
        filename = rest.partition(b".go")[0].decode("utf-8")
        logger.debug("go source: filename: /src/runtime/os_%s.go", filename)

        # via: https://cs.opensource.google/go/go/+/master:src/runtime/;bpv=1;bpt=0
        # candidates today:
        #   - aix
        #   - android
        #   - darwin
        #   - darwin_arm64
        #   - dragonfly
        #   - freebsd
        #   - freebsd2
        #   - freebsd_amd64
        #   - freebsd_arm
        #   - freebsd_arm64
        #   - freebsd_noauxv
        #   - freebsd_riscv64
        #   - illumos
        #   - js
        #   - linux
        #   - linux_arm
        #   - linux_arm64
        #   - linux_be64
        #   - linux_generic
        #   - linux_loong64
        #   - linux_mips64x
        #   - linux_mipsx
        #   - linux_noauxv
        #   - linux_novdso
        #   - linux_ppc64x
        #   - linux_riscv64
        #   - linux_s390x
        #   - linux_x86
        #   - netbsd
        #   - netbsd_386
        #   - netbsd_amd64
        #   - netbsd_arm
        #   - netbsd_arm64
        #   - nonopenbsd
        #   - only_solaris
        #   - openbsd
        #   - openbsd_arm
        #   - openbsd_arm64
        #   - openbsd_libc
        #   - openbsd_mips64
        #   - openbsd_syscall
        #   - openbsd_syscall1
        #   - openbsd_syscall2
        #   - plan9
        #   - plan9_arm
        #   - solaris
        #   - unix
        #   - unix_nonlinux
        #   - wasip1
        #   - wasm
        #   - windows
        #   - windows_arm
        #   - windows_arm64

        OS_FILENAME_TO_OS = {
            "aix": OS.AIX,
            "android": OS.ANDROID,
            "dragonfly": OS.DRAGONFLYBSD,
            "freebsd": OS.FREEBSD,
            "freebsd2": OS.FREEBSD,
            "freebsd_": OS.FREEBSD,
            "illumos": OS.ILLUMOS,
            "linux": OS.LINUX,
            "netbsd": OS.NETBSD,
            "only_solaris": OS.SOLARIS,
            "openbsd": OS.OPENBSD,
            "solaris": OS.SOLARIS,
            "unix_nonlinux": OS.UNIX,
        }

        for prefix, os in OS_FILENAME_TO_OS.items():
            if filename.startswith(prefix):
                return os

    for phdr in elf.program_headers:
        buf = phdr.buf
        NEEDLE_RT0 = b"/src/runtime/rt0_"
        try:
            index = buf.index(NEEDLE_RT0)
        except ValueError:
            continue

        rest = buf[index + len(NEEDLE_RT0) : index + len(NEEDLE_RT0) + 32]
        filename = rest.partition(b".s")[0].decode("utf-8")
        logger.debug("go source: filename: /src/runtime/rt0_%s.s", filename)

        # via: https://cs.opensource.google/go/go/+/master:src/runtime/;bpv=1;bpt=0
        # candidates today:
        #   - aix_ppc64
        #   - android_386
        #   - android_amd64
        #   - android_arm
        #   - android_arm64
        #   - darwin_amd64
        #   - darwin_arm64
        #   - dragonfly_amd64
        #   - freebsd_386
        #   - freebsd_amd64
        #   - freebsd_arm
        #   - freebsd_arm64
        #   - freebsd_riscv64
        #   - illumos_amd64
        #   - ios_amd64
        #   - ios_arm64
        #   - js_wasm
        #   - linux_386
        #   - linux_amd64
        #   - linux_arm
        #   - linux_arm64
        #   - linux_loong64
        #   - linux_mips64x
        #   - linux_mipsx
        #   - linux_ppc64
        #   - linux_ppc64le
        #   - linux_riscv64
        #   - linux_s390x
        #   - netbsd_386
        #   - netbsd_amd64
        #   - netbsd_arm
        #   - netbsd_arm64
        #   - openbsd_386
        #   - openbsd_amd64
        #   - openbsd_arm
        #   - openbsd_arm64
        #   - openbsd_mips64
        #   - openbsd_ppc64
        #   - openbsd_riscv64
        #   - plan9_386
        #   - plan9_amd64
        #   - plan9_arm
        #   - solaris_amd64
        #   - wasip1_wasm
        #   - windows_386
        #   - windows_amd64
        #   - windows_arm
        #   - windows_arm64

        RT0_FILENAME_TO_OS = {
            "aix": OS.AIX,
            "android": OS.ANDROID,
            "dragonfly": OS.DRAGONFLYBSD,
            "freebsd": OS.FREEBSD,
            "illumos": OS.ILLUMOS,
            "linux": OS.LINUX,
            "netbsd": OS.NETBSD,
            "openbsd": OS.OPENBSD,
            "solaris": OS.SOLARIS,
        }

        for prefix, os in RT0_FILENAME_TO_OS.items():
            if filename.startswith(prefix):
                return os

    return None


def guess_os_from_vdso_strings(elf: ELF) -> Optional[OS]:
    """
    The "vDSO" (virtual dynamic shared object) is a small shared
    library that the kernel automatically maps into the address space
    of all user-space applications.

    Some statically linked executables include small dynamic linker
    routines that finds these vDSO symbols, using the ASCII
    symbol name and version. We can therefore recognize the pairs
    (symbol, version) to guess the binary targets Linux.
    """
    for phdr in elf.program_headers:
        buf = phdr.buf

        # We don't really use the arch, but its interesting for documentation
        # I suppose we could restrict the arch here to what's in the ELF header,
        # but that's even more work. Let's see if this is sufficient.
        for arch, symbol, version in (
            # via: https://man7.org/linux/man-pages/man7/vdso.7.html
            ("arm", b"__vdso_gettimeofday", b"LINUX_2.6"),
            ("arm", b"__vdso_clock_gettime", b"LINUX_2.6"),
            ("aarch64", b"__kernel_rt_sigreturn", b"LINUX_2.6.39"),
            ("aarch64", b"__kernel_gettimeofday", b"LINUX_2.6.39"),
            ("aarch64", b"__kernel_clock_gettime", b"LINUX_2.6.39"),
            ("aarch64", b"__kernel_clock_getres", b"LINUX_2.6.39"),
            ("mips", b"__kernel_gettimeofday", b"LINUX_2.6"),
            ("mips", b"__kernel_clock_gettime", b"LINUX_2.6"),
            ("ia64", b"__kernel_sigtramp", b"LINUX_2.5"),
            ("ia64", b"__kernel_syscall_via_break", b"LINUX_2.5"),
            ("ia64", b"__kernel_syscall_via_epc", b"LINUX_2.5"),
            ("ppc/32", b"__kernel_clock_getres", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_clock_gettime", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_clock_gettime64", b"LINUX_5.11"),
            ("ppc/32", b"__kernel_datapage_offset", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_get_syscall_map", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_get_tbfreq", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_getcpu", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_gettimeofday", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_sigtramp_rt32", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_sigtramp32", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_sync_dicache", b"LINUX_2.6.15"),
            ("ppc/32", b"__kernel_sync_dicache_p5", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_clock_getres", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_clock_gettime", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_datapage_offset", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_get_syscall_map", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_get_tbfreq", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_getcpu", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_gettimeofday", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_sigtramp_rt64", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_sync_dicache", b"LINUX_2.6.15"),
            ("ppc/64", b"__kernel_sync_dicache_p5", b"LINUX_2.6.15"),
            ("riscv", b"__vdso_rt_sigreturn", b"LINUX_4.15"),
            ("riscv", b"__vdso_gettimeofday", b"LINUX_4.15"),
            ("riscv", b"__vdso_clock_gettime", b"LINUX_4.15"),
            ("riscv", b"__vdso_clock_getres", b"LINUX_4.15"),
            ("riscv", b"__vdso_getcpu", b"LINUX_4.15"),
            ("riscv", b"__vdso_flush_icache", b"LINUX_4.15"),
            ("s390", b"__kernel_clock_getres", b"LINUX_2.6.29"),
            ("s390", b"__kernel_clock_gettime", b"LINUX_2.6.29"),
            ("s390", b"__kernel_gettimeofday", b"LINUX_2.6.29"),
            ("superh", b"__kernel_rt_sigreturn", b"LINUX_2.6"),
            ("superh", b"__kernel_sigreturn", b"LINUX_2.6"),
            ("superh", b"__kernel_vsyscall", b"LINUX_2.6"),
            ("i386", b"__kernel_sigreturn", b"LINUX_2.5"),
            ("i386", b"__kernel_rt_sigreturn", b"LINUX_2.5"),
            ("i386", b"__kernel_vsyscall", b"LINUX_2.5"),
            ("i386", b"__vdso_clock_gettime", b"LINUX_2.6"),
            ("i386", b"__vdso_gettimeofday", b"LINUX_2.6"),
            ("i386", b"__vdso_time", b"LINUX_2.6"),
            ("x86-64", b"__vdso_clock_gettime", b"LINUX_2.6"),
            ("x86-64", b"__vdso_getcpu", b"LINUX_2.6"),
            ("x86-64", b"__vdso_gettimeofday", b"LINUX_2.6"),
            ("x86-64", b"__vdso_time", b"LINUX_2.6"),
            ("x86/32", b"__vdso_clock_gettime", b"LINUX_2.6"),
            ("x86/32", b"__vdso_getcpu", b"LINUX_2.6"),
            ("x86/32", b"__vdso_gettimeofday", b"LINUX_2.6"),
            ("x86/32", b"__vdso_time", b"LINUX_2.6"),
        ):
            if symbol in buf and version in buf:
                logger.debug("vdso string: %s %s %s", arch, symbol.decode("ascii"), version.decode("ascii"))
                return OS.LINUX

    return None


def detect_elf_os(f) -> str:
    """
    f: type Union[BinaryIO, IDAIO, GHIDRAIO]
    """
    try:
        elf = ELF(f)
    except Exception as e:
        logger.warning("Error parsing ELF file: %s", e)
        return "unknown"

    try:
        osabi_guess = guess_os_from_osabi(elf)
        logger.debug("guess: osabi: %s", osabi_guess)
    except Exception as e:
        logger.warning("Error guessing OS from OSABI: %s", e)
        osabi_guess = None

    try:
        ph_notes_guess = guess_os_from_ph_notes(elf)
        logger.debug("guess: ph notes: %s", ph_notes_guess)
    except Exception as e:
        logger.warning("Error guessing OS from program header notes: %s", e)
        ph_notes_guess = None

    try:
        sh_notes_guess = guess_os_from_sh_notes(elf)
        logger.debug("guess: sh notes: %s", sh_notes_guess)
    except Exception as e:
        logger.warning("Error guessing OS from section header notes: %s", e)
        sh_notes_guess = None

    try:
        ident_guess = guess_os_from_ident_directive(elf)
        logger.debug("guess: .ident: %s", ident_guess)
    except Exception as e:
        logger.warning("Error guessing OS from .ident directive: %s", e)
        ident_guess = None

    try:
        linker_guess = guess_os_from_linker(elf)
        logger.debug("guess: linker: %s", linker_guess)
    except Exception as e:
        logger.warning("Error guessing OS from linker: %s", e)
        linker_guess = None

    try:
        abi_versions_needed_guess = guess_os_from_abi_versions_needed(elf)
        logger.debug("guess: ABI versions needed: %s", abi_versions_needed_guess)
    except Exception as e:
        logger.warning("Error guessing OS from ABI versions needed: %s", e)
        abi_versions_needed_guess = None

    try:
        needed_dependencies_guess = guess_os_from_needed_dependencies(elf)
        logger.debug("guess: needed dependencies: %s", needed_dependencies_guess)
    except Exception as e:
        logger.warning("Error guessing OS from needed dependencies: %s", e)
        needed_dependencies_guess = None

    try:
        symtab_guess = guess_os_from_symtab(elf)
        logger.debug("guess: pertinent symbol name: %s", symtab_guess)
    except Exception as e:
        logger.warning("Error guessing OS from symbol table: %s", e)
        symtab_guess = None

    try:
        goos_guess = guess_os_from_go_buildinfo(elf)
        logger.debug("guess: Go buildinfo: %s", goos_guess)
    except Exception as e:
        logger.warning("Error guessing OS from Go buildinfo: %s", e)
        goos_guess = None

    try:
        gosrc_guess = guess_os_from_go_source(elf)
        logger.debug("guess: Go source: %s", gosrc_guess)
    except Exception as e:
        logger.warning("Error guessing OS from Go source path: %s", e)
        gosrc_guess = None

    try:
        vdso_guess = guess_os_from_vdso_strings(elf)
        logger.debug("guess: vdso strings: %s", vdso_guess)
    except Exception as e:
        logger.warning("Error guessing OS from vdso strings: %s", e)
        symtab_guess = None

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

    elif goos_guess:
        ret = goos_guess

    elif gosrc_guess:
        # prefer goos_guess to this method,
        # which is just string interpretation.
        ret = gosrc_guess

    elif ident_guess:
        # at the bottom because we don't trust this too much
        # due to potential for bugs with cross-compilation.
        ret = ident_guess

    elif vdso_guess:
        # at the bottom because this is just scanning strings,
        # which isn't very authoritative.
        ret = vdso_guess

    return ret.value if ret is not None else "unknown"


def detect_elf_arch(f: BinaryIO) -> str:
    return ELF(f).e_machine or "unknown"
