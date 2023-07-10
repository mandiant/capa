import io
import logging
import binascii
import contextlib
from typing import Tuple, Iterator

import pefile

import capa.features
import capa.features.extractors.elf
import capa.features.extractors.pefile
import capa.features.extractors.strings
from capa.features.common import (
    OS,
    OS_ANY,
    OS_AUTO,
    ARCH_ANY,
    FORMAT_PE,
    FORMAT_ELF,
    OS_WINDOWS,
    FORMAT_FREEZE,
    FORMAT_RESULT,
    Arch,
    Format,
    String,
    Feature,
)
from capa.features.freeze import is_freeze
from capa.features.address import NO_ADDRESS, Address, FileOffsetAddress

logger = logging.getLogger(__name__)

# match strings for formats
MATCH_PE = b"MZ"
MATCH_ELF = b"\x7fELF"
MATCH_RESULT = b'{"meta":'


def extract_file_strings(buf, **kwargs) -> Iterator[Tuple[String, Address]]:
    """
    extract ASCII and UTF-16 LE strings from file
    """
    for s in capa.features.extractors.strings.extract_ascii_strings(buf):
        yield String(s.s), FileOffsetAddress(s.offset)

    for s in capa.features.extractors.strings.extract_unicode_strings(buf):
        yield String(s.s), FileOffsetAddress(s.offset)


def extract_format(buf) -> Iterator[Tuple[Feature, Address]]:
    if buf.startswith(MATCH_PE):
        yield Format(FORMAT_PE), NO_ADDRESS
    elif buf.startswith(MATCH_ELF):
        yield Format(FORMAT_ELF), NO_ADDRESS
    elif is_freeze(buf):
        yield Format(FORMAT_FREEZE), NO_ADDRESS
    elif buf.startswith(MATCH_RESULT):
        yield Format(FORMAT_RESULT), NO_ADDRESS
    else:
        # we likely end up here:
        #  1. handling a file format (e.g. macho)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s", binascii.hexlify(buf[:4]).decode("ascii"))
        return


def extract_arch(buf) -> Iterator[Tuple[Feature, Address]]:
    if buf.startswith(MATCH_PE):
        yield from capa.features.extractors.pefile.extract_file_arch(pe=pefile.PE(data=buf))

    elif buf.startswith(MATCH_RESULT):
        yield Arch(ARCH_ANY), NO_ADDRESS

    elif buf.startswith(MATCH_ELF):
        with contextlib.closing(io.BytesIO(buf)) as f:
            arch = capa.features.extractors.elf.detect_elf_arch(f)

        if arch not in capa.features.common.VALID_ARCH:
            logger.debug("unsupported arch: %s", arch)
            return

        yield Arch(arch), NO_ADDRESS

    else:
        # we likely end up here:
        #  1. handling shellcode, or
        #  2. handling a new file format (e.g. macho)
        #
        # for (1) we can't do much - its shellcode and all bets are off.
        # we could maybe accept a further CLI argument to specify the arch,
        # but i think this would be rarely used.
        # rules that rely on arch conditions will fail to match on shellcode.
        #
        # for (2), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s, will not guess Arch", binascii.hexlify(buf[:4]).decode("ascii"))
        return


def extract_os(buf, os=OS_AUTO) -> Iterator[Tuple[Feature, Address]]:
    if os != OS_AUTO:
        yield OS(os), NO_ADDRESS

    if buf.startswith(MATCH_PE):
        yield OS(OS_WINDOWS), NO_ADDRESS
    elif buf.startswith(MATCH_RESULT):
        yield OS(OS_ANY), NO_ADDRESS
    elif buf.startswith(MATCH_ELF):
        with contextlib.closing(io.BytesIO(buf)) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)

        if os not in capa.features.common.VALID_OS:
            logger.debug("unsupported os: %s", os)
            return

        yield OS(os), NO_ADDRESS

    else:
        # we likely end up here:
        #  1. handling shellcode, or
        #  2. handling a new file format (e.g. macho)
        #
        # for (1) we can't do much - its shellcode and all bets are off.
        # rules that rely on OS conditions will fail to match on shellcode.
        #
        # for (2), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s, will not guess OS", binascii.hexlify(buf[:4]).decode("ascii"))
        return
