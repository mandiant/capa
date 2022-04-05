import io
import logging
import binascii
import contextlib

import pefile

import capa.features
import capa.features.extractors.elf
import capa.features.extractors.pefile
from capa.features.common import OS, FORMAT_PE, FORMAT_ELF, OS_WINDOWS, FORMAT_FREEZE, Arch, Format, String
from capa.features.freeze import is_freeze

logger = logging.getLogger(__name__)


def extract_file_strings(buf, **kwargs):
    """
    extract ASCII and UTF-16 LE strings from file
    """
    for s in capa.features.extractors.strings.extract_ascii_strings(buf):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(buf):
        yield String(s.s), s.offset


def extract_format(buf):
    if buf.startswith(b"MZ"):
        yield Format(FORMAT_PE), 0x0
    elif buf.startswith(b"\x7fELF"):
        yield Format(FORMAT_ELF), 0x0
    elif is_freeze(buf):
        yield Format(FORMAT_FREEZE), 0x0
    else:
        # we likely end up here:
        #  1. handling a file format (e.g. macho)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s", binascii.hexlify(buf[:4]).decode("ascii"))
        return


def extract_arch(buf):
    if buf.startswith(b"MZ"):
        yield from capa.features.extractors.pefile.extract_file_arch(pe=pefile.PE(data=buf))

    elif buf.startswith(b"\x7fELF"):
        with contextlib.closing(io.BytesIO(buf)) as f:
            arch = capa.features.extractors.elf.detect_elf_arch(f)

        if arch not in capa.features.common.VALID_ARCH:
            logger.debug("unsupported arch: %s", arch)
            return

        yield Arch(arch), 0x0

    else:
        # we likely end up here:
        #  1. handling shellcode, or
        #  2. handling a new file format (e.g. macho)
        #
        # for (1) we can't do much - its shellcode and all bets are off.
        # we could maybe accept a futher CLI argument to specify the arch,
        # but i think this would be rarely used.
        # rules that rely on arch conditions will fail to match on shellcode.
        #
        # for (2), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s, will not guess Arch", binascii.hexlify(buf[:4]).decode("ascii"))
        return


def extract_os(buf):
    if buf.startswith(b"MZ"):
        yield OS(OS_WINDOWS), 0x0
    elif buf.startswith(b"\x7fELF"):
        with contextlib.closing(io.BytesIO(buf)) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)

        if os not in capa.features.common.VALID_OS:
            logger.debug("unsupported os: %s", os)
            return

        yield OS(os), 0x0

    else:
        # we likely end up here:
        #  1. handling shellcode, or
        #  2. handling a new file format (e.g. macho)
        #
        # for (1) we can't do much - its shellcode and all bets are off.
        # we could maybe accept a futher CLI argument to specify the OS,
        # but i think this would be rarely used.
        # rules that rely on OS conditions will fail to match on shellcode.
        #
        # for (2), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s, will not guess OS", binascii.hexlify(buf[:4]).decode("ascii"))
        return
