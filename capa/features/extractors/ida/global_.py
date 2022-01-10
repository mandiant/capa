import logging
import contextlib

import idaapi
import ida_loader

import capa.ida.helpers
import capa.features.extractors.elf
from capa.features.common import OS, ARCH_I386, ARCH_AMD64, OS_WINDOWS, Arch

logger = logging.getLogger(__name__)


def extract_os():
    format_name = ida_loader.get_file_type_name()

    if "PE" in format_name:
        yield OS(OS_WINDOWS), 0x0

    elif "ELF" in format_name:
        with contextlib.closing(capa.ida.helpers.IDAIO()) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)

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
        logger.debug("unsupported file format: %s, will not guess OS", format_name)
        return


def extract_arch():
    info = idaapi.get_inf_structure()
    if info.procname == "metapc" and info.is_64bit():
        yield Arch(ARCH_AMD64), 0x0
    elif info.procname == "metapc" and info.is_32bit():
        yield Arch(ARCH_I386), 0x0
    elif info.procname == "metapc":
        logger.debug("unsupported architecture: non-32-bit nor non-64-bit intel")
        return
    else:
        # we likely end up here:
        #  1. handling a new architecture (e.g. aarch64)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported architecture: %s", info.procname)
        return
