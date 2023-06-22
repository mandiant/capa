import logging
import contextlib
from io import BytesIO
from typing import Tuple, Iterator

import capa.features.extractors.elf
from capa.features.common import OS, ARCH_I386, ARCH_AMD64, OS_WINDOWS, Arch, Feature
from capa.features.address import NO_ADDRESS, Address

logger = logging.getLogger(__name__)


def extract_os() -> Iterator[Tuple[Feature, Address]]:
    format_name: str = currentProgram.getExecutableFormat()  # currentProgram: static Ghidra variable

    if "PE" in format_name:
        yield OS(OS_WINDOWS), NO_ADDRESS

    elif "ELF" in format_name:
        program_memory = currentProgram.getMemory()  # ghidra.program.database.mem.MemoryMapDB
        fbytes_list = program_memory.getAllFileBytes()  # java.util.List<FileBytes>
        fbytes = fbytes_list[0]  # ghidra.program.database.mem.FileBytes

        # Java likes to return signed ints, so we must convert them
        # back into unsigned bytes manually and write to BytesIO
        #   note: May be deprecated if Jep has implements better support for Java Lists
        pb_arr = b""
        for i in range(fbytes.getSize()):
            pb_arr = pb_arr + (fbytes.getOriginalByte(i) & 0xFF).to_bytes(1, "little")
        buf = BytesIO(pb_arr)

        with contextlib.closing(buf) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)

        yield OS(os), NO_ADDRESS

    else:
        # we likely end up here:
        #  1. handling shellcode, or
        #  2. handling a new file format (e.g. macho)
        #
        # for (1) we can't do much - its shellcode and all bets are off.
        # we could maybe accept a further CLI argument to specify the OS,
        # but i think this would be rarely used.
        # rules that rely on OS conditions will fail to match on shellcode.
        #
        # for (2), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported file format: %s, will not guess OS", format_name)
        return


def extract_arch() -> Iterator[Tuple[Feature, Address]]:
    lang_id = currentProgram.getMetadata().get("Language ID")

    if "x86" in lang_id and "64" in lang_id:
        yield Arch(ARCH_AMD64), NO_ADDRESS

    elif "x86" in lang_id and "32" in lang_id:
        yield Arch(ARCH_I386), NO_ADDRESS

    elif "x86" not in lang_id:
        logger.debug("unsupported architecture: non-32-bit nor non-64-bit intel")
        return

    else:
        # we likely end up here:
        #  1. handling a new architecture (e.g. aarch64)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported architecture: %s", lang_id)
        return
