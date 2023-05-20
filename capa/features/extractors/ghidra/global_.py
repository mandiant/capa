import logging
import contextlib
from io import BytesIO
from typing import Tuple, Iterator 

import ghidra.program.flatapi as flatapi
ghidraapi = flatapi.FlatProgramAPI(currentProgram) # Ghidrathon hacks :)

import capa.features.extractors.elf
from capa.features.common import OS, ARCH_I386, ARCH_AMD64, OS_WINDOWS, Arch, Feature
from capa.features.address import NO_ADDRESS, Address

logger = logging.getLogger(__name__)

def extract_os() -> Iterator[Tuple[Feature, Address]]:
    current_program = ghidraapi.getCurrentProgram()
    format_name: str = current_program.getExecutableFormat()

    if "PE" in format_name:
        yield OS(OS_WINDOWS), NO_ADDRESS

    elif "ELF" in format_name:
        program_memory = current_program.getMemory()
        fbytes_list = program_memory.getAllFileBytes() # java.util.List<FileBytes>
        fbytes = fbytes_list[0]                        # ghidra.program.database.mem.FileBytes

        # Java likes to return signed ints, so we must convert them
        # back into unsigned bytes manually and write to BytesIO
        pb_arr = b''
        for i in range(fbytes.getSize()):
            pb_arr = pb_arr + (fbytes.getOriginalByte(i) & 0xff).to_bytes(1, 'little')
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


