import io
import logging
import binascii
import contextlib

import capa.features.extractors.elf
from capa.features.common import OS, FORMAT_PE, FORMAT_ELF, OS_WINDOWS, Format

logger = logging.getLogger(__name__)


def extract_format(buf):
    if buf.startswith(b"MZ"):
        yield Format(FORMAT_PE), 0x0
    elif buf.startswith(b"\x7fELF"):
        yield Format(FORMAT_ELF), 0x0
    else:
        raise NotImplementedError("file format: %s", binascii.hexlify(buf[:4]).decode("ascii"))


def extract_os(buf):
    if buf.startswith(b"MZ"):
        yield OS(OS_WINDOWS), 0x0
    elif buf.startswith(b"\x7fELF"):
        with contextlib.closing(io.BytesIO(buf)) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)

        yield OS(os), 0x0
    else:
        raise NotImplementedError("file format: %s", binascii.hexlify(buf[:4]).decode("ascii"))
