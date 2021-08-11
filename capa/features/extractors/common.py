import io
import logging
import binascii
import contextlib

import capa.features.extractors.elf
from capa.features.common import CHARACTERISTIC_PE, CHARACTERISTIC_ELF, CHARACTERISTIC_WINDOWS, Characteristic

logger = logging.getLogger(__name__)


def extract_format(buf):
    if buf.startswith(b"MZ"):
        yield CHARACTERISTIC_PE, 0x0
    elif buf.startswith(b"\x7fELF"):
        yield CHARACTERISTIC_ELF, 0x0
    else:
        raise NotImplementedError("file format: %s", binascii.hexlify(buf[:4]).decode("ascii"))


def extract_os(buf):
    if buf.startswith(b"MZ"):
        yield CHARACTERISTIC_WINDOWS, 0x0
    elif buf.startswith(b"\x7fELF"):
        with contextlib.closing(io.BytesIO(buf)) as f:
            os = capa.features.extractors.elf.detect_elf_os(f)

        yield Characteristic("os/%s" % (os.lower())), 0x0
    else:
        raise NotImplementedError("file format: %s", binascii.hexlify(buf[:4]).decode("ascii"))
