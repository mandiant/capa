import sys
import logging

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

logger = logging.getLogger(__name__)


class NotPackedError(ValueError):
    def __init__(self):
        super(NotPackedError, self).__init__("not packed")


def can_unpack():
    # the unpacking backend is based on Speakeasy, which supports python 3.6+
    return sys.version_info >= (3, 6)


@lru_cache
def get_unpackers():
    # break import loop
    import capa.unpack.aspack

    return {p.name: p for p in [capa.unpack.aspack.AspackUnpacker]}


def detect_packer(buf):
    for unpacker in get_unpackers().values():
        if unpacker.is_packed(buf):
            return unpacker.name

    raise NotPackedError()


def is_packed(buf):
    try:
        detect_packer(buf)
        return True
    except NotPackedError:
        return False


def unpack_pe(packer, buf):
    return get_unpackers()[packer].unpack_pe(buf)
