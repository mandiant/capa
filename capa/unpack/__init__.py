import pefile

ASPACK = "aspack"


class NotPackedError(ValueError):
    def __init__(self):
        super(NotPackedError, self).__init__("not packed")


def detect_aspack(buf):
    """return True if the given buffer contains an ASPack'd PE file"""
    try:
        pe = pefile.PE(data=buf, fast_load=True)
    except:
        return False

    for section in pe.sections:
        try:
            section_name = section.Name.partition(b"\x00")[0].decode("ascii")
        except:
            continue

        if section_name in (".aspack", ".adata"):
            return True

    return False


def unpack_aspack(buf):
    return buf


UNPACKERS = {
    ASPACK: (detect_aspack, unpack_aspack),
}


def detect_packer(buf):
    for packer, (detect, _) in UNPACKERS.items():
        if detect(buf):
            return packer

    raise NotPackedError()


def is_packed(buf):
    try:
        detect_packer(buf)
        return True
    except NotPackedError:
        return False


def unpack_pe(packer, buf):
    (detect, unpack) = UNPACKERS[packer]
    return unpack(buf)