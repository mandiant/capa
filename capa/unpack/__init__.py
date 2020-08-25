ASPACK = "aspack"


def detect_packer(buf):
    raise ValueError("not packed")


def is_packed(buf):
    try:
        detect_packer(buf)
        return True
    except ValueError:
        return False


def unpack_pe(buf):
    raise ValueError("no packed")