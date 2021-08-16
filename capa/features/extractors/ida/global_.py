import idaapi

from capa.features.common import ARCH_I386, ARCH_AMD64, Arch


def extract_arch():
    info = idaapi.get_inf_structure()
    if info.procName == "metapc" and info.is_64bit():
        yield Arch(ARCH_AMD64), 0x0
    elif info.procName == "metapc" and info.is_32bit():
        yield Arch(ARCH_I386), 0x0
    elif info.procName == "metapc":
        raise NotImplementedError("unsupported architecture: non-32-bit nor non-64-bit intel")
    else:
        raise NotImplementedError("unsupported architecture: %s" % (info.procName))
