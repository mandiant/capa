import envi.archs.i386
import envi.archs.amd64

from capa.features.common import ARCH_I386, ARCH_AMD64, Arch


def extract_arch(vw):
    if isinstance(vw.arch, envi.archs.amd64.Amd64Module):
        yield Arch(ARCH_AMD64), 0x0

    elif isinstance(vw.arch, envi.archs.i386.i386Module):
        yield Arch(ARCH_I386), 0x0

    else:
        raise NotImplementedError("unsupported architecture: %s" % (vw.arch.__class__.__name__))
