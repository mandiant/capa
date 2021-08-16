from capa.features.common import ARCH_I386, ARCH_AMD64, Arch


def extract_arch(smda_report):
    if smda_report.architecture == "intel":
        if smda_report.bitness == 32:
            yield Arch(ARCH_I386), 0x0
        elif smda_report.bitness == 64:
            yield Arch(ARCH_AMD64), 0x0
    else:
        raise NotImplementedError(smda_report.architecture)
