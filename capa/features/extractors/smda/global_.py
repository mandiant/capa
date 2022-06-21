import logging

from capa.features.common import ARCH_I386, ARCH_AMD64, Arch
from capa.features.address import NO_ADDRESS

logger = logging.getLogger(__name__)


def extract_arch(smda_report):
    if smda_report.architecture == "intel":
        if smda_report.bitness == 32:
            yield Arch(ARCH_I386), NO_ADDRESS
        elif smda_report.bitness == 64:
            yield Arch(ARCH_AMD64), NO_ADDRESS
    else:
        # we likely end up here:
        #  1. handling a new architecture (e.g. aarch64)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported architecture: %s", smda_report.architecture)
        return
