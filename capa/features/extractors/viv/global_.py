import logging
from typing import Tuple, Iterator

from capa.features.common import ARCH_I386, ARCH_AMD64, Arch, Feature
from capa.features.address import NO_ADDRESS, Address

logger = logging.getLogger(__name__)


def extract_arch(vw) -> Iterator[Tuple[Feature, Address]]:
    arch = vw.getMeta("Architecture")
    if arch == "amd64":
        yield Arch(ARCH_AMD64), NO_ADDRESS

    elif arch == "i386":
        yield Arch(ARCH_I386), NO_ADDRESS

    else:
        # we likely end up here:
        #  1. handling a new architecture (e.g. aarch64)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported architecture: %s", vw.arch.__class__.__name__)
        return
