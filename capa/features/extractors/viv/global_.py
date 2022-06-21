import logging
from typing import Tuple, Iterator

import envi.archs.i386
import envi.archs.amd64

from capa.features.common import ARCH_I386, ARCH_AMD64, Arch, Feature
from capa.features.address import NO_ADDRESS, Address

logger = logging.getLogger(__name__)


def extract_arch(vw) -> Iterator[Tuple[Feature, Address]]:
    if isinstance(vw.arch, envi.archs.amd64.Amd64Module):
        yield Arch(ARCH_AMD64), NO_ADDRESS

    elif isinstance(vw.arch, envi.archs.i386.i386Module):
        yield Arch(ARCH_I386), NO_ADDRESS

    else:
        # we likely end up here:
        #  1. handling a new architecture (e.g. aarch64)
        #
        # for (1), this logic will need to be updated as the format is implemented.
        logger.debug("unsupported architecture: %s", vw.arch.__class__.__name__)
        return
