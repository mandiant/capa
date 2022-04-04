import logging

import dnfile

from capa.features.common import ARCH_I386, ARCH_AMD64, Arch
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_os(**kwargs):
    # TODO yield OS(OS_ANY), 0x0?
    yield


def extract_file_arch(pe, **kwargs):
    # TODO also see 32 - Assembly Table?
    if pe.net.Flags.CLR_32BITREQUIRED:
        yield Arch(ARCH_I386), 0x0
    else:
        yield Arch(ARCH_AMD64), 0x0


def extract_global_features(pe, buf):
    """
    extract global features from given workspace

    args:
      pe (pefile.PE): the parsed PE
      buf: the raw sample bytes

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """
    for handler in GLOBAL_HANDLERS:
        for feature, va in handler(pe=pe, buf=buf):
            yield feature, va


GLOBAL_HANDLERS = (
    # TODO extract_file_os,
    extract_file_arch,
)


class DnfileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super(DnfileFeatureExtractor, self).__init__()
        self.path = path
        self.pe = dnfile.dnPE(path)

    def get_base_address(self):
        raise NotImplementedError("N/A")

    def extract_global_features(self):
        with open(self.path, "rb") as f:
            buf = f.read()

        yield from extract_global_features(self.pe, buf)

    def extract_file_features(self):
        # TODO
        #     with open(self.path, "rb") as f:
        #         buf = f.read()
        #
        #     yield from extract_file_features(self.pe, buf)
        yield None, 0x0

    def get_functions(self):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")

    def extract_function_features(self, f):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")

    def get_basic_blocks(self, f):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")

    def extract_basic_block_features(self, f, bb):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")

    def get_instructions(self, f, bb):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")

    def extract_insn_features(self, f, bb, insn):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")

    def is_library_function(self, va):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")

    def get_function_name(self, va):
        raise NotImplementedError("DnfileFeatureExtractor can only be used to extract file features")
