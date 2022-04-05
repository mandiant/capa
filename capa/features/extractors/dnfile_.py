import logging

import dnfile

from capa.features.common import OS, OS_ANY, ARCH_ANY, ARCH_I386, ARCH_AMD64, FORMAT_DOTNET, Arch, Format
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_format(**kwargs):
    yield Format(FORMAT_DOTNET), 0x0


def extract_file_os(**kwargs):
    yield OS(OS_ANY), 0x0


def extract_file_arch(pe, **kwargs):
    # TODO differences for versions < 4.5?
    # via https://stackoverflow.com/a/23614024/10548020
    if pe.net.Flags.CLR_32BITREQUIRED and pe.net.Flags.CLR_PREFER_32BIT:
        yield Arch(ARCH_I386), 0x0
    elif not pe.net.Flags.CLR_32BITREQUIRED and not pe.net.Flags.CLR_PREFER_32BIT:
        yield Arch(ARCH_AMD64), 0x0
    else:
        yield Arch(ARCH_ANY), 0x0


def extract_file_features(pe, buf):
    """
    extract file features from given workspace

    args:
      pe (pefile.PE): the parsed PE
      buf: the raw sample bytes

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """

    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(pe=pe, buf=buf):
            yield feature, va


FILE_HANDLERS = (
    # extract_file_export_names,
    # extract_file_import_names,
    # extract_file_section_names,
    # extract_file_strings,
    # extract_file_function_names,
    extract_file_format,
)


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
    extract_file_os,
    extract_file_arch,
)


class DnfileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super(DnfileFeatureExtractor, self).__init__()
        self.path: str = path
        self.pe: dnfile.dnPE = dnfile.dnPE(path)

    def is_dotnet_file(self) -> bool:
        return bool(self.pe.net)

    def get_base_address(self) -> int:
        return self.pe.net.struct.EntryPointTokenOrRva

    def extract_global_features(self):
        with open(self.path, "rb") as f:
            buf = f.read()

        yield from extract_global_features(self.pe, buf)

    def extract_file_features(self):
        with open(self.path, "rb") as f:
            buf = f.read()

        yield from extract_file_features(self.pe, buf)

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
