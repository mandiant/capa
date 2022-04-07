import logging
from typing import Tuple, Iterator

import dnfile
import pefile

from capa.features.common import OS, OS_ANY, ARCH_ANY, ARCH_I386, ARCH_AMD64, FORMAT_DOTNET, Arch, Format, Feature
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_format(**kwargs):
    yield Format(FORMAT_DOTNET), 0x0


def extract_file_os(**kwargs):
    yield OS(OS_ANY), 0x0


def extract_file_arch(pe, **kwargs):
    # to distinguish in more detail, see https://stackoverflow.com/a/23614024/10548020
    # .NET 4.5 added option: any CPU, 32-bit preferred
    if pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
        yield Arch(ARCH_I386), 0x0
    elif not pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        yield Arch(ARCH_AMD64), 0x0
    else:
        yield Arch(ARCH_ANY), 0x0


def extract_file_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, int]]:
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(pe=pe):  # type: ignore
            yield feature, va


FILE_HANDLERS = (
    # extract_file_export_names,
    # extract_file_import_names,
    # extract_file_section_names,
    # extract_file_strings,
    # extract_file_function_names,
    extract_file_format,
)


def extract_global_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, int]]:
    for handler in GLOBAL_HANDLERS:
        for feature, va in handler(pe=pe):  # type: ignore
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

    def get_base_address(self) -> int:
        return 0x0

    def get_entry_point(self) -> int:
        # self.pe.net.Flags.CLT_NATIVE_ENTRYPOINT
        #  True: native EP: Token
        #  False: managed EP: RVA
        return self.pe.net.struct.EntryPointTokenOrRva

    def extract_global_features(self):
        yield from extract_global_features(self.pe)

    def extract_file_features(self):
        yield from extract_file_features(self.pe)

    def is_dotnet_file(self) -> bool:
        return bool(self.pe.net)

    def is_mixed_mode(self) -> bool:
        return not bool(self.pe.net.Flags.CLR_ILONLY)

    def get_runtime_version(self) -> Tuple[int, int]:
        return self.pe.net.struct.MajorRuntimeVersion, self.pe.net.struct.MinorRuntimeVersion

    def get_meta_version_string(self) -> str:
        return self.pe.net.metadata.struct.Version.rstrip(b"\x00").decode("utf-8")

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
