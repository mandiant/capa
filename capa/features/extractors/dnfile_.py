import logging
from typing import Tuple, Iterator

import dnfile
import pefile

from capa.features.common import (
    OS,
    OS_ANY,
    ARCH_ANY,
    ARCH_I386,
    FORMAT_PE,
    ARCH_AMD64,
    FORMAT_DOTNET,
    Arch,
    Format,
    Feature,
)
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def extract_file_format(**kwargs) -> Iterator[Tuple[Feature, Address]]:
    yield Format(FORMAT_PE), NO_ADDRESS
    yield Format(FORMAT_DOTNET), NO_ADDRESS


def extract_file_os(**kwargs) -> Iterator[Tuple[Feature, Address]]:
    yield OS(OS_ANY), NO_ADDRESS


def extract_file_arch(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Feature, Address]]:
    # to distinguish in more detail, see https://stackoverflow.com/a/23614024/10548020
    # .NET 4.5 added option: any CPU, 32-bit preferred
    assert pe.net is not None
    assert pe.net.Flags is not None

    if pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
        yield Arch(ARCH_I386), NO_ADDRESS
    elif not pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        yield Arch(ARCH_AMD64), NO_ADDRESS
    else:
        yield Arch(ARCH_ANY), NO_ADDRESS


def extract_file_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, address in file_handler(pe=pe):  # type: ignore
            yield feature, address


FILE_HANDLERS = (
    # extract_file_export_names,
    # extract_file_import_names,
    # extract_file_section_names,
    # extract_file_strings,
    # extract_file_function_names,
    extract_file_format,
)


def extract_global_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, Address]]:
    for handler in GLOBAL_HANDLERS:
        for feature, addr in handler(pe=pe):  # type: ignore
            yield feature, addr


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


class DnfileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super().__init__()
        self.path: str = path
        self.pe: dnfile.dnPE = dnfile.dnPE(path)

    def get_base_address(self) -> AbsoluteVirtualAddress:
        return AbsoluteVirtualAddress(0x0)

    def get_entry_point(self) -> int:
        # self.pe.net.Flags.CLT_NATIVE_ENTRYPOINT
        #  True: native EP: Token
        #  False: managed EP: RVA
        assert self.pe.net is not None
        assert self.pe.net.struct is not None

        return self.pe.net.struct.EntryPointTokenOrRva

    def extract_global_features(self):
        yield from extract_global_features(self.pe)

    def extract_file_features(self):
        yield from extract_file_features(self.pe)

    def is_dotnet_file(self) -> bool:
        return bool(self.pe.net)

    def is_mixed_mode(self) -> bool:
        assert self.pe is not None
        assert self.pe.net is not None
        assert self.pe.net.Flags is not None

        return not bool(self.pe.net.Flags.CLR_ILONLY)

    def get_runtime_version(self) -> Tuple[int, int]:
        assert self.pe is not None
        assert self.pe.net is not None
        assert self.pe.net.struct is not None

        return self.pe.net.struct.MajorRuntimeVersion, self.pe.net.struct.MinorRuntimeVersion

    def get_meta_version_string(self) -> str:
        assert self.pe.net is not None
        assert self.pe.net.metadata is not None
        assert self.pe.net.metadata.struct is not None
        assert self.pe.net.metadata.struct.Version is not None

        vbuf = self.pe.net.metadata.struct.Version
        assert isinstance(vbuf, bytes)

        return vbuf.rstrip(b"\x00").decode("utf-8")

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
