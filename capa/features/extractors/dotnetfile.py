import logging
from typing import Tuple, Iterator

import dnfile
import pefile

import capa.features.extractors.helpers
from capa.features.file import Import, FunctionName
from capa.features.common import (
    OS,
    OS_ANY,
    ARCH_ANY,
    ARCH_I386,
    ARCH_AMD64,
    FORMAT_DOTNET,
    Arch,
    Class,
    Format,
    String,
    Feature,
    Namespace,
    Characteristic,
)
from capa.features.extractors.base_extractor import FeatureExtractor
from capa.features.extractors.dnfile.helpers import (
    is_dotnet_mixed_mode,
    is_dotnet_table_valid,
    format_dotnet_classname,
    format_dotnet_methodname,
    get_dotnet_managed_imports,
    get_dotnet_managed_methods,
    calculate_dotnet_token_value,
    get_dotnet_unmanaged_imports,
)

logger = logging.getLogger(__name__)


def extract_file_format(**kwargs) -> Iterator[Tuple[Format, int]]:
    yield Format(FORMAT_DOTNET), 0x0


def extract_file_import_names(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Import, int]]:
    for (token, namespace, class_, method) in get_dotnet_managed_imports(pe):
        # like System.IO.File::OpenRead
        yield Import(format_dotnet_methodname(namespace, class_, method)), token

    for (token, name) in get_dotnet_unmanaged_imports(pe):
        # like kernel32.CreateFileA
        dll, _, symbol = name.rpartition(".")
        for name_variant in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield Import(name_variant), token


def extract_file_function_names(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[FunctionName, int]]:
    for (token, namespace, class_, method) in get_dotnet_managed_methods(pe):
        yield FunctionName(format_dotnet_methodname(namespace, class_, method)), token


def extract_file_namespace_features(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Namespace, int]]:
    if not all((is_dotnet_table_valid(pe, "TypeDef"), is_dotnet_table_valid(pe, "TypeRef"))):
        return

    namespaces = set()
    for (rid, row) in enumerate(pe.net.mdtables.TypeDef):
        if not row.TypeNamespace:
            continue
        namespaces.add(row.TypeNamespace)

    for (rid, row) in enumerate(pe.net.mdtables.TypeRef):
        if not row.TypeNamespace:
            continue
        namespaces.add(row.TypeNamespace)

    for namespace in namespaces:
        yield Namespace(namespace), 0x0


def extract_file_class_features(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Class, int]]:
    if not all((is_dotnet_table_valid(pe, "TypeDef"), is_dotnet_table_valid(pe, "TypeRef"))):
        return

    for (rid, row) in enumerate(pe.net.mdtables.TypeDef):
        name = format_dotnet_classname(row.TypeNamespace, row.TypeName)
        token = calculate_dotnet_token_value(pe.net.mdtables.TypeDef.number, rid + 1)

        yield Class(name), token

    for (rid, row) in enumerate(pe.net.mdtables.TypeRef):
        name = format_dotnet_classname(row.TypeNamespace, row.TypeName)
        token = calculate_dotnet_token_value(pe.net.mdtables.TypeRef.number, rid + 1)
        yield Class(name), token


def extract_file_os(**kwargs) -> Iterator[Tuple[OS, int]]:
    yield OS(OS_ANY), 0x0


def extract_file_arch(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Arch, int]]:
    # to distinguish in more detail, see https://stackoverflow.com/a/23614024/10548020
    # .NET 4.5 added option: any CPU, 32-bit preferred
    if pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
        yield Arch(ARCH_I386), 0x0
    elif not pe.net.Flags.CLR_32BITREQUIRED and pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        yield Arch(ARCH_AMD64), 0x0
    else:
        yield Arch(ARCH_ANY), 0x0


def extract_file_strings(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[String, int]]:
    yield from capa.features.extractors.common.extract_file_strings(pe.__data__)


def extract_file_mixed_mode_characteristic_features(pe: dnfile.dnPE, **kwargs) -> Iterator[Tuple[Characteristic, int]]:
    if is_dotnet_mixed_mode(pe):
        yield Characteristic("mixed mode"), 0x0


def extract_file_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, int]]:
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(pe=pe):  # type: ignore
            yield feature, va


FILE_HANDLERS = (
    extract_file_import_names,
    extract_file_function_names,
    extract_file_strings,
    extract_file_format,
    extract_file_mixed_mode_characteristic_features,
    extract_file_namespace_features,
    extract_file_class_features,
)


def extract_global_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, int]]:
    for handler in GLOBAL_HANDLERS:
        for feature, va in handler(pe=pe):  # type: ignore
            yield feature, va


GLOBAL_HANDLERS = (
    extract_file_os,
    extract_file_arch,
)


class DotnetFileFeatureExtractor(FeatureExtractor):
    def __init__(self, path: str):
        super(DotnetFileFeatureExtractor, self).__init__()
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
        return is_dotnet_mixed_mode(self.pe)

    def get_runtime_version(self) -> Tuple[int, int]:
        return self.pe.net.struct.MajorRuntimeVersion, self.pe.net.struct.MinorRuntimeVersion

    def get_meta_version_string(self) -> str:
        return self.pe.net.metadata.struct.Version.rstrip(b"\x00").decode("utf-8")

    def get_functions(self):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def extract_function_features(self, f):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def get_basic_blocks(self, f):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def extract_basic_block_features(self, f, bb):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def get_instructions(self, f, bb):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def extract_insn_features(self, f, bb, insn):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def is_library_function(self, va):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")

    def get_function_name(self, va):
        raise NotImplementedError("DotnetFileFeatureExtractor can only be used to extract file features")
