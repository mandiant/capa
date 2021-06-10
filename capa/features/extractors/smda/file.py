# if we have SMDA we definitely have lief
import lief

import capa.features.extractors.helpers
import capa.features.extractors.strings
from capa.features.file import Export, Import, Section
from capa.features.common import String, Characteristic


def extract_file_embedded_pe(smda_report, file_path):
    with open(file_path, "rb") as f:
        fbytes = f.read()

    for offset, i in capa.features.extractors.helpers.carve_pe(fbytes, 1):
        yield Characteristic("embedded pe"), offset


def extract_file_export_names(smda_report, file_path):
    lief_binary = lief.parse(file_path)
    if lief_binary is not None:
        for function in lief_binary.exported_functions:
            yield Export(function.name), function.address


def extract_file_import_names(smda_report, file_path):
    # extract import table info via LIEF
    lief_binary = lief.parse(file_path)
    if not isinstance(lief_binary, lief.PE.Binary):
        return
    for imported_library in lief_binary.imports:
        library_name = imported_library.name.lower()
        library_name = library_name[:-4] if library_name.endswith(".dll") else library_name
        for func in imported_library.entries:
            va = func.iat_address + smda_report.base_addr
            if func.name:
                for name in capa.features.extractors.helpers.generate_symbols(library_name, func.name):
                    yield Import(name), va
            elif func.is_ordinal:
                for name in capa.features.extractors.helpers.generate_symbols(library_name, "#%s" % func.ordinal):
                    yield Import(name), va


def extract_file_section_names(smda_report, file_path):
    lief_binary = lief.parse(file_path)
    if not isinstance(lief_binary, lief.PE.Binary):
        return
    if lief_binary and lief_binary.sections:
        base_address = lief_binary.optional_header.imagebase
        for section in lief_binary.sections:
            yield Section(section.name), base_address + section.virtual_address


def extract_file_strings(smda_report, file_path):
    """
    extract ASCII and UTF-16 LE strings from file
    """
    with open(file_path, "rb") as f:
        b = f.read()

    for s in capa.features.extractors.strings.extract_ascii_strings(b):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(b):
        yield String(s.s), s.offset


def extract_file_function_names(smda_report, file_path):
    """
    extract the names of statically-linked library functions.
    """
    if False:
        # using a `yield` here to force this to be a generator, not function.
        yield NotImplementedError("SMDA doesn't have library matching")
    return


def extract_features(smda_report, file_path):
    """
    extract file features from given workspace

    args:
      smda_report (smda.common.SmdaReport): a SmdaReport
      file_path: path to the input file

    yields:
      Tuple[Feature, VA]: a feature and its location.
    """

    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(smda_report, file_path):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
    extract_file_function_names,
)
