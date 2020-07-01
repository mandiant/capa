import PE.carve as pe_carve  # vivisect PE

from capa.features import Characteristic
from capa.features.file import Export
from capa.features.file import Import
from capa.features.file import Section
from capa.features import String
import capa.features.extractors.strings


def extract_file_embedded_pe(vw, file_path):
    with open(file_path, 'rb') as f:
        fbytes = f.read()

    for offset, i in pe_carve.carve(fbytes, 1):
        yield Characteristic('embedded pe'), offset


def extract_file_export_names(vw, file_path):
    for va, etype, name, _ in vw.getExports():
        yield Export(name), va


def extract_file_import_names(vw, file_path):
    '''
    extract imported function names
    1. imports by ordinal:
     - modulename.#ordinal
    2. imports by name, results in two features to support importname-only matching:
     - modulename.importname
     - importname
    '''
    for va, _, _, tinfo in vw.getImports():
        # vivisect source: tinfo = "%s.%s" % (libname, impname)
        modname, impname = tinfo.split('.')
        if is_viv_ord_impname(impname):
            # replace ord prefix with #
            impname = '#%s' % impname[len('ord'):]
            tinfo = '%s.%s' % (modname, impname)
            yield Import(tinfo), va
        else:
            yield Import(tinfo), va
            yield Import(impname), va


def is_viv_ord_impname(impname):
    '''
    return if import name matches vivisect's ordinal naming scheme `'ord%d' % ord`
    '''
    if not impname.startswith('ord'):
        return False
    try:
        int(impname[len('ord'):])
    except ValueError:
        return False
    else:
        return True


def extract_file_section_names(vw, file_path):
    for va, _, segname, _ in vw.getSegments():
        yield Section(segname), va


def extract_file_strings(vw, file_path):
    '''
    extract ASCII and UTF-16 LE strings from file
    '''
    with open(file_path, 'rb') as f:
        b = f.read()

    for s in capa.features.extractors.strings.extract_ascii_strings(b):
        yield String(s.s), s.offset

    for s in capa.features.extractors.strings.extract_unicode_strings(b):
        yield String(s.s), s.offset


def extract_features(vw, file_path):
    '''
    extract file features from given workspace

    args:
      vw (vivisect.VivWorkspace): the vivisect workspace
      file_path: path to the input file

    yields:
      Tuple[Feature, VA]: a feature and its location.
    '''

    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(vw, file_path):
            yield feature, va


FILE_HANDLERS = (
    extract_file_embedded_pe,
    extract_file_export_names,
    extract_file_import_names,
    extract_file_section_names,
    extract_file_strings,
)
