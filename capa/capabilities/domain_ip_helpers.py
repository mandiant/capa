import logging
from pathlib import Path

from capa.helpers import get_auto_format
from capa.features.common import FORMAT_CAPE
from capa.render.result_document import ResultDocument
from capa.features.extractors.base_extractor import FeatureExtractor
from capa.features.extractors.cape.extractor import CapeExtractor

logger = logging.getLogger(__name__)

BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"
BACKEND_BINJA = "binja"
BACKEND_PEFILE = "pefile"


def get_file_path(doc: ResultDocument) -> Path:
    return Path(doc.meta.sample.path)


def get_sigpaths_from_doc(doc: ResultDocument):
    import capa.loader

    if doc.meta.argv:
        try:
            if "-s" in list(doc.meta.argv):
                idx = doc.meta.argv.index("-s")
                sigpath = Path(doc.meta.argv[idx + 1])
                if "./" in str(sigpath):
                    fixed_str = str(sigpath).split("./")[1]
                    sigpath = Path(fixed_str)

            elif "--signatures" in list(doc.meta.argv):
                idx = doc.meta.argv.index("--signatures")
                sigpath = Path(doc.meta.argv[idx + 1])
                if "./" in str(sigpath):
                    fixed_str = str(sigpath).split("./")[1]
                    sigpath = Path(fixed_str)

            else:
                sigpath = "(embedded)"  # type: ignore

            return capa.loader.get_signatures(sigpath)

        except AttributeError:
            raise NotImplementedError("Confirm that argv is an attribute of doc.meta")

    else:
        print("in 'get_sigpaths_from_doc', run in debug (-d) mode")
        logger.debug("'doc.meta' has not attribute 'argv', this is probably a bad sign...")


def get_extractor_from_doc(doc: ResultDocument) -> FeatureExtractor:
    import capa.loader

    path = get_file_path(doc)
    format = doc.meta.analysis.format
    os = doc.meta.analysis.os

    _ = get_auto_format(get_file_path(doc))
    if format == FORMAT_CAPE:
        report = capa.helpers.load_json_from_path(path)
        return CapeExtractor.from_report(report)
    elif _ == BACKEND_VIV:
        backend = BACKEND_VIV
    elif _ == BACKEND_PEFILE:
        backend = BACKEND_PEFILE
    elif _ == BACKEND_BINJA:
        backend = BACKEND_BINJA
    elif _ == BACKEND_DOTNET:
        backend = BACKEND_DOTNET
    else:
        backend = BACKEND_VIV  # according to main.py this is the default

    sigpath = get_sigpaths_from_doc(doc)

    return capa.loader.get_extractor(
        input_path=path,
        input_format=format,
        os_=os,
        backend=backend,
        sigpaths=sigpath,
    )
