# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

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

    logger.debug("enter get_sigpaths_from_doc")

    if doc.meta.argv:
        logger.debug("enter  if doc.meta.argv")
        try:
            logger.debug("enter try block")
            logger.debug(f"doc.meta.argv == {list(doc.meta.argv)}")
            if "-s" in list(doc.meta.argv):
                logger.debug("enter -s")
                idx = doc.meta.argv.index("-s")
                logger.debug("got -s idx")
                sigpath = Path(doc.meta.argv[idx + 1])
                logger.debug("got -s sigpath1")
                if "./" in str(sigpath):
                    logger.debug("in -s ./")
                    fixed_str = str(sigpath).split("./")[1]
                    logger.debug("got -s fixed_str")
                    sigpath = Path(fixed_str)
                    logger.debug("got -s sigpath2")

            elif "--signatures" in list(doc.meta.argv):
                logger.debug("enter --signatures")
                idx = doc.meta.argv.index("--signatures")
                logger.debug("got --signatures idx")
                sigpath = Path(doc.meta.argv[idx + 1])
                logger.debug("got --signatures sigpath1")
                if "./" in str(sigpath):
                    logger.debug("in --signatures ./ block")
                    fixed_str = str(sigpath).split("./")[1]
                    logger.debug("got --signatures fixed_str")
                    sigpath = Path(fixed_str)
                    logger.debug("got --signatures sigpath2")

            else:
                logger.debug("enter else block")
                sigpath = "(embedded)"  # type: ignore
                logger.debug("got else sigpath")

            logger.debug("attempt capa.loader.get_signatures(sigpath)")
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
