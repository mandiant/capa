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
from capa.exceptions import UnsupportedFormatError
from capa.features.common import FORMAT_CAPE, FORMAT_DOTNET, FORMAT_FREEZE, FORMAT_UNKNOWN
from capa.render.result_document import ResultDocument
from capa.features.extractors.base_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def get_file_path(doc: ResultDocument) -> Path:
    return Path(doc.meta.sample.path)


def get_sigpaths_from_doc(doc: ResultDocument):
    import capa.loader
    from capa.main import get_default_root

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
                sigpath = get_default_root() / "sigs"

            return capa.loader.get_signatures(sigpath)

        except AttributeError:
            raise NotImplementedError("Confirm that argv is an attribute of doc.meta")

    else:
        logger.debug("'doc.meta' has not attribute 'argv'")


def get_extractor_from_doc(doc: ResultDocument) -> FeatureExtractor:
    # import here to avoid circular import
    from capa.loader import BACKEND_VIV, BACKEND_CAPE, BACKEND_DOTNET, BACKEND_FREEZE, get_extractor

    path = get_file_path(doc)
    os = doc.meta.analysis.os

    if doc.meta.argv:
        args = tuple(doc.meta.argv)
    else:
        CommandLineArgumentsError("Couldn't find command line arguments!")

    for i in range(len(args)):
        if args[i] == any(["-f", "--format"]):
            format = args[i + 1]
            break
        else:
            format = ""

    if format == "":
        format = get_auto_format(path)
        if format == FORMAT_UNKNOWN:
            raise UnsupportedFormatError(f"Couldn't get format for {path.name}")

    for i in range(len(args)):
        if args[i] == any(["-b", "--backend"]):
            backend = args[i + 1]
            break
        elif format == FORMAT_CAPE:
            backend = BACKEND_CAPE
            break
        elif format == FORMAT_DOTNET:
            backend = BACKEND_DOTNET
            break
        elif format == FORMAT_FREEZE:
            backend = BACKEND_FREEZE
            break
        else:
            backend = ""

    if backend == "":
        backend = BACKEND_VIV

    sigpath = get_sigpaths_from_doc(doc)

    import capa.helpers

    logger.debug(f"running standable == {capa.helpers.is_running_standalone}")

    raise QuickExitError()

    return get_extractor(
        input_path=path,
        input_format=format,
        os_=os,
        backend=backend,
        sigpaths=sigpath,
    )


class CommandLineArgumentsError(BaseException):
    pass

class QuickExitError(BaseException):
    pass
