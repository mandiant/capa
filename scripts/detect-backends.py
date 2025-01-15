# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import sys
import logging
import argparse
import importlib.util

import rich
import rich.table

import capa.main
from capa.features.extractors.ida.idalib import find_idalib, load_idalib, is_idalib_installed
from capa.features.extractors.binja.find_binja_api import find_binaryninja, load_binaryninja, is_binaryninja_installed

logger = logging.getLogger(__name__)


def is_vivisect_installed() -> bool:
    try:
        return importlib.util.find_spec("vivisect") is not None
    except ModuleNotFoundError:
        return False


def load_vivisect() -> bool:
    try:
        import vivisect  # noqa: F401 unused import

        return True
    except ImportError:
        return False


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Detect analysis backends.")
    capa.main.install_common_args(parser, wanted=set())
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    if args.debug:
        logging.getLogger("capa").setLevel(logging.DEBUG)
        logging.getLogger("viv_utils").setLevel(logging.DEBUG)
    else:
        logging.getLogger("capa").setLevel(logging.ERROR)
        logging.getLogger("viv_utils").setLevel(logging.ERROR)

    table = rich.table.Table()
    table.add_column("backend")
    table.add_column("already installed?")
    table.add_column("found?")
    table.add_column("loads?")

    if True:
        row = ["vivisect"]
        if is_vivisect_installed():
            row.append("True")
            row.append("-")
        else:
            row.append("False")
            row.append("False")

        row.append(str(load_vivisect()))
        table.add_row(*row)

    if True:
        row = ["Binary Ninja"]
        if is_binaryninja_installed():
            row.append("True")
            row.append("-")
        else:
            row.append("False")
            row.append(str(find_binaryninja() is not None))

        row.append(str(load_binaryninja()))
        table.add_row(*row)

    if True:
        row = ["IDA idalib"]
        if is_idalib_installed():
            row.append("True")
            row.append("-")
        else:
            row.append("False")
            row.append(str(find_idalib() is not None))

        row.append(str(load_idalib()))
        table.add_row(*row)

    rich.print(table)


if __name__ == "__main__":
    sys.exit(main())
