# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import io
import sys
import time
import logging
import argparse
from pathlib import Path

import rich
from pydantic import BaseModel
from rich.console import Console
from rich.logging import RichHandler

import capa.helpers
import capa.features.extractors.ida.idalib as idalib

if not idalib.has_idalib():
    raise RuntimeError("cannot find IDA idalib module.")

if not idalib.load_idalib():
    raise RuntimeError("failed to load IDA idalib module.")

import idaapi
import idapro
import ida_auto
import idautils
import ida_funcs

logger = logging.getLogger(__name__)


def colorbool(v: bool) -> str:
    if v:
        return f"[green]{str(v)}[/green]"
    else:
        return f"[red]{str(v)}[/red]"


def colorname(n: str) -> str:
    if n.startswith("sub_"):
        return n
    else:
        return f"[cyan]{n}[/cyan]"


class FunctionId(BaseModel):
    address: int
    is_library: bool
    is_thunk: bool
    name: str

    def to_row(self):
        row = [hex(self.address)]
        row.append(colorbool(self.is_library))
        row.append(colorbool(self.is_thunk))
        row.append(colorname(self.name))
        return row


def configure_logging(args):
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # use [/] after the logger name to reset any styling,
    # and prevent the color from carrying over to the message
    logformat = "[dim]%(name)s[/]: %(message)s"

    # set markup=True to allow the use of Rich's markup syntax in log messages
    rich_handler = RichHandler(markup=True, show_time=False, show_path=True, console=capa.helpers.log_console)
    rich_handler.setFormatter(logging.Formatter(logformat))

    # use RichHandler for root logger
    logging.getLogger().addHandler(rich_handler)

    if args.debug:
        logging.getLogger("capa").setLevel(logging.DEBUG)
        logging.getLogger("viv_utils").setLevel(logging.DEBUG)
    else:
        logging.getLogger("capa").setLevel(logging.ERROR)
        logging.getLogger("viv_utils").setLevel(logging.ERROR)


def get_flirt_matches(lib_only=True):
    for ea in idautils.Functions(start=None, end=None):
        f = idaapi.get_func(ea)
        is_thunk = bool(f.flags & idaapi.FUNC_THUNK)
        is_lib = bool(f.flags & idaapi.FUNC_LIB)
        fname = idaapi.get_func_name(ea)

        if lib_only and not is_lib:
            continue

        yield FunctionId(address=ea, is_library=is_lib, is_thunk=is_thunk, name=fname)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Identify library functions using FLIRT.")
    parser.add_argument(
        "input_file",
        type=Path,
        help="path to file to analyze",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    args = parser.parse_args(args=argv)

    configure_logging(args)

    time0 = time.time()

    # stderr=True is used here to redirect the spinner banner to stderr, so that users can redirect capa's output.
    console = Console(stderr=True, quiet=False)

    logger.debug("idalib: opening database...")
    # idalib writes to stdout (ugh), so we have to capture that
    # so as not to screw up structured output.
    with capa.helpers.stdout_redirector(io.BytesIO()):
        with console.status("analyzing program...", spinner="dots"):
            if idapro.open_database(str(args.input_file), run_auto_analysis=True):
                raise RuntimeError("failed to analyze input file")

        logger.debug("idalib: waiting for analysis...")

        ida_auto.auto_wait()
        logger.debug("idalib: opened database.")

    table = rich.table.Table()
    table.add_column("FVA")
    table.add_column("library?")
    table.add_column("thunk?")
    table.add_column("name")

    for i, fid in enumerate(get_flirt_matches()):
        table.add_row(*fid.to_row())
        if i > 50:
            break

    rich.print(table)

    for index in range(0, ida_funcs.get_idasgn_qty()):
        signame, optlibs, nmatches = ida_funcs.get_idasgn_desc_with_matches(index)
        rich.print(signame, optlibs, nmatches)

    idapro.close_database()

    min, sec = divmod(time.time() - time0, 60)
    logger.debug("FLIRT-based library identification ran for ~ %02d:%02dm", min, sec)


if __name__ == "__main__":
    sys.exit(main())
