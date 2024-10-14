# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import io
import sys
import json
import time
import logging
import argparse
import tempfile
import contextlib
import collections
from enum import Enum
from typing import List, Literal, Optional
from pathlib import Path

import rich
from pydantic import Field, BaseModel
from rich.text import Text
from rich.console import Console

import capa.main
import capa.helpers
import capa.analysis.flirt
import capa.analysis.strings
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


class Classification(str, Enum):
    USER = "user"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class Method(str, Enum):
    FLIRT = "flirt"
    STRINGS = "strings"


class FunctionClassification(BaseModel):
    va: int  # rva? va?
    classification: Literal[Classification.USER, Classification.LIBRARY, Classification.UNKNOWN]
    method: Literal[Method.FLIRT, Method.STRINGS]
    # if is library
    library_name: Optional[str] = None
    library_version: Optional[str] = None


class Layout(BaseModel):
    functions: List[int] = list()


class FunctionIdResults(BaseModel):
    function_classifications: List[FunctionClassification] = list()
    # layout: Layout


@contextlib.contextmanager
def ida_session(input_path: Path, use_temp_dir=True):
    if use_temp_dir:
        t = Path(tempfile.mkdtemp(prefix="ida-")) / input_path.name
    else:
        t = input_path

    logger.debug("using %s", str(t))
    # stderr=True is used here to redirect the spinner banner to stderr, so that users can redirect capa's output.
    console = Console(stderr=True, quiet=False)

    try:
        if use_temp_dir:
            t.write_bytes(input_path.read_bytes())

        # idalib writes to stdout (ugh), so we have to capture that
        # so as not to screw up structured output.
        with capa.helpers.stdout_redirector(io.BytesIO()):
            idapro.enable_console_messages(False)
            with console.status("analyzing program...", spinner="dots"):
                if idapro.open_database(str(t.absolute()), run_auto_analysis=True):
                    raise RuntimeError("failed to analyze input file")

            logger.debug("idalib: waiting for analysis...")
            ida_auto.auto_wait()
            logger.debug("idalib: opened database.")

        yield
    finally:
        idapro.close_database()
        if use_temp_dir:
            t.unlink()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Identify library functions using various strategies.")
    capa.main.install_common_args(parser, wanted={"input_file"})
    parser.add_argument("--store-idb", action="store_true", default=False, help="store IDA database file")
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    N = 8
    time0 = time.time()

    results = FunctionIdResults()

    with ida_session(args.input_file, use_temp_dir=not args.store_idb):
        # TODO: add more signature (files)
        # TOOD: apply more signatures

        for fid in capa.analysis.flirt.get_flirt_matches(lib_only=False):
            results.function_classifications.append(
                FunctionClassification(
                    va=fid.address,
                    classification=Classification.LIBRARY,
                    method=Method.FLIRT,
                    # note: we cannot currently include which signature matched per function via the IDA API
                )
            )

        min, sec = divmod(time.time() - time0, 60)
        logger.debug("FLIRT-based library identification ran for ~ %02d:%02dm", min, sec)

        dbs = capa.analysis.strings.get_default_databases()
        capa.analysis.strings.prune_databases(dbs, n=N)

        console = rich.get_console()
        for function, strings in sorted(capa.analysis.strings.get_function_strings().items()):

            matched_strings = set()
            for string in strings:
                for db in dbs:
                    if string in db.metadata_by_string:
                        matched_strings.add(string)

            if matched_strings:
                name = ida_funcs.get_func_name(function)

                console.print(f"  [b]{name}[/]@{function:08x}:")

                for string in matched_strings:
                    for db in dbs:
                        if metadata := db.metadata_by_string.get(string):
                            location = Text(
                                f"{metadata.library_name}@{metadata.library_version}::{metadata.function_name}",
                                style="grey37",
                            )
                            console.print("    - ", location, ": ", string.rstrip())

                            results.function_classifications.append(
                                FunctionClassification(
                                    va=function,
                                    classification=Classification.LIBRARY,
                                    method=Method.STRINGS,
                                    library_name=metadata.library_name,
                                    library_version=metadata.library_version,
                                )
                            )

                            # TODO: ensure there aren't conflicts among the matches

    # RENDER
    table = rich.table.Table()
    table.add_column("FVA")
    # table.add_column("FNAME")
    table.add_column("CLASSIFICATION")
    table.add_column("METHOD")
    table.add_column("EXTRA INFO")

    idx = collections.defaultdict(list)
    for r in sorted(results.function_classifications, key=lambda d: d.va):
        # idx[r.va].append(r)
        table.add_row(
            *[
                hex(r.va),
                # bug? idaapi.get_func_name(r.va),
                r.classification,
                r.method,
                f"{r.library_name}@{r.library_version}" if r.library_name else "",
            ]
        )

    # bug in IDA (no-op) when calling generator again?
    # for va in idautils.Functions(start=0, end=None):
    #     if va in idx:
    #         for d in idx[va]:
    #             table.add_row([hex(va), ida_funcs.get_func_name(va), d.classification, d.method])
    #     else:
    #         table.add_row([hex(va)])

    rich.print(table)


if __name__ == "__main__":
    sys.exit(main())
