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
import tempfile
import contextlib
from pathlib import Path

import rich
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

import idapro
import ida_auto
import ida_funcs

logger = logging.getLogger(__name__)


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

    with ida_session(args.input_file, use_temp_dir=not args.store_idb):
        # TODO: add more signature (files)
        # TOOD: apply more signatures

        table = rich.table.Table()
        table.add_column("FVA")
        table.add_column("library?")
        table.add_column("thunk?")
        table.add_column("name")

        for fid in capa.analysis.flirt.get_flirt_matches(lib_only=False):
            table.add_row(*fid.to_row())

        rich.print(table)

        # TODO can we include which signature matched per function?
        for index in range(0, ida_funcs.get_idasgn_qty()):
            signame, optlibs, nmatches = ida_funcs.get_idasgn_desc_with_matches(index)
            rich.print(signame, optlibs, nmatches)

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

                            # TODO: ensure there aren't conflicts among the matches


if __name__ == "__main__":
    sys.exit(main())
