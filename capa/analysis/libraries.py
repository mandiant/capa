# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import io
import sys
import logging
import argparse
import tempfile
import contextlib
from enum import Enum
from typing import List, Optional
from pathlib import Path

import rich
from pydantic import BaseModel
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

logger = logging.getLogger(__name__)


class Classification(str, Enum):
    USER = "user"
    LIBRARY = "library"
    UNKNOWN = "unknown"


class Method(str, Enum):
    FLIRT = "flirt"
    STRINGS = "strings"
    THUNK = "thunk"
    ENTRYPOINT = "entrypoint"


class FunctionClassification(BaseModel):
    va: int
    classification: Classification
    # name per the disassembler/analysis tool
    # may be combined with the recovered/suspected name TODO below
    name: str

    # if is library, this must be provided
    method: Optional[Method]

    # TODO if is library, recovered/suspected name?

    # if is library, these can optionally be provided.
    library_name: Optional[str] = None
    library_version: Optional[str] = None


class FunctionIdResults(BaseModel):
    function_classifications: List[FunctionClassification]


@contextlib.contextmanager
def ida_session(input_path: Path, use_temp_dir=True):
    if use_temp_dir:
        t = Path(tempfile.mkdtemp(prefix="ida-")) / input_path.name
    else:
        t = input_path

    logger.debug("using %s", str(t))
    # stderr=True is used here to redirect the spinner banner to stderr,
    # so that users can redirect capa's output.
    console = Console(stderr=True, quiet=False)

    try:
        if use_temp_dir:
            t.write_bytes(input_path.read_bytes())

        # idalib writes to stdout (ugh), so we have to capture that
        # so as not to screw up structured output.
        with capa.helpers.stdout_redirector(io.BytesIO()):
            idapro.enable_console_messages(False)
            with capa.main.timing("analyze program"):
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


def is_thunk_function(fva):
    f = idaapi.get_func(fva)
    return bool(f.flags & idaapi.FUNC_THUNK)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Identify library functions using various strategies.")
    capa.main.install_common_args(parser, wanted={"input_file"})
    parser.add_argument("--store-idb", action="store_true", default=False, help="store IDA database file")
    parser.add_argument("--min-string-length", type=int, default=8, help="minimum string length")
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    dbs = capa.analysis.strings.get_default_databases()
    capa.analysis.strings.prune_databases(dbs, n=args.min_string_length)

    function_classifications: List[FunctionClassification] = []
    with ida_session(args.input_file, use_temp_dir=not args.store_idb):
        with capa.main.timing("FLIRT-based library identification"):
            # TODO: add more signature (files)
            # TOOD: apply more signatures
            for flirt_match in capa.analysis.flirt.get_flirt_matches():
                function_classifications.append(
                    FunctionClassification(
                        va=flirt_match.va,
                        name=flirt_match.name,
                        classification=Classification.LIBRARY,
                        method=Method.FLIRT,
                        # note: we cannot currently include which signature matched per function via the IDA API
                    )
                )

        # thunks
        for fva in idautils.Functions():
            if is_thunk_function(fva):
                function_classifications.append(
                    FunctionClassification(
                        va=fva,
                        name=idaapi.get_func_name(fva),
                        classification=Classification.LIBRARY,
                        method=Method.THUNK,
                    )
                )

        with capa.main.timing("string-based library identification"):
            for string_match in capa.analysis.strings.get_string_matches(dbs):
                function_classifications.append(
                    FunctionClassification(
                        va=string_match.va,
                        name=idaapi.get_func_name(string_match.va),
                        classification=Classification.LIBRARY,
                        method=Method.STRINGS,
                        library_name=string_match.metadata.library_name,
                        library_version=string_match.metadata.library_version,
                    )
                )

        for va in idautils.Functions():
            name = idaapi.get_func_name(va)
            if name not in {
                "WinMain",
            }:
                continue

            function_classifications.append(
                FunctionClassification(
                    va=va,
                    name=name,
                    classification=Classification.USER,
                    method=Method.ENTRYPOINT,
                )
            )

        doc = FunctionIdResults(function_classifications=[])
        classifications_by_va = capa.analysis.strings.create_index(function_classifications, "va")
        for va in idautils.Functions():
            if classifications := classifications_by_va.get(va):
                doc.function_classifications.extend(classifications)
            else:
                doc.function_classifications.append(
                    FunctionClassification(
                        va=va,
                        name=idaapi.get_func_name(va),
                        classification=Classification.UNKNOWN,
                        method=None,
                    )
                )

        if args.json:
            print(doc.model_dump_json())  # noqa: T201 print found

        else:
            table = rich.table.Table()
            table.add_column("FVA")
            table.add_column("CLASSIFICATION")
            table.add_column("METHOD")
            table.add_column("FNAME")
            table.add_column("EXTRA INFO")

            classifications_by_va = capa.analysis.strings.create_index(doc.function_classifications, "va", sorted_=True)
            for va, classifications in classifications_by_va.items():
                name = ", ".join({c.name for c in classifications})
                if "sub_" in name:
                    name = Text(name, style="grey53")

                classification = {c.classification for c in classifications}
                method = {c.method for c in classifications if c.method}
                extra = {f"{c.library_name}@{c.library_version}" for c in classifications if c.library_name}

                table.add_row(
                    hex(va),
                    ", ".join(classification) if classification != {"unknown"} else Text("unknown", style="grey53"),
                    ", ".join(method),
                    name,
                    ", ".join(extra),
                )

            rich.print(table)


if __name__ == "__main__":
    sys.exit(main())
