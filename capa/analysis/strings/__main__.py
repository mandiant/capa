# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import logging
import collections
from pathlib import Path

import rich
from rich.text import Text

import capa.analysis.strings
import capa.features.extractors.strings
import capa.features.extractors.ida.helpers as ida_helpers

logger = logging.getLogger(__name__)


def open_ida(input_path: Path):
    import tempfile

    import idapro

    t = Path(tempfile.mkdtemp(prefix="ida-")) / input_path.name
    t.write_bytes(input_path.read_bytes())
    # resource leak: we should delete this upon exit

    idapro.enable_console_messages(False)
    idapro.open_database(str(t.absolute()), run_auto_analysis=True)

    import ida_auto

    ida_auto.auto_wait()


def main():
    logging.basicConfig(level=logging.DEBUG)

    # use n=8 to ignore common words
    N = 8

    input_path = Path(sys.argv[1])

    dbs = capa.analysis.strings.get_default_databases()
    capa.analysis.strings.prune_databases(dbs, n=N)

    strings_by_library = collections.defaultdict(set)
    for string in capa.analysis.strings.extract_strings(input_path.read_bytes(), n=N):
        for db in dbs:
            if metadata := db.metadata_by_string.get(string.s):
                strings_by_library[metadata.library_name].add(string.s)

    console = rich.get_console()
    console.print("found libraries:", style="bold")
    for library, strings in sorted(strings_by_library.items(), key=lambda p: len(p[1]), reverse=True):
        console.print(f"  - [b]{library}[/] ({len(strings)} strings)")

        for string in sorted(strings)[:10]:
            console.print(f"    - {string}", markup=False, style="grey37")

        if len(strings) > 10:
            console.print("    ...", style="grey37")

    if not strings_by_library:
        console.print("  (none)", style="grey37")
        # since we're not going to find any strings
        # return early and don't do IDA analysis
        return

    # TODO: ensure there are XXX matches for each library, or ignore those entries

    open_ida(input_path)

    import idaapi
    import idautils
    import ida_funcs

    strings_by_function = collections.defaultdict(set)
    for ea in idautils.Functions():
        f = idaapi.get_func(ea)

        # ignore library functions and thunk functions as identified by IDA
        if f.flags & idaapi.FUNC_THUNK:
            continue
        if f.flags & idaapi.FUNC_LIB:
            continue

        for bb in ida_helpers.get_function_blocks(f):
            for insn in ida_helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
                ref = capa.features.extractors.ida.helpers.find_data_reference_from_insn(insn)
                if ref == insn.ea:
                    continue

                string = capa.features.extractors.ida.helpers.find_string_at(ref)
                if not string:
                    continue

                for db in dbs:
                    if metadata := db.metadata_by_string.get(string):
                        strings_by_function[ea].add(string)

    # ensure there are at least XXX functions renamed, or ignore those entries

    console.print("functions:", style="bold")
    for function, strings in sorted(strings_by_function.items()):
        if strings:
            name = ida_funcs.get_func_name(function)

            console.print(f"  [b]{name}[/]@{function:08x}:")

            for string in strings:
                for db in dbs:
                    if metadata := db.metadata_by_string.get(string):
                        location = Text(
                            f"{metadata.library_name}@{metadata.library_version}::{metadata.function_name}",
                            style="grey37",
                        )
                        console.print("    - ", location, ": ", string.rstrip())

                        # TODO: ensure there aren't conflicts among the matches

    console.print()

    console.print(
        f"found {len(strings_by_function)} library functions across {len(list(idautils.Functions()))} functions"
    )


if __name__ == "__main__":
    main()
