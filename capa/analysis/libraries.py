"""
further requirements:
  - nltk
"""

import sys
import logging
import collections
from pathlib import Path

import rich
from rich.text import Text

import capa.analysis.strings
import capa.features.extractors.strings
from capa.analysis.strings import LibraryStringDatabase

logger = logging.getLogger(__name__)


def extract_strings(buf, n=4):
    yield from capa.features.extractors.strings.extract_ascii_strings(buf, n=n)
    yield from capa.features.extractors.strings.extract_unicode_strings(buf, n=n)


def prune_databases(dbs: list[LibraryStringDatabase], n=8):
    """remove less trustyworthy database entries.

    such as:
      - those found in multiple databases
      - those that are English words
      - those that are too short
      - Windows API and DLL names
    """

    # TODO: consider applying these filters directly to the persisted databases, not at load time.

    winapi = capa.analysis.strings.WindowsApiStringDatabase.from_defaults()
    
    try:
        from nltk.corpus import words as nltk_words
    except ImportError:
        # one-time download of dataset.
        # this probably doesn't work well for embedded use.
        import nltk
        nltk.download("words")
        from nltk.corpus import words as nltk_words
    words = set(nltk_words.words())

    counter = collections.Counter()
    to_remove = set()
    for db in dbs:
        for string in db.metadata_by_string.keys():
            counter[string] += 1

            if string in words:
                to_remove.add(string)
                continue

            if len(string) < n:
                to_remove.add(string)
                continue

            if string in winapi.api_names:
                to_remove.add(string)
                continue

            if string in winapi.dll_names:
                to_remove.add(string)
                continue

    for string, count in counter.most_common():
        if count <= 1:
            break

        # remove strings that are seen in more than one database
        to_remove.add(string)

    for db in dbs:
        for string in to_remove:
            if string in db.metadata_by_string:
                del db.metadata_by_string[string]


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
    input_buf = input_path.read_bytes()

    dbs = capa.analysis.strings.get_default_databases()
    prune_databases(dbs, n=N)

    strings_by_library = collections.defaultdict(set)
    for string in extract_strings(input_path.read_bytes(), n=N):
        for db in dbs:
            if (metadata := db.metadata_by_string.get(string.s)):
                strings_by_library[metadata.library_name].add(string.s)

    console = rich.get_console()
    console.print(f"found libraries:", style="bold")
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
    import capa.features.extractors.ida.helpers as ida_helpers

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
                    if (metadata := db.metadata_by_string.get(string)):
                        strings_by_function[ea].add(string)

    # ensure there are at least XXX functions renamed, or ignore those entries

    console.print("functions:", style="bold")
    for function, strings in sorted(strings_by_function.items()):
        if strings:
            name = ida_funcs.get_func_name(function)

            console.print(f"  [b]{name}[/]@{function:08x}:")

            for string in strings:
                for db in dbs:
                    if (metadata := db.metadata_by_string.get(string)):
                        location = Text(f"{metadata.library_name}@{metadata.library_version}::{metadata.function_name}", style="grey37")
                        console.print("    - ", location, ": ", string.rstrip())

                        # TODO: ensure there aren't conflicts among the matches

    console.print()

    console.print(f"found {len(strings_by_function)} library functions across {len(list(idautils.Functions()))} functions")


if __name__ == "__main__":
    main()
