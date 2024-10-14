# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
further requirements:
  - nltk
"""
import gzip
import logging
import collections
from typing import Dict
from pathlib import Path
from dataclasses import dataclass

import msgspec

import capa.features.extractors.strings

logger = logging.getLogger(__name__)


class LibraryString(msgspec.Struct):
    string: str
    library_name: str
    library_version: str
    file_path: str | None = None
    function_name: str | None = None
    line_number: int | None = None


@dataclass
class LibraryStringDatabase:
    metadata_by_string: Dict[str, LibraryString]

    def __len__(self) -> int:
        return len(self.metadata_by_string)

    @classmethod
    def from_file(cls, path: Path) -> "LibraryStringDatabase":
        metadata_by_string: Dict[str, LibraryString] = {}
        decoder = msgspec.json.Decoder(type=LibraryString)
        for line in gzip.decompress(path.read_bytes()).split(b"\n"):
            if not line:
                continue
            s = decoder.decode(line)
            metadata_by_string[s.string] = s

        return cls(metadata_by_string=metadata_by_string)


DEFAULT_FILENAMES = (
    "brotli.jsonl.gz",
    "bzip2.jsonl.gz",
    "cryptopp.jsonl.gz",
    "curl.jsonl.gz",
    "detours.jsonl.gz",
    "jemalloc.jsonl.gz",
    "jsoncpp.jsonl.gz",
    "kcp.jsonl.gz",
    "liblzma.jsonl.gz",
    "libsodium.jsonl.gz",
    "libpcap.jsonl.gz",
    "mbedtls.jsonl.gz",
    "openssl.jsonl.gz",
    "sqlite3.jsonl.gz",
    "tomcrypt.jsonl.gz",
    "wolfssl.jsonl.gz",
    "zlib.jsonl.gz",
)

DEFAULT_PATHS = tuple(Path(__file__).parent / "data" / "oss" / filename for filename in DEFAULT_FILENAMES) + (
    Path(__file__).parent / "data" / "crt" / "msvc_v143.jsonl.gz",
)


def get_default_databases() -> list[LibraryStringDatabase]:
    return [LibraryStringDatabase.from_file(path) for path in DEFAULT_PATHS]


@dataclass
class WindowsApiStringDatabase:
    dll_names: set[str]
    api_names: set[str]

    def __len__(self) -> int:
        return len(self.dll_names) + len(self.api_names)

    @classmethod
    def from_dir(cls, path: Path) -> "WindowsApiStringDatabase":
        dll_names: set[str] = set()
        api_names: set[str] = set()

        for line in gzip.decompress((path / "dlls.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            dll_names.add(line)

        for line in gzip.decompress((path / "apis.txt.gz").read_bytes()).decode("utf-8").splitlines():
            if not line:
                continue
            api_names.add(line)

        return cls(dll_names=dll_names, api_names=api_names)

    @classmethod
    def from_defaults(cls) -> "WindowsApiStringDatabase":
        return cls.from_dir(Path(__file__).parent / "data" / "winapi")


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

    winapi = WindowsApiStringDatabase.from_defaults()

    try:
        from nltk.corpus import words as nltk_words
        nltk_words.words()
    except ImportError:
        # one-time download of dataset.
        # this probably doesn't work well for embedded use.
        import nltk

        nltk.download("words")
        from nltk.corpus import words as nltk_words
    words = set(nltk_words.words())

    counter: collections.Counter[str] = collections.Counter()
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


def get_function_strings():
    import idaapi
    import idautils

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

                strings_by_function[ea].add(string)

    return strings_by_function
