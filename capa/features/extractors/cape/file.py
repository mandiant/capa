# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Dict, Tuple, Iterator

from capa.features.file import Export, Import, Section
from capa.features.common import String, Feature
from capa.features.address import NO_ADDRESS, Address, ProcessAddress, AbsoluteVirtualAddress
from capa.features.extractors.helpers import generate_symbols
from capa.features.extractors.base_extractor import ProcessHandle

logger = logging.getLogger(__name__)


def get_processes(static: Dict) -> Iterator[ProcessHandle]:
    """
    get all the created processes for a sample
    """

    def rec(process):
        address: ProcessAddress = ProcessAddress(pid=process["pid"], ppid=process["parent_id"])
        inner: Dict[str, str] = {"name": process["name"]}
        yield ProcessHandle(address=address, inner=inner)
        for child in process["children"]:
            yield from rec(child)

    for process in static["processtree"]:
        yield from rec(process)


def extract_import_names(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    """
    extract imported function names
    """
    imports = static["imports"]

    """
        2.2-CAPE
        "imports": [
            {
             "dll": "RPCRT4.dll",
             "imports": [{"address": "0x40504c","name": "NdrSimpleTypeUnmarshall"}, ...]
            },
            ...
        ]

        2.4-CAPE
        "imports": {
            "ADVAPI32": {
                "dll": "ADVAPI32.dll",
                "imports": [{"address": "0x522000", "name": "OpenSCManagerA"}, ...],
                ...
            },
            ...
        }
    """
    if isinstance(imports, dict):
        imports = imports.values()

    for library in imports:
        for function in library["imports"]:
            addr = int(function["address"], 16)
            for name in generate_symbols(library["dll"], function["name"]):
                yield Import(name), AbsoluteVirtualAddress(addr)


def extract_export_names(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for function in static["exports"]:
        name, address = function["name"], int(function["address"], 16)
        yield Export(name), AbsoluteVirtualAddress(address)


def extract_section_names(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    # be consistent with static extractors and use section VA
    base = int(static["imagebase"], 16)
    for section in static["sections"]:
        name, address = section["name"], int(section["virtual_address"], 16)
        yield Section(name), AbsoluteVirtualAddress(base + address)


def extract_file_strings(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for string_ in static["strings"]:
        yield String(string_), NO_ADDRESS


def extract_used_regkeys(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for regkey in static["keys"]:
        yield String(regkey), NO_ADDRESS


def extract_used_files(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for filename in static["files"]:
        yield String(filename), NO_ADDRESS


def extract_used_mutexes(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for mutex in static["mutexes"]:
        yield String(mutex), NO_ADDRESS


def extract_features(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for handler in FILE_HANDLERS:
        for feature, addr in handler(static):
            yield feature, addr


FILE_HANDLERS = (
    extract_import_names,
    extract_export_names,
    extract_section_names,
    extract_file_strings,
    extract_used_regkeys,
    extract_used_files,
    extract_used_mutexes,
)
