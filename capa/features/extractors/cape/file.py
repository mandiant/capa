# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Any, Dict, List, Tuple, Iterator

from capa.features.common import Feature, String, Registry, Filename, Mutex
from capa.features.file import Section, Import, Export, FunctionName
from capa.features.address import Address, AbsoluteVirtualAddress, NO_ADDRESS


logger = logging.getLogger(__name__)


def extract_import_names(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    """
    extract the names of imported library files, for example: USER32.dll
    """
    for library in static["imports"]:
        name, address = library["name"], int(library["virtual_address"], 16)
        yield Import(name), address


def extract_export_names(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for function in static["exports"]:
        name, address = function["name"], int(function["virtual_address"], 16)
        yield Export(name), address


def extract_section_names(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for section in static["sections"]:
        name, address = section["name"], int(section["virtual_address"], 16)
        yield Section(name), address


def extract_function_names(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    """
    extract the names of imported functions.
    """
    for library in static["imports"]:
        for function in library["imports"]:
            name, address = function["name"], int(function["address"], 16)
            yield FunctionName(name), AbsoluteVirtualAddress(address)


def extract_file_strings(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for string_ in static["strings"]:
        yield String(string_), NO_ADDRESS


def extract_used_regkeys(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for regkey in static["keys"]:
        yield Registry(regkey), NO_ADDRESS


def extract_used_files(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for filename in static["files"]:
        yield Filename(filename), NO_ADDRESS


def extract_used_mutexes(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for mutex in static["mutexes"]:
        yield Mutex(mutex), NO_ADDRESS


def extract_features(static: Dict) -> Iterator[Tuple[Feature, Address]]:
    for handler in FILE_HANDLERS:
        for feature, addr in handler(static):
            yield feature, addr


FILE_HANDLERS = (
    extract_import_names,
    extract_export_names,
    extract_section_names,
    extract_function_names,
    extract_file_strings,
    extract_used_regkeys,
    extract_used_files,
    extract_used_mutexes,
)