# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Tuple, Iterator

from capa.features.common import Feature
from capa.features.address import Address

# TODO(wb): 1755
TODOType = Any


def extract_file_export_names(be2: TODOType, buf: bytes) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_file_import_names(be2: TODOType, buf: bytes) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_file_section_names(be2: TODOType, buf: bytes) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_file_strings(be2: TODOType, buf: bytes) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_file_format(be2: TODOType, buf: bytes) -> Iterator[Tuple[Feature, Address]]:
    # TODO(wb): 1755
    yield from ()


def extract_features(be2: TODOType, buf: bytes) -> Iterator[Tuple[Feature, Address]]:
    """extract file features"""
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(be2, buf):
            yield feature, addr


FILE_HANDLERS = (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_strings,
    extract_file_section_names,
    extract_file_format,
)
