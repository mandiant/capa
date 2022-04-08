# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Tuple, Iterator

if TYPE_CHECKING:
    import dnfile
    from capa.features.common import Feature, Format
    from capa.features.file import Import

import capa.features.extractors


def extract_file_import_names(pe: dnfile.dnPE) -> Iterator[Tuple[Import, int]]:
    yield from capa.features.extractors.dotnetfile.extract_file_import_names(pe)


def extract_file_format(pe: dnfile.dnPE) -> Iterator[Tuple[Format, int]]:
    yield from capa.features.extractors.dotnetfile.extract_file_format(pe=pe)


def extract_features(pe: dnfile.dnPE) -> Iterator[Tuple[Feature, int]]:
    for file_handler in FILE_HANDLERS:
        for (feature, token) in file_handler(pe):
            yield feature, token


FILE_HANDLERS = (
    extract_file_import_names,
    # TODO extract_file_strings,
    # TODO extract_file_function_names,
    extract_file_format,
)
