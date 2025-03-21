# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import annotations

from typing import Iterator

import dnfile

import capa.features.extractors.dotnetfile
from capa.features.file import Import, FunctionName
from capa.features.common import Class, Format, String, Feature, Namespace, Characteristic
from capa.features.address import Address


def extract_file_import_names(ctx) -> Iterator[tuple[Import, Address]]:
    yield from capa.features.extractors.dotnetfile.extract_file_import_names(pe=ctx["pe"])


def extract_file_format(ctx) -> Iterator[tuple[Format, Address]]:
    yield from capa.features.extractors.dotnetfile.extract_file_format(pe=ctx["pe"])


def extract_file_function_names(ctx) -> Iterator[tuple[FunctionName, Address]]:
    yield from capa.features.extractors.dotnetfile.extract_file_function_names(pe=ctx["pe"])


def extract_file_strings(ctx) -> Iterator[tuple[String, Address]]:
    yield from capa.features.extractors.dotnetfile.extract_file_strings(pe=ctx["pe"])


def extract_file_mixed_mode_characteristic_features(ctx) -> Iterator[tuple[Characteristic, Address]]:
    yield from capa.features.extractors.dotnetfile.extract_file_mixed_mode_characteristic_features(pe=ctx["pe"])


def extract_file_namespace_features(ctx) -> Iterator[tuple[Namespace, Address]]:
    yield from capa.features.extractors.dotnetfile.extract_file_namespace_features(pe=ctx["pe"])


def extract_file_class_features(ctx) -> Iterator[tuple[Class, Address]]:
    yield from capa.features.extractors.dotnetfile.extract_file_class_features(pe=ctx["pe"])


def extract_features(ctx) -> Iterator[tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, address in file_handler(ctx={"pe": ctx["pe"], "min_str_len": ctx["min_str_len"]}):
            yield feature, address


FILE_HANDLERS = (
    extract_file_import_names,
    extract_file_function_names,
    extract_file_strings,
    extract_file_format,
    extract_file_mixed_mode_characteristic_features,
    extract_file_namespace_features,
    extract_file_class_features,
)
