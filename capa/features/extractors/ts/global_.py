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

from typing import Tuple, Iterator

import capa.features.extractors.script
from capa.features.common import Feature
from capa.features.address import Address


def extract_arch() -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_arch()


def extract_os() -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_os()


def extract_file_format() -> Iterator[Tuple[Feature, Address]]:
    yield from capa.features.extractors.script.extract_format()


def extract_features() -> Iterator[Tuple[Feature, Address]]:
    for glob_handler in GLOBAL_HANDLERS:
        for feature, addr in glob_handler():
            yield feature, addr


GLOBAL_HANDLERS = (extract_arch, extract_os, extract_file_format)
