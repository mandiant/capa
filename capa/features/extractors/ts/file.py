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
from functools import singledispatch

from capa.features.common import Feature, Namespace
from capa.features.address import Address
from capa.features.extractors.ts.engine import TreeSitterBaseEngine, TreeSitterBashEngine, TreeSitterExtractorEngine


def extract_namespaces(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for namespace in engine.get_processed_namespaces():
        if namespace.node is not None:
            yield Namespace(namespace.name), engine.get_address(namespace.node)


@singledispatch
def extract_features(engine: TreeSitterBaseEngine) -> Iterator[Tuple[Feature, Address]]:
    raise TypeError(f"unsupported Tree-Sitter engine: {type(engine).__name__}")


@extract_features.register
def _(engine: TreeSitterExtractorEngine) -> Iterator[Tuple[Feature, Address]]:
    for file_handler in FILE_HANDLERS:
        for feature, addr in file_handler(engine):
            yield feature, addr


@extract_features.register
def _(engine: TreeSitterBashEngine) -> Iterator[Tuple[Feature, Address]]:
    yield from ()


FILE_HANDLERS = (extract_namespaces,)
