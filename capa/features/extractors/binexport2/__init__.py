# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
Proto files generated via protobuf v24.4:

    protoc --python_out=. --mypy_out=. binexport2.proto
"""
import os
import logging
from pathlib import Path
from dataclasses import dataclass

from capa.features.extractors.binexport2.binexport2_pb2 import BinExport2

logger = logging.getLogger(__name__)


def get_binexport2(sample: Path) -> BinExport2:
    be2 = BinExport2()
    be2.ParseFromString(sample.read_bytes())
    return be2


def get_sample_from_binexport2(be2: BinExport2) -> Path:
    # also search in same directory as input
    # for files with the given sha256,
    # starting with files with a similar prefix as given.
    # TODO(wb): 1755

    # $CAPA_SAMPLE_DIR/<sha256>
    base = Path(os.environ.get("CAPA_SAMPLES_DIR", "."))

    sha256 = be2.meta_information.executable_id.lower()

    logger.debug("searching for sample in: %s", base)
    path = base / sha256
    if path.exists():
        return path
    else:
        raise ValueError("cannot find sample")


@dataclass
class FunctionContext:
    be2: BinExport2
    function_index: int


@dataclass
class BasicBlockContext:
    be2: BinExport2
    basic_block_index: int


@dataclass
class InstructionContext:
    be2: BinExport2
    instruction_index: int
