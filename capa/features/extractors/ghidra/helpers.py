# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Any, Dict, Tuple, Iterator, Optional


def find_byte_sequence(seq: bytes) -> Iterator[int]:
    """yield all ea of a given byte sequence

    args:
        seq: bytes to search e.g. b"\x01\x03"
    """
    seqstr = "".join([f"\\x{b:02x}" for b in seq])
    ea = findBytes(currentProgram.getMinAddress().add(1), seqstr, 1, 1)
    for e in ea:
        yield e
