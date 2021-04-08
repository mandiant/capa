# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import codecs

from capa.features.extractors import helpers


def test_all_zeros():
    a = b"\x00\x00\x00\x00"
    b = codecs.decode("00000000", "hex")
    c = b"\x01\x00\x00\x00"
    d = codecs.decode("01000000", "hex")
    assert helpers.all_zeros(a) is True
    assert helpers.all_zeros(b) is True
    assert helpers.all_zeros(c) is False
    assert helpers.all_zeros(d) is False
