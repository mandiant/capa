# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import fixtures

import capa.features.insn


def test_function_id_simple_match(pma16_01_extractor):
    assert pma16_01_extractor.is_library_function(0x407490) is True
    assert pma16_01_extractor.get_function_name(0x407490) == "__aulldiv"


def test_function_id_gz_pat(pma16_01_extractor):
    # aullrem is stored in `test_aullrem.pat.gz`
    assert pma16_01_extractor.is_library_function(0x407500) is True
    assert pma16_01_extractor.get_function_name(0x407500) == "__aullrem"


def test_function_id_complex_match(pma16_01_extractor):
    # 0x405714 is __spawnlp which requires recursive match of __spawnvp at 0x407FAB
    # (and __spawnvpe at 0x409DE8)
    assert pma16_01_extractor.is_library_function(0x405714) is True
    assert pma16_01_extractor.get_function_name(0x405714) == "__spawnlp"


def test_function_id_api_feature(pma16_01_extractor):
    f = fixtures.get_function(pma16_01_extractor, 0x404548)
    features = fixtures.extract_function_features(pma16_01_extractor, f)
    assert capa.features.insn.API("__aulldiv") in features
