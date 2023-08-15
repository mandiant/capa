# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import gzip

import fixtures

from capa.features.extractors.cape.models import CapeReport


def test_cape_model_can_load():
    path = fixtures.get_data_path_by_name("0000a657")
    buf = gzip.decompress(path.read_bytes())
    report = CapeReport.from_buf(buf)
    assert report is not None
