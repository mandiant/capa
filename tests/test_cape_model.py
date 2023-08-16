# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import gzip
from pathlib import Path

import fixtures

from capa.features.extractors.cape.models import CapeReport

CD = Path(__file__).resolve().parent
CAPE_DIR = CD / "data" / "dynamic" / "cape"


@fixtures.parametrize(
    "version,filename",
    [
        ("v2.2", "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz"),
        ("v2.2", "55dcd38773f4104b95589acc87d93bf8b4a264b4a6d823b73fb6a7ab8144c08b.json.gz"),
        ("v2.2", "77c961050aa252d6d595ec5120981abf02068c968f4a5be5958d10e87aa6f0e8.json.gz"),
        ("v2.2", "d46900384c78863420fb3e297d0a2f743cd2b6b3f7f82bf64059a168e07aceb7.json.gz"),
    ],
)
def test_cape_model_can_load(version: str, filename: str):
    path = CAPE_DIR / version / filename
    buf = gzip.decompress(path.read_bytes())
    report = CapeReport.from_buf(buf)
    assert report is not None
