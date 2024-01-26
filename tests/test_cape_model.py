# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import gzip
from typing import Type
from pathlib import Path

import pytest
import fixtures

from capa.exceptions import EmptyReportError, UnsupportedFormatError
from capa.features.extractors.cape.models import Call, CapeReport

CD = Path(__file__).resolve().parent
CAPE_DIR = CD / "data" / "dynamic" / "cape"


@fixtures.parametrize(
    "version,filename",
    [
        ("v2.2", "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz"),
        ("v2.2", "55dcd38773f4104b95589acc87d93bf8b4a264b4a6d823b73fb6a7ab8144c08b.json.gz"),
        ("v2.2", "77c961050aa252d6d595ec5120981abf02068c968f4a5be5958d10e87aa6f0e8.json.gz"),
        ("v2.2", "d46900384c78863420fb3e297d0a2f743cd2b6b3f7f82bf64059a168e07aceb7.json.gz"),
        ("v2.4", "36d218f384010cce9f58b8193b7d8cc855d1dff23f80d16e13a883e152d07921.json.gz"),
        ("v2.4", "41ce492f04accef7931b84b8548a6ca717ffabb9bedc4f624de2d37a5345036c.json.gz"),
        ("v2.4", "515a6269965ccdf1005008e017ec87fafb97fd2464af1c393ad93b438f6f33fe.json.gz"),
        ("v2.4", "5d61700feabba201e1ba98df3c8210a3090c8c9f9adbf16cb3d1da3aaa2a9d96.json.gz"),
        ("v2.4", "5effaf6795932d8b36755f89f99ce7436421ea2bd1ed5bc55476530c1a22009f.json.gz"),
        ("v2.4", "873275144af88e9b95ea2c59ece39b8ce5a9d7fe09774b683050098ac965054d.json.gz"),
        ("v2.4", "8b9aaf4fad227cde7a7dabce7ba187b0b923301718d9d40de04bdd15c9b22905.json.gz"),
        ("v2.4", "b1c4aa078880c579961dc5ec899b2c2e08ae5db80b4263e4ca9607a68e2faef9.json.gz"),
        ("v2.4", "fb7ade52dc5a1d6128b9c217114a46d0089147610f99f5122face29e429a1e74.json.gz"),
    ],
)
def test_cape_model_can_load(version: str, filename: str):
    path = CAPE_DIR / version / filename
    buf = gzip.decompress(path.read_bytes())
    report = CapeReport.from_buf(buf)
    assert report is not None


@fixtures.parametrize(
    "version,filename,exception",
    [
        ("v2.2", "0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz", None),
        ("v2.2", "55dcd38773f4104b95589acc87d93bf8b4a264b4a6d823b73fb6a7ab8144c08b.json.gz", None),
        ("v2.2", "77c961050aa252d6d595ec5120981abf02068c968f4a5be5958d10e87aa6f0e8.json.gz", EmptyReportError),
        ("v2.2", "d46900384c78863420fb3e297d0a2f743cd2b6b3f7f82bf64059a168e07aceb7.json.gz", None),
        ("v2.4", "36d218f384010cce9f58b8193b7d8cc855d1dff23f80d16e13a883e152d07921.json.gz", UnsupportedFormatError),
        ("v2.4", "41ce492f04accef7931b84b8548a6ca717ffabb9bedc4f624de2d37a5345036c.json.gz", UnsupportedFormatError),
        ("v2.4", "515a6269965ccdf1005008e017ec87fafb97fd2464af1c393ad93b438f6f33fe.json.gz", UnsupportedFormatError),
        ("v2.4", "5d61700feabba201e1ba98df3c8210a3090c8c9f9adbf16cb3d1da3aaa2a9d96.json.gz", UnsupportedFormatError),
        ("v2.4", "5effaf6795932d8b36755f89f99ce7436421ea2bd1ed5bc55476530c1a22009f.json.gz", UnsupportedFormatError),
        ("v2.4", "873275144af88e9b95ea2c59ece39b8ce5a9d7fe09774b683050098ac965054d.json.gz", UnsupportedFormatError),
        ("v2.4", "8b9aaf4fad227cde7a7dabce7ba187b0b923301718d9d40de04bdd15c9b22905.json.gz", UnsupportedFormatError),
        ("v2.4", "b1c4aa078880c579961dc5ec899b2c2e08ae5db80b4263e4ca9607a68e2faef9.json.gz", UnsupportedFormatError),
        ("v2.4", "fb7ade52dc5a1d6128b9c217114a46d0089147610f99f5122face29e429a1e74.json.gz", None),
    ],
)
def test_cape_extractor(version: str, filename: str, exception: Type[BaseException]):
    path = CAPE_DIR / version / filename

    if exception:
        with pytest.raises(exception):
            _ = fixtures.get_cape_extractor(path)
    else:
        cr = fixtures.get_cape_extractor(path)
        assert cr is not None


def test_cape_model_argument():
    call = Call.model_validate_json(
        """
        {
            "timestamp": "2023-10-20 12:30:14,015",
            "thread_id": "2380",
            "caller": "0x7797dff8",
            "parentcaller": "0x77973486",
            "category": "system",
            "api": "TestApiCall",
            "status": true,
            "return": "0x00000000",
            "arguments": [
              {
                "name": "Value Base 10",
                "value": "30"
              },
              {
                "name": "Value Base 16",
                "value": "0x30"
              }
            ],
            "repeated": 19,
            "id": 0
        }
        """
    )
    assert call.arguments[0].value == 30
    assert call.arguments[1].value == 0x30
