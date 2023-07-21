# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging

import pytest
import fixtures

from capa.features.extractors.base_extractor import SampleHashes

logger = logging.getLogger(__name__)


@fixtures.parametrize(
    "extractor,hashes",
    fixtures.EXTRACTOR_HASHING_TESTS,
)
def test_hash_extraction(extractor, hashes):
    assert extractor.get_sample_hashes() == hashes


# We need to skip the binja test if we cannot import binaryninja, e.g., in GitHub CI.
binja_present: bool = False
try:
    import binaryninja

    try:
        binaryninja.load(source=b"\x90")
    except RuntimeError:
        logger.warning("Binary Ninja license is not valid, provide via $BN_LICENSE or license.dat")
    else:
        binja_present = True
except ImportError:
    pass


@pytest.mark.skipif(binja_present is False, reason="Skip binja tests if the binaryninja Python API is not installed")
def test_binja_hash_extraction():
    extractor = fixtures.get_binja_extractor(fixtures.get_data_path_by_name("mimikatz"))
    hashes = SampleHashes(
        md5="5f66b82558ca92e54e77f216ef4c066c",
        sha1="e4f82e4d7f22938dc0a0ff8a4a7ad2a763643d38",
        sha256="131314a6f6d1d263c75b9909586b3e1bd837036329ace5e69241749e861ac01d",
    )
    assert extractor.get_sample_hashes() == hashes
