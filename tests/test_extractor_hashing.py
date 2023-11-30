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


def test_viv_hash_extraction():
    assert fixtures.get_viv_extractor(fixtures.get_data_path_by_name("mimikatz")).get_sample_hashes() == SampleHashes(
        md5="5f66b82558ca92e54e77f216ef4c066c",
        sha1="e4f82e4d7f22938dc0a0ff8a4a7ad2a763643d38",
        sha256="131314a6f6d1d263c75b9909586b3e1bd837036329ace5e69241749e861ac01d",
    )


def test_pefile_hash_extraction():
    assert fixtures.get_pefile_extractor(
        fixtures.get_data_path_by_name("mimikatz")
    ).get_sample_hashes() == SampleHashes(
        md5="5f66b82558ca92e54e77f216ef4c066c",
        sha1="e4f82e4d7f22938dc0a0ff8a4a7ad2a763643d38",
        sha256="131314a6f6d1d263c75b9909586b3e1bd837036329ace5e69241749e861ac01d",
    )


def test_dnfile_hash_extraction():
    assert fixtures.get_dnfile_extractor(fixtures.get_data_path_by_name("b9f5b")).get_sample_hashes() == SampleHashes(
        md5="b9f5bd514485fb06da39beff051b9fdc",
        sha1="c72a2e50410475a51d897d29ffbbaf2103754d53",
        sha256="34acc4c0b61b5ce0b37c3589f97d1f23e6d84011a241e6f85683ee517ce786f1",
    )


def test_dotnetfile_hash_extraction():
    assert fixtures.get_dotnetfile_extractor(
        fixtures.get_data_path_by_name("b9f5b")
    ).get_sample_hashes() == SampleHashes(
        md5="b9f5bd514485fb06da39beff051b9fdc",
        sha1="c72a2e50410475a51d897d29ffbbaf2103754d53",
        sha256="34acc4c0b61b5ce0b37c3589f97d1f23e6d84011a241e6f85683ee517ce786f1",
    )


def test_cape_hash_extraction():
    assert fixtures.get_cape_extractor(fixtures.get_data_path_by_name("0000a657")).get_sample_hashes() == SampleHashes(
        md5="e2147b5333879f98d515cd9aa905d489",
        sha1="ad4d520fb7792b4a5701df973d6bd8a6cbfbb57f",
        sha256="0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82",
    )


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
