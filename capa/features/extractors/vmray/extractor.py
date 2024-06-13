# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import json
from typing import Tuple, Iterator
from pathlib import Path
from zipfile import ZipFile

import capa.helpers
import capa.features.extractors.vmray.file
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors.vmray import VMRayAnalysis
from capa.features.extractors.vmray.models import Analysis, SummaryV2
from capa.features.extractors.base_extractor import DynamicFeatureExtractor

# TODO also/or look into xmltodict?


class VMRayExtractor(DynamicFeatureExtractor):
    def __init__(self, analysis):
        self.analysis = analysis

    @classmethod
    def from_archive(cls, archive_path: Path):
        archive = ZipFile(archive_path, "r")

        sv2_json = json.loads(archive.read("logs/summary_v2.json", pwd=b"infected"))
        sv2 = SummaryV2.model_validate(sv2_json)

        flog_xml = archive.read("logs/flog.xml", pwd=b"infected")
        flog = Analysis.from_xml(flog_xml)

        return cls(VMRayAnalysis(sv2, flog))

    def get_base_address(self) -> Address:
        # value according to the PE header, the actual trace may use a different imagebase
        return AbsoluteVirtualAddress(self.analysis.base_address)

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.vmray.file.extract_features(self.analysis)


if __name__ == "__main__":
    import sys

    input_path = Path(sys.argv[1])

    extractor = VMRayExtractor.from_archive(input_path)
    for feat, addr in extractor.extract_file_features():
        print(f"{feat} -> {addr}")

    print(f"base address: {hex(extractor.get_base_address())}")