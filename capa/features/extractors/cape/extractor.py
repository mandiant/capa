# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Dict, Tuple, Iterator

import capa.features.extractors.cape.file
import capa.features.extractors.cape.thread
import capa.features.extractors.cape.global_
import capa.features.extractors.cape.process
from capa.features.common import Feature
from capa.features.address import NO_ADDRESS, Address, AbsoluteVirtualAddress, _NoAddress
from capa.features.extractors.base_extractor import ThreadHandle, ProcessHandle, DynamicFeatureExtractor

logger = logging.getLogger(__name__)

TESTED_VERSIONS = ("2.2-CAPE",)


class CapeExtractor(DynamicFeatureExtractor):
    def __init__(self, cape_version: str, static: Dict, behavior: Dict):
        super().__init__()
        self.cape_version = cape_version
        self.static = static
        self.behavior = behavior

        self.global_features = capa.features.extractors.cape.global_.extract_features(self.static)

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, _NoAddress, None]:
        # value according to the PE header, the actual trace may use a different imagebase
        return AbsoluteVirtualAddress(self.static["pe"]["imagebase"])

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from self.global_features

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.file.extract_features(self.static)

    def get_processes(self) -> Iterator[ProcessHandle]:
        yield from capa.features.extractors.cape.file.get_processes(self.behavior)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.process.extract_features(self.behavior, ph)

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        yield from capa.features.extractors.cape.process.get_threads(self.behavior, ph)

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.thread.extract_features(self.behavior, ph, th)

    @classmethod
    def from_report(cls, report: Dict) -> "CapeExtractor":
        cape_version = report["info"]["version"]
        if cape_version not in TESTED_VERSIONS:
            logger.warning("CAPE version '%s' not tested/supported yet", cape_version)

        static = report["static"]
        format_ = list(static.keys())[0]
        static = static[format_]
        static.update(report["behavior"].pop("summary"))
        static.update(report["target"])
        static.update({"processtree": report["behavior"]["processtree"]})
        static.update({"strings": report["strings"]})
        static.update({"format": format_})

        behavior = report.pop("behavior")
        behavior["network"] = report.pop("network")

        return cls(cape_version, static, behavior)
