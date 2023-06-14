# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import logging
from typing import Dict, Tuple, Iterator

import capa.features.extractors.cape.global_
import capa.features.extractors.cape.process
import capa.features.extractors.cape.file
import capa.features.extractors.cape.thread
from capa.features.common import Feature
from capa.features.address import Address
from capa.features.extractors.base_extractor import ProcessHandle, ThreadHandle, DynamicExtractor

logger = logging.getLogger(__name__)


class CapeExtractor(DynamicExtractor):
    def __init__(self, static: Dict, behavior: Dict, network: Dict):
        super().__init__()
        self.static = static
        self.behavior = behavior

        self.global_features = capa.features.extractors.cape.global_.extract_features(self.static)


    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from self.global_features

    def get_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.file.extract_features(self.static)
        
    def get_processes(self) -> Iterator[ProcessHandle]:
        yield from capa.features.extractors.cape.process.get_processes(self.behavior)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.process.extract_features(self.behavior, ph)

    def get_threads(self, ph: ProcessHandle) -> Iterator[ProcessHandle]:
        yield from capa.features.extractors.cape.process.get_threads(self.behavior, ph)

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.cape.thread.extract_features(self.behavior, ph, th)


    @classmethod
    def from_report(cls, report: Dict) -> "DynamicExtractor":
        # todo:
        # 1. make the information extraction code more elegant
        # 2. filter out redundant cape features in an efficient way
        static = report["static"]
        format_ = list(static.keys())[0]
        static = static[format_]
        static.update(report["target"])
        static.update({"strings": report["strings"]})
        static.update({"format": format_})

        behavior = report.pop("behavior")
        behavior.update(behavior.pop("summary"))
        behavior["network"] = report.pop("network")

        return cls(static, behavior)