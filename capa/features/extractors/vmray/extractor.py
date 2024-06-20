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

import xmltodict

import capa.helpers
import capa.features.extractors.vmray.call
import capa.features.extractors.vmray.file
import capa.features.extractors.vmray.global_
from capa.features.common import Feature, Characteristic
from capa.features.address import NO_ADDRESS, Address, ThreadAddress, DynamicCallAddress, AbsoluteVirtualAddress
from capa.features.extractors.vmray import VMRayAnalysis
from capa.features.extractors.vmray.models import Flog, Process, SummaryV2
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)


class VMRayExtractor(DynamicFeatureExtractor):
    def __init__(self, analysis: VMRayAnalysis):
        super().__init__(
            hashes=SampleHashes(
                md5=analysis.sample_file_analysis.hash_values.md5.lower(),
                sha1=analysis.sample_file_analysis.hash_values.sha1.lower(),
                sha256=analysis.sample_file_analysis.hash_values.sha256.lower(),
            )
        )

        self.analysis = analysis

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features = list(capa.features.extractors.vmray.global_.extract_features(self.analysis))

    def get_base_address(self) -> Address:
        # value according to the PE header, the actual trace may use a different imagebase
        return AbsoluteVirtualAddress(self.analysis.base_address)

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.vmray.file.extract_features(self.analysis)

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from self.global_features

    def get_processes(self) -> Iterator[ProcessHandle]:
        yield from capa.features.extractors.vmray.file.get_processes(self.analysis)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
        # TODO (meh)
        yield from []

    def get_process_name(self, ph) -> str:
        process: Process = ph.inner
        return process.image_name

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        for thread in self.analysis.process_threads[ph.address.pid]:
            address: ThreadAddress = ThreadAddress(process=ph.address, tid=thread)
            yield ThreadHandle(address=address, inner={})

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
        if False:
            # force this routine to be a generator,
            # but we don't actually have any elements to generate.
            yield Characteristic("never"), NO_ADDRESS
        return

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        for function_call in self.analysis.process_calls[ph.address.pid][th.address.tid]:
            addr = DynamicCallAddress(thread=th.address, id=int(function_call.fncall_id))
            yield CallHandle(address=addr, inner=function_call)

    def extract_call_features(
        self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.vmray.call.extract_features(ph, th, ch)

    def get_call_name(self, ph, th, ch) -> str:
        # TODO (meh)
        raise NotImplementedError()

    @classmethod
    def from_zipfile(cls, zipfile_path: Path):
        with ZipFile(zipfile_path, "r") as zipfile:
            sv2_json = json.loads(zipfile.read("logs/summary_v2.json", pwd=b"infected"))
            sv2 = SummaryV2.model_validate(sv2_json)

            flog_xml = zipfile.read("logs/flog.xml", pwd=b"infected")
            flog_json = xmltodict.parse(flog_xml, attr_prefix="")
            flog = Flog.model_validate(flog_json)

        return cls(VMRayAnalysis(sv2, flog))
