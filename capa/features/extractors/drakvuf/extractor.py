# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging
from typing import Union, Iterator

import capa.features.extractors.drakvuf.call
import capa.features.extractors.drakvuf.file
import capa.features.extractors.drakvuf.thread
import capa.features.extractors.drakvuf.global_
import capa.features.extractors.drakvuf.process
from capa.features.common import Feature, Characteristic
from capa.features.address import NO_ADDRESS, Address, ThreadAddress, ProcessAddress, AbsoluteVirtualAddress, _NoAddress
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)
from capa.features.extractors.drakvuf.models import Call, DrakvufReport
from capa.features.extractors.drakvuf.helpers import index_calls

logger = logging.getLogger(__name__)


class DrakvufExtractor(DynamicFeatureExtractor):
    def __init__(self, report: DrakvufReport):
        super().__init__(
            # DRAKVUF currently does not yield hash information about the sample in its output
            hashes=SampleHashes(md5="", sha1="", sha256="")
        )

        self.report: DrakvufReport = report

        # sort the api calls to prevent going through the entire list each time
        self.sorted_calls: dict[ProcessAddress, dict[ThreadAddress, list[Call]]] = index_calls(report)

        # pre-compute these because we'll yield them at *every* scope.
        self.global_features = list(capa.features.extractors.drakvuf.global_.extract_features(self.report))

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, _NoAddress, None]:
        # DRAKVUF currently does not yield information about the PE's address
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from self.global_features

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.drakvuf.file.extract_features(self.report)

    def get_processes(self) -> Iterator[ProcessHandle]:
        yield from capa.features.extractors.drakvuf.file.get_processes(self.sorted_calls)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.drakvuf.process.extract_features(ph)

    def get_process_name(self, ph: ProcessHandle) -> str:
        return ph.inner["process_name"]

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        yield from capa.features.extractors.drakvuf.process.get_threads(self.sorted_calls, ph)

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[tuple[Feature, Address]]:
        if False:
            # force this routine to be a generator,
            # but we don't actually have any elements to generate.
            yield Characteristic("never"), NO_ADDRESS
        return

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        yield from capa.features.extractors.drakvuf.thread.get_calls(self.sorted_calls, ph, th)

    def get_call_name(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> str:
        call: Call = ch.inner
        call_name = "{}({}){}".format(
            call.name,
            ", ".join(f"{arg_name}={arg_value}" for arg_name, arg_value in call.arguments.items()),
            (f" -> {getattr(call, 'return_value', '')}"),  # SysCalls don't have a return value, while WinApi calls do
        )
        return call_name

    def extract_call_features(
        self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.drakvuf.call.extract_features(ph, th, ch)

    @classmethod
    def from_report(cls, report: Iterator[dict]) -> "DrakvufExtractor":
        dr = DrakvufReport.from_raw_report(report)
        return DrakvufExtractor(report=dr)
