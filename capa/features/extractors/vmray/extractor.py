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


from typing import Iterator
from pathlib import Path

import capa.helpers
import capa.features.extractors.vmray.call
import capa.features.extractors.vmray.file
import capa.features.extractors.vmray.global_
from capa.features.common import Feature, Characteristic
from capa.features.address import (
    NO_ADDRESS,
    Address,
    ThreadAddress,
    ProcessAddress,
    DynamicCallAddress,
    AbsoluteVirtualAddress,
)
from capa.features.extractors.vmray import VMRayAnalysis, VMRayMonitorThread, VMRayMonitorProcess
from capa.features.extractors.vmray.models import PARAM_TYPE_STR, ParamList, FunctionCall
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)


def get_formatted_params(params: ParamList) -> list[str]:
    params_list: list[str] = []

    for param in params:
        if param.deref and param.deref.value is not None:
            deref_value: str = f'"{param.deref.value}"' if param.deref.type_ in PARAM_TYPE_STR else param.deref.value
            params_list.append(f"{param.name}: {deref_value}")
        else:
            value: str = "" if param.value is None else param.value
            params_list.append(f"{param.name}: {value}")

    return params_list


class VMRayExtractor(DynamicFeatureExtractor):
    def __init__(self, analysis: VMRayAnalysis):
        assert analysis.sample_file_analysis is not None

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

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.vmray.file.extract_features(self.analysis)

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        yield from self.global_features

    def get_processes(self) -> Iterator[ProcessHandle]:
        for monitor_process in self.analysis.monitor_processes.values():
            address: ProcessAddress = ProcessAddress(pid=monitor_process.pid, ppid=monitor_process.ppid)
            yield ProcessHandle(address, inner=monitor_process)

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[tuple[Feature, Address]]:
        # we have not identified process-specific features for VMRay yet
        yield from []

    def get_process_name(self, ph) -> str:
        monitor_process: VMRayMonitorProcess = ph.inner
        return f"{monitor_process.image_name} ({monitor_process.cmd_line})"

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        for monitor_thread_id in self.analysis.monitor_threads_by_monitor_process[ph.inner.monitor_id]:
            monitor_thread: VMRayMonitorThread = self.analysis.monitor_threads[monitor_thread_id]

            address: ThreadAddress = ThreadAddress(process=ph.address, tid=monitor_thread.tid)
            yield ThreadHandle(address=address, inner=monitor_thread)

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[tuple[Feature, Address]]:
        if False:
            # force this routine to be a generator,
            # but we don't actually have any elements to generate.
            yield Characteristic("never"), NO_ADDRESS
        return

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        for function_call in self.analysis.monitor_process_calls[ph.inner.monitor_id][th.inner.monitor_id]:
            addr = DynamicCallAddress(thread=th.address, id=function_call.fncall_id)
            yield CallHandle(address=addr, inner=function_call)

    def extract_call_features(
        self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle
    ) -> Iterator[tuple[Feature, Address]]:
        yield from capa.features.extractors.vmray.call.extract_features(ph, th, ch)

    def get_call_name(self, ph, th, ch) -> str:
        call: FunctionCall = ch.inner
        call_formatted: str = call.name

        # format input parameters
        if call.params_in:
            call_formatted += f"({', '.join(get_formatted_params(call.params_in.params))})"
        else:
            call_formatted += "()"

        # format output parameters
        if call.params_out:
            call_formatted += f" -> {', '.join(get_formatted_params(call.params_out.params))}"

        return call_formatted

    @classmethod
    def from_zipfile(cls, zipfile_path: Path):
        return cls(VMRayAnalysis(zipfile_path))
