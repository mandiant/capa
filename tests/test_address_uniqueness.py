# Copyright 2026 Google LLC
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

from typing import cast
from unittest.mock import Mock

from capa.engine import MatchResults
import capa.loader
import capa.features.common
import capa.features.freeze as frz
from capa.features.address import Address, ThreadAddress, ProcessAddress, DynamicCallAddress
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)


def test_process_address_id_affects_identity():
    a = ProcessAddress(pid=1000, ppid=10, id=1)
    b = ProcessAddress(pid=1000, ppid=10, id=2)

    assert a != b
    assert hash(a) != hash(b)


def test_thread_address_id_affects_identity():
    p = ProcessAddress(pid=1000, ppid=10, id=1)
    a = ThreadAddress(process=p, tid=42, id=1)
    b = ThreadAddress(process=p, tid=42, id=2)

    assert a != b
    assert hash(a) != hash(b)


def test_freeze_roundtrip_process_with_id():
    addr = ProcessAddress(pid=1000, ppid=10, id=7)
    frozen = frz.Address.from_capa(addr)
    thawed = frozen.to_capa()

    assert isinstance(thawed, ProcessAddress)
    assert thawed == addr
    assert thawed.id == 7


def test_freeze_roundtrip_thread_with_ids():
    addr = ThreadAddress(process=ProcessAddress(pid=1000, ppid=10, id=5), tid=42, id=9)
    frozen = frz.Address.from_capa(addr)
    thawed = frozen.to_capa()

    assert isinstance(thawed, ThreadAddress)
    assert thawed == addr
    assert thawed.process.id == 5
    assert thawed.id == 9


def test_freeze_roundtrip_call_with_ids():
    addr = DynamicCallAddress(
        thread=ThreadAddress(process=ProcessAddress(pid=1000, ppid=10, id=5), tid=42, id=9), id=77
    )
    frozen = frz.Address.from_capa(addr)
    thawed = frozen.to_capa()

    assert isinstance(thawed, DynamicCallAddress)
    assert thawed == addr
    assert thawed.thread.process.id == 5
    assert thawed.thread.id == 9


def test_compute_dynamic_layout_recycled_tid_does_not_drop_matched_call():
    process_addr = ProcessAddress(pid=1000, ppid=10)
    thread_addr = ThreadAddress(process=process_addr, tid=42)
    call_addr = DynamicCallAddress(thread=thread_addr, id=1)

    process_handle = ProcessHandle(address=process_addr, inner=None)
    thread_handle1 = ThreadHandle(address=thread_addr, inner="first")
    thread_handle2 = ThreadHandle(address=thread_addr, inner="second")
    call_handle = CallHandle(address=call_addr, inner=None)

    class RecycledTidExtractor(DynamicFeatureExtractor):
        def __init__(self):
            super().__init__(SampleHashes(md5="a" * 32, sha1="a" * 40, sha256="a" * 64))

        def extract_global_features(self):
            return iter([])

        def extract_file_features(self):
            return iter([])

        def get_processes(self):
            yield process_handle

        def extract_process_features(self, ph):
            return iter([])

        def get_process_name(self, ph):
            return "sample.exe"

        def get_threads(self, ph):
            # same thread address appears twice, emulating TID reuse/collision.
            yield thread_handle1
            yield thread_handle2

        def extract_thread_features(self, ph, th):
            return iter([])

        def get_calls(self, ph, th):
            if th.inner == "first":
                yield call_handle
            else:
                yield from ()

        def extract_call_features(self, ph, th, ch):
            return iter([])

        def get_call_name(self, ph, th, ch):
            return "CreateFileW(lpFileName=C:\\\\tmp\\\\x)"

    extractor = RecycledTidExtractor()
    result = capa.features.common.Result(success=True, statement=Mock(), children=[], locations={call_addr})
    capabilities = cast(MatchResults, {"repro rule": [(cast(Address, call_addr), result)]})

    layout = capa.loader.compute_dynamic_layout(Mock(), extractor, capabilities)

    assert len(layout.processes) == 1
    assert len(layout.processes[0].matched_threads) == 1
    assert len(layout.processes[0].matched_threads[0].matched_calls) == 1
    assert layout.processes[0].matched_threads[0].matched_calls[0].name.startswith("CreateFileW")
