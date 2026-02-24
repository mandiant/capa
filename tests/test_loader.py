# Copyright 2025 Google LLC
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

from unittest.mock import MagicMock

import capa.loader
import capa.features.common
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    ThreadAddress,
    ProcessAddress,
    DynamicCallAddress,
    DynamicFeatureExtractor,
)


def test_compute_dynamic_layout_recycled_tid():
    """
    When an OS recycles a thread ID within the same process, compute_dynamic_layout
    should accumulate calls from all instances of that TID rather than overwriting
    the first instance's call list with an empty list.

    Without the fix the second iteration of the recycled TID resets
    calls_by_thread[t.address] to [], causing matched calls from the first instance
    to disappear from the layout and raising a ValueError during rendering.

    See #2619.
    """
    proc_addr = ProcessAddress(pid=1000, ppid=0)
    thread_addr = ThreadAddress(proc_addr, tid=42)  # TID that will be recycled

    # A call from the *first* thread instance that a rule matched.
    call_addr = DynamicCallAddress(thread_addr, id=0)

    proc_handle = ProcessHandle(address=proc_addr, inner=None)
    # Two distinct handle objects sharing the same address — a recycled TID.
    thread_handle_1 = ThreadHandle(address=thread_addr, inner="instance-1")
    thread_handle_2 = ThreadHandle(address=thread_addr, inner="instance-2")
    call_handle = CallHandle(address=call_addr, inner=None)

    class RecycledTidExtractor(DynamicFeatureExtractor):
        def extract_global_features(self):
            return iter([])

        def extract_file_features(self):
            return iter([])

        def get_processes(self):
            yield proc_handle

        def extract_process_features(self, ph):
            return iter([])

        def get_process_name(self, ph):
            return "test.exe"

        def get_threads(self, ph):
            # Yield the same thread address twice to simulate TID recycling.
            yield thread_handle_1
            yield thread_handle_2

        def extract_thread_features(self, ph, th):
            return iter([])

        def get_calls(self, ph, th):
            # Only the first instance has the matched call; the second is empty.
            if th is thread_handle_1:
                yield call_handle

        def extract_call_features(self, ph, th, ch):
            return iter([])

        def get_call_name(self, ph, th, ch):
            return "CreateFile(hFile)"

    extractor = RecycledTidExtractor(
        SampleHashes(md5="a" * 32, sha1="a" * 40, sha256="a" * 64)
    )

    # Simulate a rule match at call_addr so it ends up in matched_calls.
    result = capa.features.common.Result(
        success=True,
        statement=MagicMock(),
        children=[],
        locations={call_addr},
    )
    capabilities = {"test rule": [(call_addr, result)]}

    # Before the fix this raised a ValueError during rendering because the
    # second thread instance (recycled TID) wiped the first instance's calls
    # from calls_by_thread.
    layout = capa.loader.compute_dynamic_layout(MagicMock(), extractor, capabilities)

    assert len(layout.processes) == 1
    proc_layout = layout.processes[0]

    # The thread should appear exactly once in the layout.
    assert len(proc_layout.matched_threads) == 1
    thread_layout = proc_layout.matched_threads[0]

    # The call from the first thread instance must be present in the layout.
    assert len(thread_layout.matched_calls) == 1
    assert thread_layout.matched_calls[0].name == "CreateFile(hFile)"
