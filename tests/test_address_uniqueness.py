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

"""
Tests for address uniqueness when PIDs/TIDs are recycled by the OS.

These tests verify the fix for issue #2619 / #2361: dynamic sandbox extractors
(especially VMRay) can report multiple process/thread instances that share the
same OS-assigned IDs.  The optional `id` field on ProcessAddress and
ThreadAddress allows capa to distinguish them.
"""

from unittest.mock import MagicMock

import capa.loader
import capa.features.common
import capa.features.freeze as frz
from capa.features.address import ThreadAddress, ProcessAddress, DynamicCallAddress
from capa.features.extractors.base_extractor import (
    CallHandle,
    SampleHashes,
    ThreadHandle,
    ProcessHandle,
    DynamicFeatureExtractor,
)

# ---------------------------------------------------------------------------
# ProcessAddress identity tests
# ---------------------------------------------------------------------------


class TestProcessAddressUniqueness:
    def test_same_pid_different_id_not_equal(self):
        a = ProcessAddress(pid=100, ppid=1, id=1)
        b = ProcessAddress(pid=100, ppid=1, id=2)
        assert a != b

    def test_same_pid_different_id_different_hash(self):
        a = ProcessAddress(pid=100, ppid=1, id=1)
        b = ProcessAddress(pid=100, ppid=1, id=2)
        assert hash(a) != hash(b)

    def test_same_pid_same_id_equal(self):
        a = ProcessAddress(pid=100, ppid=1, id=5)
        b = ProcessAddress(pid=100, ppid=1, id=5)
        assert a == b
        assert hash(a) == hash(b)

    def test_sorting_with_ids(self):
        addrs = [
            ProcessAddress(pid=100, ppid=1, id=3),
            ProcessAddress(pid=100, ppid=1, id=1),
            ProcessAddress(pid=100, ppid=1, id=2),
        ]
        assert sorted(addrs) == [
            ProcessAddress(pid=100, ppid=1, id=1),
            ProcessAddress(pid=100, ppid=1, id=2),
            ProcessAddress(pid=100, ppid=1, id=3),
        ]

    def test_dict_key_uniqueness(self):
        a = ProcessAddress(pid=100, ppid=1, id=1)
        b = ProcessAddress(pid=100, ppid=1, id=2)
        d = {a: "first", b: "second"}
        assert len(d) == 2
        assert d[a] == "first"
        assert d[b] == "second"

    def test_set_uniqueness(self):
        a = ProcessAddress(pid=100, ppid=1, id=1)
        b = ProcessAddress(pid=100, ppid=1, id=2)
        c = ProcessAddress(pid=100, ppid=1, id=1)  # duplicate of a
        s = {a, b, c}
        assert len(s) == 2

    def test_repr_with_id(self):
        a = ProcessAddress(pid=100, ppid=1, id=5)
        assert "id: 5" in repr(a)


# ---------------------------------------------------------------------------
# ThreadAddress identity tests
# ---------------------------------------------------------------------------


class TestThreadAddressUniqueness:
    def test_same_tid_different_id_not_equal(self):
        p = ProcessAddress(pid=100, ppid=1, id=0)
        a = ThreadAddress(p, tid=42, id=1)
        b = ThreadAddress(p, tid=42, id=2)
        assert a != b

    def test_same_tid_different_id_different_hash(self):
        p = ProcessAddress(pid=100, ppid=1, id=0)
        a = ThreadAddress(p, tid=42, id=1)
        b = ThreadAddress(p, tid=42, id=2)
        assert hash(a) != hash(b)

    def test_same_tid_same_id_equal(self):
        p = ProcessAddress(pid=100, ppid=1, id=0)
        a = ThreadAddress(p, tid=42, id=7)
        b = ThreadAddress(p, tid=42, id=7)
        assert a == b
        assert hash(a) == hash(b)

    def test_different_process_id_propagates(self):
        """threads in recycled processes (different process.id) should differ"""
        p1 = ProcessAddress(pid=100, ppid=1, id=1)
        p2 = ProcessAddress(pid=100, ppid=1, id=2)
        t1 = ThreadAddress(p1, tid=42, id=0)
        t2 = ThreadAddress(p2, tid=42, id=0)
        assert t1 != t2
        assert hash(t1) != hash(t2)

    def test_sorting_with_ids(self):
        p = ProcessAddress(pid=100, ppid=1, id=0)
        addrs = [
            ThreadAddress(p, tid=42, id=3),
            ThreadAddress(p, tid=42, id=1),
            ThreadAddress(p, tid=42, id=2),
        ]
        assert sorted(addrs) == [
            ThreadAddress(p, tid=42, id=1),
            ThreadAddress(p, tid=42, id=2),
            ThreadAddress(p, tid=42, id=3),
        ]

    def test_repr_with_id(self):
        p = ProcessAddress(pid=100, ppid=1, id=0)
        t = ThreadAddress(p, tid=42, id=7)
        assert "id: 7" in repr(t)


# ---------------------------------------------------------------------------
# DynamicCallAddress with unique thread addresses
# ---------------------------------------------------------------------------


class TestCallAddressWithUniqueThreads:
    def test_calls_in_different_thread_instances_not_equal(self):
        p = ProcessAddress(pid=100, ppid=1, id=1)
        t1 = ThreadAddress(p, tid=42, id=10)
        t2 = ThreadAddress(p, tid=42, id=20)
        c1 = DynamicCallAddress(t1, id=0)
        c2 = DynamicCallAddress(t2, id=0)
        assert c1 != c2

    def test_calls_in_same_thread_instance_same_id_equal(self):
        p = ProcessAddress(pid=100, ppid=1, id=1)
        t = ThreadAddress(p, tid=42, id=10)
        c1 = DynamicCallAddress(t, id=5)
        c2 = DynamicCallAddress(t, id=5)
        assert c1 == c2


# ---------------------------------------------------------------------------
# Freeze roundtrip tests
# ---------------------------------------------------------------------------


class TestFreezeRoundtrip:
    def test_process_address_roundtrip(self):
        addr = ProcessAddress(pid=100, ppid=1, id=42)
        frozen = frz.Address.from_capa(addr)
        thawed = frozen.to_capa()
        assert addr == thawed
        assert thawed.id == 42

    def test_thread_address_roundtrip(self):
        addr = ThreadAddress(ProcessAddress(pid=100, ppid=1, id=10), tid=5, id=20)
        frozen = frz.Address.from_capa(addr)
        thawed = frozen.to_capa()
        assert addr == thawed
        assert thawed.process.id == 10
        assert thawed.id == 20

    def test_call_address_roundtrip(self):
        addr = DynamicCallAddress(
            ThreadAddress(ProcessAddress(pid=100, ppid=1, id=10), tid=5, id=20),
            id=99,
        )
        frozen = frz.Address.from_capa(addr)
        thawed = frozen.to_capa()
        assert addr == thawed
        assert thawed.thread.process.id == 10
        assert thawed.thread.id == 20

    def test_process_address_zero_id_roundtrip(self):
        addr = ProcessAddress(pid=100, ppid=1, id=0)
        frozen = frz.Address.from_capa(addr)
        thawed = frozen.to_capa()
        assert thawed.id == 0

    def test_thread_address_zero_ids_roundtrip(self):
        addr = ThreadAddress(ProcessAddress(pid=100, ppid=1, id=0), tid=5, id=0)
        frozen = frz.Address.from_capa(addr)
        thawed = frozen.to_capa()
        assert thawed.process.id == 0
        assert thawed.id == 0


# ---------------------------------------------------------------------------
# compute_dynamic_layout: recycled TID with unique addresses
# ---------------------------------------------------------------------------


class TestComputeDynamicLayoutRecycledTid:
    """
    When a sandbox (e.g. VMRay) reports two thread instances with the same
    OS-level TID but different unique ids (monitor_ids), compute_dynamic_layout
    must keep both thread instances and their respective calls separate.
    """

    def _make_extractor(self):
        proc_addr = ProcessAddress(pid=1000, ppid=0, id=1)

        # Two thread instances sharing the same OS-level TID but with
        # different unique ids, simulating VMRay's monitor_id.
        thread_addr_1 = ThreadAddress(proc_addr, tid=42, id=10)
        thread_addr_2 = ThreadAddress(proc_addr, tid=42, id=20)

        call_addr_1 = DynamicCallAddress(thread_addr_1, id=0)
        call_addr_2 = DynamicCallAddress(thread_addr_2, id=0)

        proc_handle = ProcessHandle(address=proc_addr, inner=None)
        thread_handle_1 = ThreadHandle(address=thread_addr_1, inner="instance-1")
        thread_handle_2 = ThreadHandle(address=thread_addr_2, inner="instance-2")
        call_handle_1 = CallHandle(address=call_addr_1, inner=None)
        call_handle_2 = CallHandle(address=call_addr_2, inner=None)

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
                yield thread_handle_1
                yield thread_handle_2

            def extract_thread_features(self, ph, th):
                return iter([])

            def get_calls(self, ph, th):
                if th is thread_handle_1:
                    yield call_handle_1
                elif th is thread_handle_2:
                    yield call_handle_2

            def extract_call_features(self, ph, th, ch):
                return iter([])

            def get_call_name(self, ph, th, ch):
                if ch is call_handle_1:
                    return "CreateFile(hFile)"
                else:
                    return "WriteFile(hFile)"

        extractor = RecycledTidExtractor(SampleHashes(md5="a" * 32, sha1="a" * 40, sha256="a" * 64))

        # Both calls matched by rules
        result_1 = capa.features.common.Result(
            success=True, statement=MagicMock(), children=[], locations={call_addr_1}
        )
        result_2 = capa.features.common.Result(
            success=True, statement=MagicMock(), children=[], locations={call_addr_2}
        )
        capabilities = {
            "rule A": [(call_addr_1, result_1)],
            "rule B": [(call_addr_2, result_2)],
        }

        return extractor, capabilities

    def test_both_thread_instances_appear(self):
        extractor, capabilities = self._make_extractor()
        layout = capa.loader.compute_dynamic_layout(MagicMock(), extractor, capabilities)

        assert len(layout.processes) == 1
        proc = layout.processes[0]

        # Both thread instances must appear as separate entries
        assert len(proc.matched_threads) == 2

    def test_each_thread_has_its_own_call(self):
        extractor, capabilities = self._make_extractor()
        layout = capa.loader.compute_dynamic_layout(MagicMock(), extractor, capabilities)

        proc = layout.processes[0]
        thread_names = set()
        for t in proc.matched_threads:
            assert len(t.matched_calls) == 1
            thread_names.add(t.matched_calls[0].name)

        assert "CreateFile(hFile)" in thread_names
        assert "WriteFile(hFile)" in thread_names

    def test_no_data_loss(self):
        """the original bug: second thread instance overwrites first's calls"""
        extractor, capabilities = self._make_extractor()
        layout = capa.loader.compute_dynamic_layout(MagicMock(), extractor, capabilities)

        # count total matched calls across all threads
        total_calls = sum(len(t.matched_calls) for t in layout.processes[0].matched_threads)
        assert total_calls == 2


# ---------------------------------------------------------------------------
# compute_dynamic_layout: recycled PID with unique addresses
# ---------------------------------------------------------------------------


class TestComputeDynamicLayoutRecycledPid:
    """
    When a sandbox reports two process instances with the same OS-level PID
    but different unique ids, compute_dynamic_layout must keep both processes
    and their respective threads/calls separate.
    """

    def test_both_process_instances_appear(self):
        proc_addr_1 = ProcessAddress(pid=500, ppid=1, id=1)
        proc_addr_2 = ProcessAddress(pid=500, ppid=1, id=2)

        thread_addr_1 = ThreadAddress(proc_addr_1, tid=10, id=100)
        thread_addr_2 = ThreadAddress(proc_addr_2, tid=10, id=200)

        call_addr_1 = DynamicCallAddress(thread_addr_1, id=0)
        call_addr_2 = DynamicCallAddress(thread_addr_2, id=0)

        ph1 = ProcessHandle(address=proc_addr_1, inner=None)
        ph2 = ProcessHandle(address=proc_addr_2, inner=None)
        th1 = ThreadHandle(address=thread_addr_1, inner=None)
        th2 = ThreadHandle(address=thread_addr_2, inner=None)
        ch1 = CallHandle(address=call_addr_1, inner=None)
        ch2 = CallHandle(address=call_addr_2, inner=None)

        class RecycledPidExtractor(DynamicFeatureExtractor):
            def extract_global_features(self):
                return iter([])

            def extract_file_features(self):
                return iter([])

            def get_processes(self):
                yield ph1
                yield ph2

            def extract_process_features(self, ph):
                return iter([])

            def get_process_name(self, ph):
                return "malware.exe" if ph is ph1 else "malware.exe (recycled)"

            def get_threads(self, ph):
                if ph is ph1:
                    yield th1
                elif ph is ph2:
                    yield th2

            def extract_thread_features(self, ph, th):
                return iter([])

            def get_calls(self, ph, th):
                if th is th1:
                    yield ch1
                elif th is th2:
                    yield ch2

            def extract_call_features(self, ph, th, ch):
                return iter([])

            def get_call_name(self, ph, th, ch):
                return "NtCreateFile()" if ch is ch1 else "NtWriteFile()"

        extractor = RecycledPidExtractor(SampleHashes(md5="b" * 32, sha1="b" * 40, sha256="b" * 64))

        result_1 = capa.features.common.Result(
            success=True, statement=MagicMock(), children=[], locations={call_addr_1}
        )
        result_2 = capa.features.common.Result(
            success=True, statement=MagicMock(), children=[], locations={call_addr_2}
        )
        capabilities = {
            "rule A": [(call_addr_1, result_1)],
            "rule B": [(call_addr_2, result_2)],
        }

        layout = capa.loader.compute_dynamic_layout(MagicMock(), extractor, capabilities)

        # both process instances must appear
        assert len(layout.processes) == 2

        # each process should have its own thread and call
        for p in layout.processes:
            assert len(p.matched_threads) == 1
            assert len(p.matched_threads[0].matched_calls) == 1
