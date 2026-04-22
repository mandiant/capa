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

import json

from capa.features.address import ThreadAddress, ProcessAddress, DynamicCallAddress
from capa.features.extractors.base_extractor import (
    CallHandle,
    ThreadHandle,
    ProcessHandle,
)
from capa.features.extractors.drakvuf.models import SystemCall, WinApiCall, ConciseModel, DrakvufReport
from capa.features.extractors.drakvuf.extractor import DrakvufExtractor


def test_concise_model_ignores_extra_fields():
    class Strict(ConciseModel):
        x: int

    instance = Strict(x=1, unexpected_field="hello")  # type: ignore[call-arg]
    assert instance.x == 1
    assert not hasattr(instance, "unexpected_field")


def test_syscall_argument_construction():
    call_dictionary = json.loads(r"""
        {
            "Plugin": "syscall",
            "TimeStamp": "1716999134.581449",
            "PID": 3888,
            "PPID": 2852,
            "TID": 368,
            "UserName": "SessionID",
            "UserId": 2,
            "ProcessName": "\\Device\\HarddiskVolume2\\Windows\\explorer.exe",
            "Method": "NtRemoveIoCompletionEx",
            "EventUID": "0x1f",
            "Module": "nt",
            "vCPU": 0,
            "CR3": "0x119b1002",
            "Syscall": 369,
            "NArgs": 6,
            "IoCompletionHandle": "0xffffffff80001ac0",
            "IoCompletionInformation": "0xfffff506a0284898",
            "Count": "0x1",
            "NumEntriesRemoved": "0xfffff506a02846bc",
            "Timeout": "0xfffff506a02846d8",
            "Alertable": "0x0"
        }
        """)
    call = SystemCall(**call_dictionary)
    assert len(call.arguments) == call.nargs
    assert call.arguments["IoCompletionHandle"] == "0xffffffff80001ac0"
    assert call.arguments["IoCompletionInformation"] == "0xfffff506a0284898"
    assert call.arguments["Count"] == "0x1"
    assert call.arguments["NumEntriesRemoved"] == "0xfffff506a02846bc"
    assert call.arguments["Timeout"] == "0xfffff506a02846d8"
    assert call.arguments["Alertable"] == "0x0"


def _make_call_handle(call):
    proc_addr = ProcessAddress(pid=1, ppid=0)
    thread_addr = ThreadAddress(process=proc_addr, tid=1)
    call_addr = DynamicCallAddress(thread=thread_addr, id=0)
    return CallHandle(address=call_addr, inner=call)


def _make_extractor():
    return DrakvufExtractor(report=DrakvufReport())


def _make_process_handle():
    proc_addr = ProcessAddress(pid=1, ppid=0)
    return ProcessHandle(address=proc_addr, inner={})


def _make_thread_handle():
    proc_addr = ProcessAddress(pid=1, ppid=0)
    thread_addr = ThreadAddress(process=proc_addr, tid=1)
    return ThreadHandle(address=thread_addr, inner={})


def test_get_call_name_syscall_has_no_return_value_suffix():
    call_dict = json.loads(r"""
        {
            "Plugin": "syscall",
            "TimeStamp": "1716999134.581449",
            "PID": 3888,
            "PPID": 2852,
            "TID": 368,
            "UserName": "SessionID",
            "UserId": 2,
            "ProcessName": "\\Device\\HarddiskVolume2\\Windows\\explorer.exe",
            "Method": "NtClose",
            "EventUID": "0x1f",
            "Module": "nt",
            "vCPU": 0,
            "CR3": "0x119b1002",
            "Syscall": 15,
            "NArgs": 1,
            "Handle": "0xffffffff80001ac0"
        }
        """)
    call = SystemCall(**call_dict)
    extractor = _make_extractor()
    ph = _make_process_handle()
    th = _make_thread_handle()
    ch = _make_call_handle(call)

    name = extractor.get_call_name(ph, th, ch)

    assert " -> " not in name
    assert name == "NtClose(Handle=0xffffffff80001ac0)"


def test_get_call_name_winapicall_includes_return_value():
    call_dict = {
        "Plugin": "apimon",
        "TimeStamp": "1716999134.581449",
        "PID": 3888,
        "PPID": 2852,
        "TID": 368,
        "ProcessName": "explorer.exe",
        "Method": "CreateFileW",
        "Event": "api_called",
        "Arguments": ["hFile=0x1234"],
        "ReturnValue": "0x5678",
    }
    call = WinApiCall(**call_dict)  # type: ignore[arg-type]  # dict literal infers object values due to mixed str/list types
    extractor = _make_extractor()
    ph = _make_process_handle()
    th = _make_thread_handle()
    ch = _make_call_handle(call)

    name = extractor.get_call_name(ph, th, ch)

    assert " -> 0x5678" in name
    assert name == "CreateFileW(hFile=0x1234) -> 0x5678"
