# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import json

from capa.features.extractors.drakvuf.models import SystemCall


def test_syscall_argument_construction():
    call_dictionary = json.loads(
        r"""
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
        """
    )
    call = SystemCall(**call_dictionary)
    assert len(call.arguments) == call.nargs
    assert call.arguments["IoCompletionHandle"] == "0xffffffff80001ac0"
    assert call.arguments["IoCompletionInformation"] == "0xfffff506a0284898"
    assert call.arguments["Count"] == "0x1"
    assert call.arguments["NumEntriesRemoved"] == "0xfffff506a02846bc"
    assert call.arguments["Timeout"] == "0xfffff506a02846d8"
    assert call.arguments["Alertable"] == "0x0"
