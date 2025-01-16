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
from typing import Any, Iterator

from pydantic import Field, BaseModel, ConfigDict, model_validator

logger = logging.getLogger(__name__)


REQUIRED_SYSCALL_FIELD_NAMES = {
    "Plugin",
    "TimeStamp",
    "PID",
    "PPID",
    "TID",
    "UserName",
    "UserId",
    "ProcessName",
    "Method",
    "EventUID",
    "Module",
    "vCPU",
    "CR3",
    "Syscall",
    "NArgs",
}


class ConciseModel(BaseModel):
    ConfigDict(extra="ignore")


class DiscoveredDLL(ConciseModel):
    plugin_name: str = Field(alias="Plugin")
    event: str = Field(alias="Event")
    name: str = Field(alias="DllName")
    pid: int = Field(alias="PID")


class LoadedDLL(ConciseModel):
    plugin_name: str = Field(alias="Plugin")
    event: str = Field(alias="Event")
    name: str = Field(alias="DllName")
    imports: dict[str, int] = Field(alias="Rva")


class Call(ConciseModel):
    plugin_name: str = Field(alias="Plugin")
    timestamp: str = Field(alias="TimeStamp")
    process_name: str = Field(alias="ProcessName")
    ppid: int = Field(alias="PPID")
    pid: int = Field(alias="PID")
    tid: int = Field(alias="TID")
    name: str = Field(alias="Method")
    arguments: dict[str, str]


class WinApiCall(Call):
    # This class models Windows API calls captured by DRAKVUF (DLLs, etc.).
    arguments: dict[str, str] = Field(alias="Arguments")
    event: str = Field(alias="Event")
    return_value: str = Field(alias="ReturnValue")

    @model_validator(mode="before")
    @classmethod
    def build_arguments(cls, values: dict[str, Any]) -> dict[str, Any]:
        args = values["Arguments"]
        values["Arguments"] = dict(arg.split("=", 1) for arg in args)
        return values


class SystemCall(Call):
    # This class models native Windows API calls captured by DRAKVUF.
    # Schema: {
    #   "Plugin": "syscall",
    #   "TimeStamp": "1716999134.582553",
    #   "PID": 3888, "PPID": 2852, "TID": 368, "UserName": "SessionID", "UserId": 2,
    #   "ProcessName": "\\Device\\HarddiskVolume2\\Windows\\explorer.exe",
    #   "Method": "NtSetIoCompletionEx",
    #   "EventUID": "0x27",
    #   "Module": "nt",
    #   "vCPU": 0,
    #   "CR3": "0x119b1002",
    #   "Syscall": 419,
    #   "NArgs": 6,
    #   "IoCompletionHandle": "0xffffffff80001ac0", "IoCompletionReserveHandle": "0xffffffff8000188c",
    #   "KeyContext": "0x0", "ApcContext": "0x2", "IoStatus": "0x7ffb00000000", "IoStatusInformation": "0x0"
    # }
    # The keys up until "NArgs" are common to all the native calls that DRAKVUF reports, with
    # the remaining keys representing the call's specific arguments.
    syscall_number: int = Field(alias="Syscall")
    module: str = Field(alias="Module")
    nargs: int = Field(alias="NArgs")

    @model_validator(mode="before")
    @classmethod
    def build_extra(cls, values: dict[str, Any]) -> dict[str, Any]:
        # DRAKVUF stores argument names and values as entries in the syscall's entry.
        # This model validator collects those arguments into a list in the model.
        values["arguments"] = {
            name: value for name, value in values.items() if name not in REQUIRED_SYSCALL_FIELD_NAMES
        }
        return values


class DrakvufReport(ConciseModel):
    syscalls: list[SystemCall] = []
    apicalls: list[WinApiCall] = []
    discovered_dlls: list[DiscoveredDLL] = []
    loaded_dlls: list[LoadedDLL] = []

    @classmethod
    def from_raw_report(cls, entries: Iterator[dict]) -> "DrakvufReport":
        report = cls()

        for entry in entries:
            plugin = entry.get("Plugin")
            # TODO(yelhamer): add support for more DRAKVUF plugins
            # https://github.com/mandiant/capa/issues/2181
            if plugin == "syscall":
                report.syscalls.append(SystemCall(**entry))
            elif plugin == "apimon":
                event = entry.get("Event")
                if event == "api_called":
                    report.apicalls.append(WinApiCall(**entry))
                elif event == "dll_loaded":
                    report.loaded_dlls.append(LoadedDLL(**entry))
                elif event == "dll_discovered":
                    report.discovered_dlls.append(DiscoveredDLL(**entry))

        return report
