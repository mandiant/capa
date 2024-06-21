# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import logging
from typing import Any, Dict, List, Iterator

from pydantic import Field, BaseModel, ConfigDict, model_validator

from capa.exceptions import EmptyReportError

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
    imports: Dict[str, int] = Field(alias="Rva")


class Call(ConciseModel):
    plugin_name: str = Field(alias="Plugin")
    timestamp: str = Field(alias="TimeStamp")
    process_name: str = Field(alias="ProcessName")
    ppid: int = Field(alias="PPID")
    pid: int = Field(alias="PID")
    tid: int = Field(alias="TID")
    name: str = Field(alias="Method")
    arguments: Dict[str, str]


class WinApiCall(Call):
    # This class models Windows api calls captured by Drakvuf (DLLs, etc.).
    arguments: Dict[str, str] = Field(alias="Arguments")
    event: str = Field(alias="Event")
    return_value: str = Field(alias="ReturnValue")

    @model_validator(mode="before")
    @classmethod
    def build_arguments(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        args = values["Arguments"]
        values["Arguments"] = {name: val for name, val in (arg.split("=", 1) for arg in args)}
        return values


class SystemCall(Call):
    # This class models native Windows api calls captured by Drakvuf.
    syscall_number: int = Field(alias="Syscall")
    module: str = Field(alias="Module")
    nargs: int = Field(alias="NArgs")

    @model_validator(mode="before")
    @classmethod
    def build_extra(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # Drakvuf stores argument names and values as entries in the syscall's entry.
        # This model validator collects those arguments into a list in the model.
        values["arguments"] = {
            name: value for name, value in values.items() if name not in REQUIRED_SYSCALL_FIELD_NAMES
        }
        return values


class DrakvufReport(ConciseModel):
    syscalls: List[SystemCall] = []
    apicalls: List[WinApiCall] = []
    discovered_dlls: List[DiscoveredDLL] = []
    loaded_dlls: List[LoadedDLL] = []

    @model_validator(mode="after")
    def validate_arguments(self) -> "DrakvufReport":
        if any((self.syscalls, self.apicalls, self.discovered_dlls, self.loaded_dlls)) is False:
            raise EmptyReportError("Report is empty")
        return self

    @classmethod
    def from_raw_report(cls, entries: Iterator[Dict]) -> "DrakvufReport":
        values: Dict[str, List] = {"syscalls": [], "apicalls": [], "discovered_dlls": [], "loaded_dlls": []}

        for entry in entries:
            plugin = entry.get("Plugin")
            if plugin == "syscall":
                values["syscalls"].append(SystemCall(**entry))
            elif plugin == "apimon":
                event = entry.get("Event")
                if event == "api_called":
                    values["apicalls"].append(WinApiCall(**entry))
                elif event == "dll_loaded":
                    values["loaded_dlls"].append(LoadedDLL(**entry))
                elif event == "dll_discovered":
                    values["discovered_dlls"].append(DiscoveredDLL(**entry))

        return DrakvufReport(**values)
