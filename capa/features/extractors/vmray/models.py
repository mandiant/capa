# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Any, Dict, List, Union, Literal, Optional

from pydantic import BaseModel

# TODO install/force lxml?
from pydantic_xml import BaseXmlModel, attr, element


### models for flog.xml


class FunctionCall(BaseXmlModel, tag="fncall"):
    # ts: str = attr()
    # fncall_id: int = attr()
    # process_id: int = attr()
    name: str = attr()
    # in_: element(name="in")
    # out: element()


class MonitorProcess(BaseXmlModel, tag="monitor_process"):
    ts: str = attr()
    process_id: int = attr()
    image_name: str = attr()


class MonitorThread(BaseXmlModel, tag="monitor_thread"):
    ts: str = attr()
    thread_id: int = attr()
    process_id: int = attr()
    os_tid: str = attr()  # TODO hex


class Analysis(BaseXmlModel, tag="analysis"):
    log_version: str = attr()
    analyzer_version: str = attr()
    analysis_date: str = attr()
    processes: List[MonitorProcess] = element(tag="monitor_process")
    threads: List[MonitorThread] = element(tag="monitor_thread")
    # failing so far...
    # fncall: List[FunctionCall] = element(tag="fncall")


### models for summary_v2.json files


class GenericReference(BaseModel):
    _type: str
    path: List[str]
    source: str


class StaticDataReference(GenericReference): ...


class PEFileBasicInfo(BaseModel):
    _type: str
    compile_time: str
    file_type: str
    image_base: int
    machine_type: str
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    subsystem: str
    entry_point: int
    imphash: Optional[str] = None


class API(BaseModel):
    _type: str
    name: str
    ordinal: Optional[int] = None


class PEFileExport(BaseModel):
    _type: str
    address: int
    api: API


class PEFileImport(BaseModel):
    _type: str
    address: int
    api: API
    thunk_offset: int
    hint: Optional[int] = None
    thunk_rva: int


class PEFileImportModule(BaseModel):
    _type: str
    dll: str
    apis: List[PEFileImport]


class PEFile(BaseModel):
    _type: str
    basic_info: Optional[PEFileBasicInfo] = None
    exports: Optional[List[PEFileExport]] = None
    imports: Optional[List[PEFileImportModule]] = None


class StaticData(BaseModel):
    pe: Optional[PEFile] = None


class File(BaseModel):
    _type: str
    categories: List[str]
    hash_values: Dict[str, str]
    is_artifact: bool
    is_ioc: bool
    is_sample: bool
    size: int
    is_truncated: bool
    mime_type: Optional[str] = None
    operations: Optional[List[str]] = None
    ref_filenames: Optional[List[GenericReference]] = None
    ref_gfncalls: Optional[List[GenericReference]] = None
    ref_static_data: Optional[StaticDataReference] = None
    ref_vti_matches: Optional[List[GenericReference]] = None
    verdict: str


class SummaryV2(BaseModel):
    files: Dict[str, File]
    static_data: Dict[str, StaticData]