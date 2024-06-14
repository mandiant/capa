# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Dict, List, Optional

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
    path: List[str]
    source: str


class StaticDataReference(GenericReference): ...


class PEFileBasicInfo(BaseModel):
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
    name: str
    ordinal: Optional[int] = None


class PEFileExport(BaseModel):
    address: int
    api: API


class PEFileImport(BaseModel):
    address: int
    api: API
    thunk_offset: int
    hint: Optional[int] = None
    thunk_rva: int


class PEFileImportModule(BaseModel):
    dll: str
    apis: List[PEFileImport]


class PEFileSection(BaseModel):
    entropy: float
    flags: List[str] = []
    name: str
    raw_data_offset: int
    raw_data_size: int
    virtual_address: int
    virtual_size: int


class PEFile(BaseModel):
    basic_info: PEFileBasicInfo
    exports: List[PEFileExport] = []
    imports: List[PEFileImportModule] = []
    sections: List[PEFileSection] = []


class StaticData(BaseModel):
    pe: Optional[PEFile] = None


class FileHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str
    ssdeep: str


class File(BaseModel):
    categories: List[str]
    hash_values: FileHashes
    is_artifact: bool
    is_ioc: bool
    is_sample: bool
    size: int
    is_truncated: bool
    mime_type: Optional[str] = None
    operations: List[str] = []
    ref_filenames: List[GenericReference] = []
    ref_gfncalls: List[GenericReference] = []
    ref_static_data: Optional[StaticDataReference] = None
    ref_vti_matches: List[GenericReference] = []
    verdict: str


class AnalysisMetadata(BaseModel):
    sample_type: str
    submission_filename: str


class SummaryV2(BaseModel):
    files: Dict[str, File]
    static_data: Dict[str, StaticData]
    analysis_metadata: AnalysisMetadata
