# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, List, Union, Literal, Optional

from pydantic import Field, BaseModel
from pydantic_xml import BaseXmlModel, attr, element


### models for flog.xml
class Param(BaseXmlModel, tag="param"):
    name: str = attr()
    type: str = attr()
    value: Optional[str] = attr(default=None)


# or see https://pydantic-xml.readthedocs.io/en/latest/pages/quickstart.html#wrapper
class In(BaseXmlModel, tag="in"):
    params: List[Param] = element(name="in")


class Out(BaseXmlModel, tag="out"):
    params: List[Param] = element(name="out")


class FunctionCall(BaseXmlModel, tag="fncall"):
    ts: int = attr()
    fncall_id: int = attr()
    process_id: int = attr()
    thread_id: int = attr()
    name: str = attr()  # API call name?
    address: str = attr(name="addr")
    from_: str = attr(name="from")
    in_: Optional[In] = element(tag="in", default=None)
    out_: Optional[Out] = element(tag="out", default=None)


# note that not all fncalls always have an associated fnret, e.g. exit or WaitForSingleObject
class FunctionReturn(BaseXmlModel, tag="fnret"):
    ts: int = attr()
    fncall_id: int = attr()
    address: str = attr(name="addr")  # string that contains a hex value
    from_: str = attr(name="from")  # string that contains a hex value


# TODO check multiple are there
class MonitorProcess(BaseXmlModel, tag="monitor_process"):
    ts: int = attr()
    process_id: int = attr()
    image_name: str = attr()


# TODO check multiple are there
class MonitorThread(BaseXmlModel, tag="monitor_thread"):
    ts: int = attr()
    thread_id: int = attr()
    process_id: int = attr()
    os_tid: str = attr()  # TODO hex


class NewRegion(BaseXmlModel, tag="new_region"):
    ts: int = attr()
    region_id: int = attr()
    process_id: int = attr()
    start_va: str = attr()
    end_va: str = attr()
    entry_point: str = attr()


class RemoveRegion(BaseXmlModel, tag="remove_region"):
    ts: int = attr()
    region_id: int = attr()


# unordered is very slow, but elements may occur in any order
class Analysis(BaseXmlModel, tag="analysis", search_mode="unordered"):
    log_version: str = attr()
    analyzer_version: str = attr()
    analysis_date: str = attr()

    # super slow
    # data: List[Union[MonitorProcess, MonitorThread, NewRegion, RemoveRegion, FunctionCall, FunctionReturn]]

    # may want to preprocess file and remove/reorder entries for more efficient parsing

    processes: List[MonitorProcess] = element(tag="monitor_process")
    threads: List[MonitorThread] = element(tag="monitor_thread")

    # not important and slow down parsing
    # new_regions: List[NewRegion] = element(tag="new_region")
    # remove_regions: List[RemoveRegion] = element(tag="remove_region")

    # very slow alternative; calls: List[Union[FunctionCall, FunctionReturn]]
    fncalls: List[FunctionCall] = element(tag="fncall")
    fnrets: List[FunctionReturn] = element(tag="fnret")


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


class Process(BaseModel):
    bitness: int
    is_artifact: bool
    is_ioc: bool
    monitor_id: int
    monitor_reason: str
    os_pid: int
    filename: str
    image_name: str
    ref_parent_process: Optional[GenericReference] = None


class Filename(BaseModel):
    filename: str
    is_artifact: bool
    is_ioc: bool
    verdict: str


class Mutex(BaseModel):
    name: str
    is_artifact: bool
    is_ioc: bool
    verdict: str


class Registry(BaseModel):
    reg_key_name: str
    reg_key_value_type: Optional[str] = None
    is_artifact: bool
    is_ioc: bool
    verdict: str


class Domain(BaseModel):
    domain: str
    is_artifact: bool
    is_ioc: bool
    verdict: str


class IPAddress(BaseModel):
    ip_address: str
    is_artifact: bool
    is_ioc: bool
    verdict: str


class AnalysisMetadata(BaseModel):
    sample_type: str
    submission_filename: str


class SummaryV2(BaseModel):
    analysis_metadata: AnalysisMetadata

    static_data: Dict[str, StaticData] = {}

    # recorded artifacts
    files: Dict[str, File] = {}
    processes: Dict[str, Process] = {}
    filenames: Dict[str, Filename] = {}
    mutexes: Dict[str, Mutex] = {}
    domains: Dict[str, Domain] = {}
    ip_addresses: Dict[str, IPAddress] = {}
    registry_records: Dict[str, Registry] = {}
