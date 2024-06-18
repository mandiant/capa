# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, List, Union, Literal, Optional
from pydantic_xml import BaseXmlModel, attr, element

#
class Param(BaseXmlModel):
    name: str = attr()
    type: str = attr()
    value: str = attr()


class FunctionCall(BaseXmlModel, tag="fncall"):
    ts: int = attr()
    fncall_id: int = attr()
    process_id: int = attr()
    name: str = attr() #API call name?
    address: str = attr() #address
    from_: str = attr() 
    in_: List[Param] = element(name="in")
    out: Optional[Param] = element(name="out")

class FunctionReturn(BaseXmlModel, tag="fnret"):
    ts: int = attr()
    fncall_id: int = attr()
    addr: str = attr() #string that contains a hex value
    from_: str = attr #string that contains a hex value

class MonitorProcess(BaseXmlModel, tag="monitor_process"):
    ts: int = attr()
    process_id: int = attr()
    image_name: str = attr()


class MonitorThread(BaseXmlModel, tag="monitor_thread"):
    ts: int = attr()
    thread_id: int = attr()
    process_id: int = attr()
    os_tid: str = attr()  # TODO hex

class NewRegion(BaseXmlModel):
    ts: int = attr()
    start_va: str = attr()
    end_va: str = attr()
    entry_point: str = attr()

class RemoveRegion(BaseXmlModel, tag="remove_region"):
    ts: int = attr()
    region_id: int = attr()

class Analysis(BaseXmlModel, tag="analysis"):
    log_version: str = attr()
    analyzer_version: str = attr()
    analysis_date: str = attr()
    processes: List[MonitorProcess] = element(tag="monitor_process")
    threads: List[MonitorThread] = element(tag="monitor_thread")
    new_regions: List[NewRegion] = element(tag="new_region")
    remove_regions: List[RemoveRegion] = element(tag="remove_region")
    fncalls: List[FunctionCall] = element(tag="fncall")
    fnrets: List[FunctionReturn] = element(tag="fnret")
   
